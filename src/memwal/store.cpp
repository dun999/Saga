#include "memwal/store.h"

#include <cstdio>

#include "memwal/redact.h"

namespace saga::memwal {
namespace {

int64_t now_s() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
      .count();
}

void log_err(const char* what, const std::exception& e) { std::fprintf(stderr, "[memory] %s: %s\n", what, e.what()); }

}  // namespace

json WriteRecord::to_json() const {
  return {{"namespace", ns}, {"kind", kind}, {"text", text.substr(0, 240)}, {"job_id", job_id},
          {"blob_id", blob_id}, {"status", status}, {"error", error}, {"ts", ts}, {"ref", ref}};
}

std::string encode_record(const std::string& kind, const json& payload) {
  return "SAGA:" + kind + " " + payload.dump();
}

std::optional<json> decode_record(const std::string& text, const std::string& kind) {
  const std::string prefix = "SAGA:" + kind + " ";
  if (!text.starts_with(prefix)) return std::nullopt;
  const std::string body = text.substr(prefix.size());
  // nlohmann has no depth limit; a nested record can overflow the stack inside parse.
  if (json_nesting(body) > kMaxJsonDepth) return std::nullopt;
  auto j = json::parse(body, nullptr, false);
  if (j.is_discarded()) return std::nullopt;
  return j;
}

Store::Store(Client* client, bool enabled) : client_(client), enabled_(enabled) {
  if (this->enabled()) thread_ = std::thread([this] { worker(); });
}

Store::~Store() {
  stop_ = true;
  cv_.notify_all();
  if (thread_.joinable()) thread_.join();
}

void Store::put(const std::string& ns, const std::string& kind, const std::string& text, const std::string& ref,
                const std::string& owner) {
  if (!enabled() || text.empty()) return;
  // Agent output, checkpoints, and direct memory calls all land here, past the web field limits.
  // Refuse before the queue: the logged text is the placeholder, never the original.
  constexpr size_t kMaxQueued = 200;
  const StorageText prepared = prepare_for_storage(text);
  WriteRecord r;
  r.ns = ns;
  r.kind = kind;
  r.text = prepared.text;
  r.ref = ref;
  r.owner = owner;
  r.ts = now_s();
  bool queued = false;
  {
    std::lock_guard lk(mu_);
    if (!prepared.ok) {
      r.status = "failed";
      r.error = prepared.error;
      log_.push_back(r);
    } else if (queue_.size() >= kMaxQueued) {
      r.status = "failed";
      r.error = "memory queue is full";
      log_.push_back(r);
    } else {
      queue_.push_back(r);
      queued = true;
    }
  }
  notify(r);
  if (queued) cv_.notify_all();
}

void Store::analyze(const std::string& ns, const std::string& text) {
  if (!enabled() || text.size() < 12) return;
  put(ns, "analyze", text);  // worker routes kind=analyze to /api/analyze
}

std::vector<Memory> Store::recall(const std::string& query, const std::string& ns, const RecallOptions& opt,
                                  bool* failed) {
  if (!enabled() || query.empty()) return {};
  try {
    return client_->recall(query, ns, opt);
  } catch (const std::exception& e) {
    log_err(("recall " + ns).c_str(), e);
    if (failed) *failed = true;
    return {};
  }
}

void Store::add_listener(WriteListener fn) {
  std::lock_guard lk(mu_);
  listeners_.push_back(std::move(fn));
}

std::vector<WriteRecord> Store::recent(size_t n) const {
  std::lock_guard lk(mu_);
  std::vector<WriteRecord> out(queue_.begin(), queue_.end());
  const size_t start = log_.size() > n ? log_.size() - n : 0;
  out.insert(out.end(), log_.begin() + start, log_.end());
  return out;
}

void Store::notify(const WriteRecord& r) {
  std::vector<WriteListener> ls;
  {
    std::lock_guard lk(mu_);
    ls = listeners_;
  }
  for (auto& l : ls) l(r);
}

void Store::flush(std::chrono::seconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    {
      std::lock_guard lk(mu_);
      bool busy = !queue_.empty();
      for (auto& r : log_) busy |= (r.status != "done" && r.status != "failed");
      if (!busy) return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
}

bool Store::retry_later(WriteRecord& r) {
  static constexpr int kMaxAttempts = 4;
  const bool transient = r.error.find("navailable") != std::string::npos || r.error.find("imeout") != std::string::npos ||
                         r.error.find("timed out") != std::string::npos || r.error.find(" 50") != std::string::npos ||
                         r.error.find("onnection") != std::string::npos;
  if (!transient || r.attempts + 1 >= kMaxAttempts || r.kind == "analyze") return false;
  WriteRecord again{.ns = r.ns, .kind = r.kind, .text = r.text, .ref = r.ref, .owner = r.owner, .ts = r.ts};
  again.attempts = r.attempts + 1;
  again.retry_at = std::time(nullptr) + (20L << r.attempts);  // 20s, 40s, 80s
  queue_.push_back(std::move(again));  // caller holds mu_
  return true;
}

void Store::worker() {
  while (!stop_) {
    // 1) Submit everything queued. Plain memories go through /api/remember/bulk (≤20 per call).
    std::vector<WriteRecord> batch;
    {
      std::unique_lock lk(mu_);
      cv_.wait_for(lk, std::chrono::seconds(2), [&] {
        const int64_t now = std::time(nullptr);
        return stop_ || std::any_of(queue_.begin(), queue_.end(), [&](auto& r) { return r.retry_at <= now; });
      });
      const int64_t now = std::time(nullptr);
      std::deque<WriteRecord> later;
      while (!queue_.empty()) {
        if (queue_.front().retry_at <= now) batch.push_back(std::move(queue_.front()));
        else later.push_back(std::move(queue_.front()));
        queue_.pop_front();
      }
      queue_.swap(later);
      // A retried write replaces its earlier entry in the log instead of showing twice.
      for (auto& r : batch)
        if (r.attempts > 0)
          std::erase_if(log_, [&](const WriteRecord& o) { return o.status == "retrying" && o.ns == r.ns && o.text == r.text; });
    }
    std::vector<WriteRecord> plain, submitted;
    for (auto& r : batch) {
      if (r.kind != "analyze") {
        plain.push_back(std::move(r));
        continue;
      }
      try {
        auto res = client_->analyze(r.text, r.ns);
        for (auto& f : res.value("facts", json::array())) {
          WriteRecord fr = r;
          fr.kind = "fact";
          fr.text = f.value("text", "");
          fr.job_id = f.value("job_id", f.value("id", ""));
          fr.status = "running";
          submitted.push_back(fr);
        }
      } catch (const std::exception& e) {
        log_err("analyze", e);
      }
    }
    if (!plain.empty()) {
      std::vector<std::pair<std::string, std::string>> items;
      for (auto& r : plain) items.emplace_back(r.text, r.ns);
      try {
        auto ids = client_->remember_bulk(items);
        for (size_t i = 0; i < plain.size(); ++i) {
          plain[i].job_id = i < ids.size() ? ids[i] : "";
          plain[i].status = plain[i].job_id.empty() ? "failed" : "running";
          submitted.push_back(plain[i]);
        }
      } catch (const std::exception& e) {
        log_err("remember", e);
        std::lock_guard lk(mu_);
        for (auto& r : plain) {
          r.error = e.what();
          r.status = retry_later(r) ? "retrying" : "failed";
          submitted.push_back(r);
        }
      }
    }
    if (!submitted.empty()) {
      {
        std::lock_guard lk(mu_);
        log_.insert(log_.end(), submitted.begin(), submitted.end());
      }
      for (auto& r : submitted) notify(r);
    }

    // 2) Poll in-flight jobs until Walrus reports a blob id.
    std::vector<std::string> pending;
    {
      std::lock_guard lk(mu_);
      for (auto& r : log_)
        if (r.status != "done" && r.status != "failed" && !r.job_id.empty()) pending.push_back(r.job_id);
    }
    if (pending.empty()) continue;
    std::vector<JobStatus> st;
    try {
      st = client_->jobs(pending);
    } catch (const std::exception& e) {
      log_err("job status", e);
      continue;
    }
    std::vector<WriteRecord> changed;
    {
      std::lock_guard lk(mu_);
      for (auto& s : st) {
        for (auto& r : log_) {
          if (r.job_id != s.job_id || r.status == s.status) continue;
          r.status = s.status == "not_found" ? "failed" : s.status;
          r.blob_id = s.blob_id;
          r.error = s.error;
          if (r.status == "failed" && retry_later(r)) r.status = "retrying";
          if (r.status == "done") ++blobs_written_;
          changed.push_back(r);
        }
      }
    }
    for (auto& r : changed) notify(r);

    // The log is only this session's view for the UI: keep every write still in flight, and the
    // most recent settled ones.
    {
      std::lock_guard lk(mu_);
      constexpr size_t kKeepSettled = 500;
      size_t settled = 0;
      for (auto it = log_.rbegin(); it != log_.rend(); ++it) settled += it->status == "done" || it->status == "failed";
      for (auto it = log_.begin(); settled > kKeepSettled && it != log_.end();) {
        if (it->status == "done" || it->status == "failed") {
          it = log_.erase(it);
          --settled;
        } else {
          ++it;
        }
      }
    }
  }
}

}  // namespace saga::memwal

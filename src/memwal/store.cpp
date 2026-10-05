#include "memwal/store.h"

#include <cstdio>
#include <future>

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
  if (!this->enabled()) return;
  client_->set_background_stop([this] { return stop_.load(); });
  thread_ = std::thread([this] { worker(); });
}

Store::~Store() {
  stop_ = true;
  cv_.notify_all();
  if (thread_.joinable()) thread_.join();
  if (enabled()) client_->set_background_stop(nullptr);
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
  // The same read already in flight (the chat list and a user's settings load both read their
  // transcripts when a page opens) is joined, not sent again: its answer is as fresh as a new one.
  const std::string key = json::array({ns, query, opt.limit, opt.max_distance ? *opt.max_distance : -1.0, opt.recent,
                                       opt.recency_weight, opt.importance_weight}).dump();
  std::promise<Recalled> mine;
  std::shared_future<Recalled> flight;
  bool leader = false;
  {
    std::lock_guard lk(mu_);
    auto it = recalls_.find(key);
    if (it == recalls_.end()) {
      it = recalls_.emplace(key, mine.get_future().share()).first;
      leader = true;
    }
    flight = it->second;
  }
  if (leader) {
    Recalled r;
    try {
      r.hits = client_->recall(query, ns, opt);
    } catch (const std::exception& e) {
      log_err(("recall " + ns).c_str(), e);
      r.failed = true;
    }
    {
      std::lock_guard lk(mu_);
      recalls_.erase(key);
    }
    mine.set_value(std::move(r));
  }
  const Recalled& r = flight.get();
  if (failed && r.failed) *failed = true;
  return r.hits;
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
  // While someone waits, the worker sends at once and checks for blob ids every second.
  struct Flushing {
    Store& s;
    explicit Flushing(Store& s) : s(s) { ++s.flushing_; s.cv_.notify_all(); }
    ~Flushing() { --s.flushing_; }
  } flushing{*this};
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    {
      std::lock_guard lk(mu_);
      bool busy = !queue_.empty() || submitting_ > 0;
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
  // Everything this thread sends is background work for the relayer's budget: users' reads go first.
  BackgroundRequests background;
  using clock = std::chrono::steady_clock;
  // A write takes about 20 s to reach Walrus, and each status request spends the budget, so the first
  // check waits kFirstPoll after submission and later ones come every kPollEvery. While a caller waits in
  // flush(), checks start at once and come every kFlushPollEvery: faster polling would spend the
  // background share of the budget and then stall until the minute rolls over.
  constexpr std::chrono::milliseconds kGather{150}, kFirstPoll{10'000}, kPollEvery{4'000}, kFlushPollEvery{2'000};
  clock::time_point next_poll{};
  while (!stop_) {
    // 1) Submit everything queued: one write through /api/remember, several through /api/remember/bulk
    // (≤20 per call), which costs the relayer's budget as much as two single writes.
    std::vector<WriteRecord> batch;
    {
      std::unique_lock lk(mu_);
      auto ready = [&] {
        const int64_t now = std::time(nullptr);
        return std::any_of(queue_.begin(), queue_.end(), [&](auto& r) { return r.retry_at <= now; });
      };
      cv_.wait_for(lk, flushing_ > 0 ? std::chrono::milliseconds(250) : std::chrono::milliseconds(1000),
                   [&] { return stop_ || ready(); });
      // A turn's writes arrive moments apart (a step's checkpoint, then the episode and transcript):
      // a short pause sends the burst as one request instead of several.
      if (!stop_ && ready() && flushing_ == 0) cv_.wait_for(lk, kGather, [&] { return stop_.load(); });
      const int64_t now = std::time(nullptr);
      std::deque<WriteRecord> later;
      while (!queue_.empty()) {
        if (queue_.front().retry_at <= now) batch.push_back(std::move(queue_.front()));
        else later.push_back(std::move(queue_.front()));
        queue_.pop_front();
      }
      queue_.swap(later);
      submitting_ = batch.size();
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
          fr.submitted = clock::now();
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
        const auto ids = items.size() == 1 ? std::vector<std::string>{client_->remember(items[0].first, items[0].second)}
                                           : client_->remember_bulk(items);
        for (size_t i = 0; i < plain.size(); ++i) {
          plain[i].job_id = i < ids.size() ? ids[i] : "";
          plain[i].status = plain[i].job_id.empty() ? "failed" : "running";
          plain[i].submitted = clock::now();
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
    {
      std::lock_guard lk(mu_);
      log_.insert(log_.end(), submitted.begin(), submitted.end());
      submitting_ = 0;
    }
    for (auto& r : submitted) notify(r);

    // 2) Poll in-flight jobs until Walrus reports a blob id.
    std::vector<std::string> pending;
    const auto now = clock::now();
    bool due = false;
    {
      std::lock_guard lk(mu_);
      for (auto& r : log_)
        if (r.status != "done" && r.status != "failed" && !r.job_id.empty()) {
          pending.push_back(r.job_id);
          due |= flushing_ > 0 || now - r.submitted >= kFirstPoll;
        }
    }
    if (pending.empty() || !due || now < next_poll) continue;
    next_poll = now + (flushing_ > 0 ? kFlushPollEvery : kPollEvery);
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

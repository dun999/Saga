#include "memwal/store.h"

#include <cstdio>
#include <future>
#include <algorithm>
#include <cctype>

#include "memwal/redact.h"

namespace saga::memwal {
namespace {

int64_t now_s() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
      .count();
}

void log_err(const char* what, const std::exception& e) { std::fprintf(stderr, "[memory] %s: %s\n", what, e.what()); }

std::string normalized(std::string_view text) {
  std::string out;
  bool space = false;
  for (unsigned char c : text) {
    if (std::isspace(c)) { space = !out.empty(); continue; }
    if (space) out += ' ';
    out += static_cast<char>(c);
    space = false;
  }
  return out;
}

std::string memory_id(const std::string& kind, const std::string& text) {
  return "m-" + crypto::sha256_hex(kind + "\n" + normalized(text)).substr(0, 32);
}

Memory unpack(Memory m, const std::string& ns) {
  m.namespace_ = ns;
  if (auto r = decode_record(m.text, "memory"); r && r->is_object()) {
    auto str = [&](const char* key, const std::string& fallback = "") {
      return r->contains(key) && (*r)[key].is_string() ? (*r)[key].get<std::string>() : fallback;
    };
    m.text = str("text");
    m.kind = str("kind", "fact");
    m.agent = str("agent");
    m.session = str("session");
    m.id = memory_id(m.kind, m.text);
  } else if (auto uid = shared_uid(ns); uid) {
    m.kind = "fact";  // tolerate plain memories written by an older client
  } else {
    const auto suffix = ns.substr(ns.find_last_of(':') + 1);
    m.kind = ns.find(":lessons:") != std::string::npos ? "lesson" :
             suffix == "episodes" ? "episode" : suffix == "skills" ? "skill" : "fact";
  }
  if (m.id.empty()) m.id = memory_id(m.kind, m.text);
  return m;
}

}  // namespace

json WriteRecord::to_json() const {
  const auto record = decode_record(text, "memory");
  const auto excerpt = record && record->is_object() && record->contains("text") && (*record)["text"].is_string()
                           ? (*record)["text"].get<std::string>() : text;
  return {{"namespace", ns}, {"kind", kind}, {"text", excerpt.substr(0, 240)}, {"job_id", job_id},
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

bool Store::put(const std::string& ns, const std::string& kind, const std::string& text, const std::string& ref,
                const std::string& owner) {
  if (!enabled() || text.empty()) return false;
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
    if (shared_uid(ns) && prepared.ok) {
      const auto m = unpack(Memory{.text = prepared.text}, ns);
      for (const auto& [space, known] : local_)
        if (space == ns && known.id == m.id) return true;
    }
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
      update_local(r);
      queued = true;
    }
  }
  notify(r);
  if (queued) cv_.notify_all();
  return queued;
}

json Store::remember(const std::string& uid, const std::string& text, const std::string& kind,
                     const std::string& agent, const std::string& session, const std::string& ref) {
  const std::string ns = shared_namespace(uid);
  if (!enabled()) return {{"ok", false}, {"error", "memory is disabled"}};
  if (kind != "fact" && kind != "correction" && kind != "episode" && kind != "lesson" && kind != "skill")
    return {{"ok", false}, {"error", "unsupported memory kind"}};
  if (text.empty() || text.size() > 32000) return {{"ok", false}, {"error", "text required (at most 32000 bytes)"}};
  const auto safe = prepare_for_storage(text);
  if (!safe.ok || safe.found || normalized(safe.text).empty())
    return {{"ok", false}, {"error", "memory proposal contained a secret or invalid text"}};
  const auto id = memory_id(kind, safe.text);
  const auto record = encode_record("memory", {{"id", id}, {"kind", kind}, {"text", safe.text},
      {"agent", agent}, {"session", session}, {"ts", now_s()}});
  if (!put(ns, kind, record, ref, uid)) return {{"ok", false}, {"error", "memory queue is full"}};
  for (const auto& m : local_memories(ns))
    if (m.id == id) return {{"ok", true}, {"ns", ns}, {"id", id}, {"status", m.status}, {"blob_id", m.blob_id}};
  return {{"ok", true}, {"ns", ns}, {"id", id}, {"status", "queued"}};
}

void Store::update_local(const WriteRecord& r) {
  if (!shared_uid(r.ns)) return;
  auto m = unpack(Memory{.text = r.text}, r.ns);
  std::erase_if(local_, [&](const auto& item) { return item.first == r.ns && item.second.id == m.id; });
  if (r.status == "failed") return;
  m.status = r.status;
  m.blob_id = r.blob_id;
  m.local = true;
  local_.emplace_back(r.ns, std::move(m));
  constexpr size_t kMaxLocal = 256;
  while (local_.size() > kMaxLocal) local_.pop_front();
}

std::vector<Memory> Store::local_memories(const std::string& ns) const {
  std::lock_guard lk(mu_);
  std::vector<Memory> out;
  for (auto it = local_.rbegin(); it != local_.rend(); ++it)
    if (it->first == ns) out.push_back(it->second);
  return out;
}

void Store::legacy_agents(const std::vector<std::string>& names) {
  std::lock_guard lk(mu_);
  legacy_agents_.insert(names.begin(), names.end());
}

std::vector<std::string> Store::legacy_namespaces(const std::string& uid) {
  // An inventory distinguishes new users (one shared read) from users with legacy knowledge.
  // No data is copied or deleted: old blob IDs remain the sources, including removed agents.
  std::call_once(namespaces_loaded_, [&] {
    try {
      std::set<std::string> spaces;
      for (const auto& n : client_->namespaces().value("namespaces", json::array()))
        spaces.insert(n.is_string() ? n.get<std::string>() : n.value("namespace", n.value("name", "")));
      namespaces_ = std::move(spaces);
    } catch (const std::exception&) { /* older relayers: use known content namespaces */ }
  });
  std::vector<std::string> out;
  if (namespaces_) {
    for (const auto& ns : *namespaces_) if (legacy_knowledge(uid, ns)) out.push_back(ns);
  } else {
    out = {user_namespace(uid, "facts"), user_namespace(uid, "episodes"), user_namespace(uid, "skills")};
    std::lock_guard lk(mu_);
    for (const auto& agent : legacy_agents_) out.push_back(user_namespace(uid, "lessons:" + agent));
  }
  return out;
}

std::vector<Memory> Store::recall(const std::string& query, const std::string& ns, const RecallOptions& opt,
                                  bool* failed) {
  if (!enabled() || query.empty()) return {};
  const auto uid = shared_uid(ns);
  if (!uid) return recall_one(query, ns, opt, failed);
  std::vector<std::future<Recalled>> reads;
  auto spaces = legacy_namespaces(*uid);
  spaces.insert(spaces.begin(), ns);
  for (const auto& space : spaces)
    reads.push_back(std::async(std::launch::async, [&, space] {
      Recalled r;
      r.hits = recall_one(query, space, opt, &r.failed);
      for (auto& m : r.hits) m = unpack(std::move(m), space);
      return r;
    }));
  std::vector<Memory> hits;
  for (auto& read : reads) {
    auto r = read.get();
    if (failed && r.failed) *failed = true;
    for (auto& m : r.hits) hits.push_back(std::move(m));
  }
  std::stable_sort(hits.begin(), hits.end(), [&](const Memory& a, const Memory& b) {
    if (opt.recent && a.created_at != b.created_at) return a.created_at > b.created_at;
    return a.score.value_or(1 - a.distance) > b.score.value_or(1 - b.distance);
  });
  std::set<std::string> seen;
  std::erase_if(hits, [&](const Memory& m) { return m.text.empty() || !seen.insert(m.id).second; });
  auto local = local_memories(ns);
  std::vector<Memory> fresh;
  for (auto& m : local) {
    if (seen.contains(m.id)) continue;
    if (fresh.size() < 4) fresh.push_back(std::move(m));
  }
  if (hits.size() + fresh.size() > static_cast<size_t>(std::max(opt.limit, 1)))
    hits.resize(std::max(opt.limit, 1) - std::min<int>(fresh.size(), std::max(opt.limit, 1)));
  if (fresh.size() > static_cast<size_t>(std::max(opt.limit, 1))) fresh.resize(std::max(opt.limit, 1));
  hits.insert(hits.end(), fresh.begin(), fresh.end());
  return hits;
}

std::vector<Memory> Store::recall_one(const std::string& query, const std::string& ns, const RecallOptions& opt,
                                     bool* failed) {
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
      for (auto& m : r.hits) m.namespace_ = ns;
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
  if (!transient || r.attempts + 1 >= kMaxAttempts) return false;
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
    std::vector<WriteRecord> plain = std::move(batch), submitted;
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
      for (const auto& r : submitted) update_local(r);
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
          update_local(r);
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

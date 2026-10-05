#include "memwal/client.h"
#include "memwal/redact.h"

#include <cstdio>
#include <ctime>
#include <thread>

#include "core/http.h"

namespace saga::memwal {
namespace {

constexpr int kSealTtlMin = 5;                 // matches official SDKs
constexpr int64_t kSealSafetyMarginMs = 30'000;

int64_t now_ms() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

std::string describe(const http::Response& r) {
  std::string m = r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error;
  if (auto it = r.headers.find("x-auth-error"); it != r.headers.end()) m += " [" + it->second + "]";
  if (!r.body.empty()) m += ": " + r.body.substr(0, 300);
  return m;
}

// Redact, or refuse, before any byte is signed and sent. A refusal is a short error, never the input.
std::string for_storage(const std::string& text) {
  const StorageText r = prepare_for_storage(text);
  if (!r.ok) throw Error(400, r.error.empty() ? "memory record refused" : r.error);
  return r.text;
}

}  // namespace

namespace {
thread_local bool tl_background = false;
}

BackgroundRequests::BackgroundRequests() : prev_(tl_background) { tl_background = true; }
BackgroundRequests::~BackgroundRequests() { tl_background = prev_; }

// The relayer's endpoint weights (services/server/src/rate_limit.rs). The owner read API has its own
// budget, and the unauthenticated routes none.
int RateBudget::weight(const std::string& method, const std::string& path) {
  if (path.starts_with("/v1/owners/")) return 0;
  if (method == "POST" && path == "/api/analyze") return 5;
  if (method == "POST" && path == "/api/remember") return 5;
  if (method == "POST" && path == "/api/remember/bulk") return 10;
  if (path == "/api/restore") return 3;
  return 1;
}

int RateBudget::used_locked(clock::time_point now) const {
  while (!spent_.empty() && now - spent_.front().first >= std::chrono::seconds(60)) spent_.pop_front();
  int used = 0;
  for (auto& [_, w] : spent_) used += w;
  return used;
}

void RateBudget::spend(int weight) {
  if (weight <= 0) return;
  std::lock_guard lk(mu_);
  spent_.emplace_back(clock::now(), weight);
}

bool RateBudget::wait_for(int weight, const std::function<bool()>& stop) {
  if (weight <= 0) return true;
  for (;;) {
    if (stop && stop()) return false;
    clock::time_point until;
    {
      std::lock_guard lk(mu_);
      const auto now = clock::now();
      if (now >= hold_until_ && used_locked(now) + weight <= std::max(limit_ - kReserve, weight)) {
        spent_.emplace_back(now, weight);
        return true;
      }
      // Headroom returns when the oldest spend leaves the window, or the relayer's hold ends.
      until = now < hold_until_ ? hold_until_ : spent_.front().first + std::chrono::seconds(60);
    }
    std::this_thread::sleep_for(std::min<clock::duration>(until - clock::now(), std::chrono::milliseconds(500)));
  }
}

void RateBudget::denied(const std::string& body, int retry_after_s) {
  std::lock_guard lk(mu_);
  hold_until_ = std::max(hold_until_, clock::now() + std::chrono::seconds(retry_after_s));
  // {"layer":"delegate_key","limit":"60 weighted-requests/min",...}
  const auto j = json::parse(body, nullptr, false);
  if (!j.is_object() || j.value("layer", "") != "delegate_key") return;
  const std::string limit = j.value("limit", "");
  if (!limit.ends_with("/min")) return;
  try {
    if (const int n = std::stoi(limit); n > 0) limit_ = n;
  } catch (...) {
  }
}

int RateBudget::limit() const {
  std::lock_guard lk(mu_);
  return limit_;
}

int RateBudget::spent() const {
  std::lock_guard lk(mu_);
  return used_locked(clock::now());
}

std::string canonical_message(const std::string& ts, const std::string& method, const std::string& path,
                              const std::string& body_sha256, const std::string& nonce,
                              const std::string& account_id) {
  return ts + "." + method + "." + path + "." + body_sha256 + "." + nonce + "." + account_id;
}

std::string seal_personal_message(const std::string& package_id, int ttl_min, int64_t creation_ms,
                                  const crypto::Bytes& session_pub) {
  const std::time_t secs = static_cast<std::time_t>(creation_ms / 1000);
  std::tm tm{};
  gmtime_r(&secs, &tm);
  char when[32];
  std::strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S UTC", &tm);
  return "Accessing keys of package " + package_id + " for " + std::to_string(ttl_min) + " mins from " +
         when + ", session key " + crypto::b64_encode(session_pub);
}

Client::Client(Config cfg) : cfg_(std::move(cfg)), key_(crypto::Ed25519Key::parse(cfg_.private_key)) {
  while (!cfg_.server_url.empty() && cfg_.server_url.back() == '/') cfg_.server_url.pop_back();
  address_ = key_.sui_address();
}

json Client::health() const {
  auto r = http::get(cfg_.server_url + "/health");
  if (!r.ok()) throw Error(r.status, "health: " + describe(r));
  return json::parse(r.body);
}

json Client::server_config() {
  std::lock_guard lk(mu_);
  if (!config_cache_) {
    auto r = http::get(cfg_.server_url + "/config");
    if (!r.ok()) throw Error(r.status, "config: " + describe(r));
    config_cache_ = json::parse(r.body);
  }
  return *config_cache_;
}

std::string Client::seal_session() {
  const std::string package_id = server_config().value("packageId", "");
  std::lock_guard lk(mu_);
  if (!session_cache_.empty() && now_ms() < session_expiry_ms_) return session_cache_;
  if (package_id.empty()) throw Error(0, "relayer /config has no packageId");

  const auto session = crypto::Ed25519Key::generate();
  const int64_t created = now_ms();
  const std::string pm =
      seal_personal_message(package_id, kSealTtlMin, created, {session.pub.begin(), session.pub.end()});
  const json envelope = {
      {"address", address_},
      {"packageId", package_id},
      {"mvrName", nullptr},
      {"creationTimeMs", created},
      {"ttlMin", kSealTtlMin},
      {"personalMessageSignature", key_.sign_personal_message(pm)},
      {"sessionKey", session.sui_private_key()},
  };
  session_cache_ = crypto::b64_encode(envelope.dump());
  session_expiry_ms_ = created + kSealTtlMin * 60'000 - kSealSafetyMarginMs;
  return session_cache_;
}

json Client::signed_request(const std::string& method, const std::string& path, const json& body,
                            bool include_seal_session, long timeout_s) {
  const std::string body_str = (method == "GET" || body.is_null()) ? "" : body.dump();
  const int weight = RateBudget::weight(method, path);
  for (int attempt = 0;; ++attempt) {
    if (!tl_background) budget_.spend(weight);
    else if (!budget_.wait_for(weight, background_stop_)) throw Error(0, method + " " + path + ": shutting down");
    const std::string ts = std::to_string(now_ms() / 1000);
    const std::string nonce = crypto::uuid4();
    const auto sig = key_.sign(
        canonical_message(ts, method, path, crypto::sha256_hex(body_str), nonce, cfg_.account_id));

    http::Headers h = {
        {"Content-Type", "application/json"},
        {"x-public-key", key_.pub_hex()},
        {"x-signature", crypto::to_hex(sig.data(), sig.size())},
        {"x-timestamp", ts},
        {"x-nonce", nonce},
        {"x-account-id", cfg_.account_id},
    };
    if (include_seal_session) h["x-seal-session"] = seal_session();

    auto r = http::request(method, cfg_.server_url + path, h, body_str, timeout_s);
    // 503 (Sui upstream / rate limiter) and 429 are retryable with backoff. So is a transport error,
    // except for a write that may already have landed (a timeout after sending): retrying that
    // would store the memory twice.
    const bool write = path.starts_with("/api/remember") && path.find("/status") == std::string::npos &&
                       method == "POST";
    const bool not_sent = r.error.find("connect to server") != std::string::npos ||
                          r.error.find("resolve") != std::string::npos;
    const bool transport = !r.error.empty() && (!(write || path == "/api/analyze") || not_sent);
    if ((r.status == 503 || r.status == 429 || transport) && attempt < 3) {
      int wait_s = 2 << attempt;
      if (auto it = r.headers.find("retry-after"); it != r.headers.end()) {
        try { wait_s = std::max(1, std::stoi(it->second)); } catch (...) {}
      }
      if (r.status == 429) budget_.denied(r.body, wait_s);
      std::fprintf(stderr, "[memory] %s %s: %s, retrying in %ds\n", method.c_str(), path.c_str(),
                   r.error.empty() ? ("HTTP " + std::to_string(r.status)).c_str() : r.error.c_str(), wait_s);
      std::this_thread::sleep_for(std::chrono::seconds(wait_s));
      continue;
    }
    if (!r.ok()) throw Error(r.status, method + " " + path + ": " + describe(r));
    return r.body.empty() ? json::object() : json::parse(r.body);
  }
}

json Client::whoami() { return signed_request("GET", "/api/whoami", nullptr, false); }

std::string Client::remember(const std::string& text, const std::string& ns) {
  return signed_request("POST", "/api/remember", {{"text", for_storage(text)}, {"namespace", ns}}).value("job_id", "");
}

std::vector<std::string> Client::remember_bulk(const std::vector<std::pair<std::string, std::string>>& items) {
  // Refuse the whole call before the first request, so one bad record can't ride along with the rest.
  std::vector<std::pair<std::string, std::string>> clean;
  clean.reserve(items.size());
  for (auto& it : items) clean.emplace_back(for_storage(it.first), it.second);
  std::vector<std::string> ids;
  for (size_t off = 0; off < clean.size(); off += 20) {  // relayer cap: 20 per request
    json arr = json::array();
    for (size_t i = off; i < std::min(clean.size(), off + 20); ++i)
      arr.push_back({{"text", clean[i].first}, {"namespace", clean[i].second}});
    auto res = signed_request("POST", "/api/remember/bulk", {{"items", arr}});
    for (auto& id : res.value("job_ids", json::array())) ids.push_back(id.get<std::string>());
  }
  return ids;
}

static JobStatus parse_job(const json& j) {
  JobStatus s;
  s.job_id = j.value("job_id", "");
  s.status = j.value("status", "");
  if (j.contains("blob_id") && j["blob_id"].is_string()) s.blob_id = j["blob_id"];
  if (j.contains("error") && j["error"].is_string()) s.error = j["error"];
  if (j.contains("namespace") && j["namespace"].is_string()) s.namespace_ = j["namespace"];
  return s;
}

JobStatus Client::job(const std::string& job_id) {
  return parse_job(signed_request("GET", "/api/remember/" + job_id, nullptr, false));
}

std::vector<JobStatus> Client::jobs(const std::vector<std::string>& job_ids) {
  std::vector<JobStatus> out;
  for (size_t off = 0; off < job_ids.size(); off += 100) {
    json ids(std::vector<std::string>(job_ids.begin() + off,
                                      job_ids.begin() + std::min(job_ids.size(), off + 100)));
    auto res = signed_request("POST", "/api/remember/bulk/status", {{"job_ids", ids}}, false);
    for (auto& j : res.value("results", json::array())) out.push_back(parse_job(j));
  }
  return out;
}

JobStatus Client::wait(const std::string& job_id, std::chrono::seconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  auto delay = std::chrono::milliseconds(500);
  for (;;) {
    auto s = job(job_id);
    if (s.settled() || std::chrono::steady_clock::now() > deadline) return s;
    std::this_thread::sleep_for(delay);
    delay = std::min(delay * 2, std::chrono::milliseconds(4000));
  }
}

std::vector<Memory> Client::recall(const std::string& query, const std::string& ns, const RecallOptions& opt) {
  json body = {{"query", query}, {"limit", opt.limit}, {"namespace", ns}};
  if (opt.recent) {
    body["sort"] = "recent";
  } else if (opt.recency_weight > 0 || opt.importance_weight > 0) {
    body["scoring_weights"] = {{"semantic", 1.0},
                               {"recency", opt.recency_weight},
                               {"importance", opt.importance_weight}};
  }
  auto res = signed_request("POST", "/api/recall", body);
  std::vector<Memory> out;
  for (auto& r : res.value("results", json::array())) {
    Memory m{r.value("blob_id", ""), r.value("text", ""), r.value("distance", 1.0), std::nullopt};
    if (r.contains("score") && r["score"].is_number()) m.score = r["score"].get<double>();
    if (r.contains("created_at") && r["created_at"].is_string()) m.created_at = r["created_at"].get<std::string>();
    if (opt.max_distance && m.distance > *opt.max_distance) continue;
    out.push_back(std::move(m));
  }
  return out;
}

json Client::analyze(const std::string& text, const std::string& ns) {
  json res = signed_request("POST", "/api/analyze", {{"text", for_storage(text)}, {"namespace", ns}}, true, 120);
  budget_.spend(static_cast<int>(res.value("facts", json::array()).size()));  // the relayer charges one per fact
  return res;
}

json Client::restore(const std::string& ns, int limit) {
  return signed_request("POST", "/api/restore", {{"namespace", ns}, {"limit", limit}}, true, 300);
}

json Client::stats(const std::string& ns) {
  return signed_request("POST", "/api/stats", {{"namespace", ns}}, false);
}

json Client::namespaces() {
  // The route is keyed by the account *owner* (wallet), not the delegate key address.
  const std::string owner = whoami().value("owner", address_);
  return signed_request("GET", "/v1/owners/" + owner + "/namespaces", nullptr, false);
}

}  // namespace saga::memwal

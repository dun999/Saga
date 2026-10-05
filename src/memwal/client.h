#pragma once
// Native C++ client for the Walrus Memory (MemWal) relayer.
// Wire protocol ported from MystenLabs/MemWal (services/server/src/auth.rs and the
// Python SDK): Ed25519 signed headers + a SEAL SessionKey envelope for decrypt flows.
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/crypto.h"

namespace saga::memwal {

using json = nlohmann::json;

struct Config {
  std::string private_key;  // hex seed or suiprivkey1…
  std::string account_id;   // MemWalAccount object id (0x…)
  std::string server_url = "https://relayer.memory.walrus.xyz";
};

struct Memory {
  std::string blob_id;
  std::string text;
  double distance = 0;
  std::optional<double> score;
  std::string created_at;  // optional RFC3339 write time, returned by newer relayers
};

struct JobStatus {
  std::string job_id, status, blob_id, error, namespace_;
  bool done() const { return status == "done"; }
  bool settled() const { return status == "done" || status == "failed" || status == "not_found"; }
};

struct RecallOptions {
  int limit = 10;
  std::optional<double> max_distance;  // client-side filter, lower = closer
  bool recent = false;                  // sort:"recent" instead of relevance
  double recency_weight = 0, importance_weight = 0;
};

class Error : public std::runtime_error {
 public:
  Error(long status, const std::string& msg) : std::runtime_error(msg), status(status) {}
  long status;
};

// The relayer's weighted per-delegate-key budget (60 a minute on mainnet; a 429 that names another
// limit replaces it). Every signed request is counted with the relayer's own weights. Foreground
// requests (a turn's recalls, page loads) go at once; background ones (queued writes, status polls,
// fact extraction, restores) wait for headroom and leave kReserve for the foreground, so a user's
// reads are not refused with a minute-long Retry-After because of writes Saga could have spaced out.
class RateBudget {
 public:
  using clock = std::chrono::steady_clock;
  static constexpr int kReserve = 20;
  static int weight(const std::string& method, const std::string& path);
  void spend(int weight);
  // Waits until `weight` fits under the limit minus the reserve, then records it. False once `stop` is set.
  bool wait_for(int weight, const std::function<bool()>& stop);
  void denied(const std::string& body, int retry_after_s);  // a 429: learn the limit, hold background work
  int limit() const;
  int spent() const;

 private:
  int used_locked(clock::time_point now) const;
  mutable std::mutex mu_;
  mutable std::deque<std::pair<clock::time_point, int>> spent_;
  int limit_ = 60;
  clock::time_point hold_until_{};
};

// Marks the calling thread's requests as background work for the budget while in scope.
class BackgroundRequests {
 public:
  BackgroundRequests();
  ~BackgroundRequests();
  BackgroundRequests(const BackgroundRequests&) = delete;
  BackgroundRequests& operator=(const BackgroundRequests&) = delete;

 private:
  bool prev_;
};

// Exposed for tests.
std::string canonical_message(const std::string& ts, const std::string& method, const std::string& path,
                              const std::string& body_sha256, const std::string& nonce,
                              const std::string& account_id);
std::string seal_personal_message(const std::string& package_id, int ttl_min, int64_t creation_ms,
                                  const crypto::Bytes& session_pub);

class Client {
 public:
  explicit Client(Config cfg);

  // Public
  json health() const;
  json server_config();  // cached GET /config

  // Protected
  json whoami();
  std::string remember(const std::string& text, const std::string& ns);  // -> job_id
  std::vector<std::string> remember_bulk(const std::vector<std::pair<std::string, std::string>>& items);
  JobStatus job(const std::string& job_id);
  std::vector<JobStatus> jobs(const std::vector<std::string>& job_ids);
  JobStatus wait(const std::string& job_id, std::chrono::seconds timeout = std::chrono::seconds(90));
  std::vector<Memory> recall(const std::string& query, const std::string& ns, const RecallOptions& opt = {});
  json analyze(const std::string& text, const std::string& ns);  // {job_ids, facts, ...}
  json restore(const std::string& ns, int limit = 50);
  json stats(const std::string& ns);
  json namespaces();

  RateBudget& budget() { return budget_; }
  // Lets a background caller stop waiting for headroom (the store's worker, at shutdown).
  void set_background_stop(std::function<bool()> stop) { background_stop_ = std::move(stop); }

  const std::string& owner_address() const { return address_; }
  const std::string& account_id() const { return cfg_.account_id; }
  const std::string& server_url() const { return cfg_.server_url; }

  // Raw signed request; throws Error on non-2xx.
  json signed_request(const std::string& method, const std::string& path, const json& body = nullptr,
                      bool include_seal_session = true, long timeout_s = 60);

 private:
  std::string seal_session();

  Config cfg_;
  crypto::Ed25519Key key_;
  std::string address_;
  std::mutex mu_;
  std::optional<json> config_cache_;
  std::string session_cache_;
  int64_t session_expiry_ms_ = 0;
  RateBudget budget_;
  std::function<bool()> background_stop_;
};

}  // namespace saga::memwal

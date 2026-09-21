#pragma once
// Native C++ client for the Walrus Memory (MemWal) relayer.
// Wire protocol ported from MystenLabs/MemWal (services/server/src/auth.rs and the
// Python SDK): Ed25519 signed headers + a SEAL SessionKey envelope for decrypt flows.
#include <chrono>
#include <cstdint>
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
};

}  // namespace saga::memwal

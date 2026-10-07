#pragma once
// Local socket for `saga mem`. Agents call the running Saga process, which holds the MemWal
// delegate key. The key is never placed in an agent's environment.
#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "memwal/client.h"
#include "memwal/store.h"

namespace saga::memwal {

using json = nlohmann::json;

// Handles one request. Rejects privileged writes before any network call. A remember with
// "wait": false goes through `store` (when there is one) and answers once queued; otherwise it waits
// for Walrus to confirm the blob.
json gate_request(Client& client, const json& req, Store* store = nullptr);

// Connect to a Gate and return its response object.
json gate_transact(const std::string& path, const json& req);

class Gate {
 public:
  using Observer = std::function<void(const json& request, const json& response)>;
  // A nonempty recall_uid exposes only that user's content reads, for one sandboxed run.
  explicit Gate(Client& client, Store* store = nullptr, std::string recall_uid = {}, Observer observer = {});
  ~Gate();
  Gate(const Gate&) = delete;
  Gate& operator=(const Gate&) = delete;

  const std::string& path() const { return path_; }

 private:
  void serve();
  void handle(int fd);

  Client& client_;
  Store* store_;  // queued writes, shown in Saga's write log like the harness's own
  std::string recall_uid_;
  Observer observer_;
  std::string dir_;   // 0700 directory this gate created; the socket lives inside it
  std::string path_;
  int listen_fd_ = -1;
  static constexpr int kMaxActive = 16;
  std::mutex mu_;
  std::condition_variable idle_;
  int active_ = 0;  // requests being handled
  int recalls_ = 0;
  std::set<int> clients_;
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

}  // namespace saga::memwal

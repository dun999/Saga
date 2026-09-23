#pragma once
// Local socket for `saga mem`. Agents call the running Saga process, which holds the MemWal
// delegate key. The key is never placed in an agent's environment.
#include <atomic>
#include <mutex>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "memwal/client.h"

namespace saga::memwal {

using json = nlohmann::json;

// Handles one request. Rejects privileged writes before any network call.
json gate_request(Client& client, const json& req);

// Connect to a Gate and return its response object.
json gate_transact(const std::string& path, const json& req);

class Gate {
 public:
  explicit Gate(Client& client);
  ~Gate();
  Gate(const Gate&) = delete;
  Gate& operator=(const Gate&) = delete;

  const std::string& path() const { return path_; }

 private:
  void serve();
  void handle(int fd);

  Client& client_;
  std::string path_;
  int listen_fd_ = -1;
  std::mutex mu_;
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

}  // namespace saga::memwal

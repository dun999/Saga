#pragma once
#include <memory>
#include <string>
#include <vector>

namespace saga::proxy {
// Only CONNECT to public peers on 443 is supported. No raw host sockets enter the sandbox.
std::string connect_host(const std::string& request_line);
class Broker {
 public:
  Broker();
  ~Broker();
  Broker(const Broker&) = delete;
  Broker& operator=(const Broker&) = delete;
  const std::string& path() const;
 private:
  struct State;
  std::unique_ptr<State> state_;
};
// Internal launcher inside the network namespace. Relays its loopback proxy to the mounted broker.
int exec(const std::string& socket_path, const std::vector<std::string>& argv);
}  // namespace saga::proxy

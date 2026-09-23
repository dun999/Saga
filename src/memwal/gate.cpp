#include "memwal/gate.h"

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <stdexcept>

namespace saga::memwal {
namespace fs = std::filesystem;

namespace {

constexpr size_t kMaxLine = 65536;

std::string read_line(int fd) {
  std::string s;
  char buf[2048];
  while (s.size() < kMaxLine) {
    pollfd p{fd, POLLIN, 0};
    if (poll(&p, 1, 120000) <= 0) break;
    const ssize_t n = ::read(fd, buf, sizeof buf);
    if (n <= 0) break;
    s.append(buf, static_cast<size_t>(n));
    if (s.find('\n') != std::string::npos) break;
  }
  const auto nl = s.find('\n');
  return nl == std::string::npos ? std::string{} : s.substr(0, nl);
}

bool write_all(int fd, const std::string& s) {
  size_t off = 0;
  while (off < s.size()) {
    const ssize_t n = ::write(fd, s.data() + off, s.size() - off);
    if (n <= 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

}  // namespace

json gate_request(Client& client, const json& req) {
  const std::string op = req.value("op", "");
  const std::string ns = req.value("ns", "");
  if (ns.empty() || ns.size() > 200) return {{"ok", false}, {"error", "namespace required"}};
  if (op == "remember") {
    if (ns.starts_with("harness:")) return {{"ok", false}, {"error", "harness:* namespaces are written by the harness only"}};
    const std::string text = req.value("text", "");
    if (text.empty() || text.size() > 32000) return {{"ok", false}, {"error", "text required"}};
    const auto st = client.wait(client.remember(text, ns), std::chrono::seconds(90));
    return {{"ok", st.done()}, {"status", st.status}, {"ns", ns}, {"blob_id", st.blob_id}, {"error", st.error}};
  }
  if (op == "recall") {
    const std::string query = req.value("text", "");
    if (query.empty()) return {{"ok", true}, {"hits", json::array()}};
    int limit = req.value("limit", 8);
    if (limit < 1) limit = 1;
    if (limit > 20) limit = 20;
    json hits = json::array();
    for (auto& m : client.recall(query, ns, {.limit = limit}))
      hits.push_back({{"text", m.text}, {"distance", m.distance}, {"blob_id", m.blob_id}});
    return {{"ok", true}, {"hits", hits}};
  }
  return {{"ok", false}, {"error", "unknown op"}};
}

json gate_transact(const std::string& path, const json& req) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return {{"ok", false}, {"error", "cannot open memory socket"}};
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() >= sizeof addr.sun_path) {
    ::close(fd);
    return {{"ok", false}, {"error", "memory socket path too long"}};
  }
  std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
    ::close(fd);
    return {{"ok", false}, {"error", "saga memory socket is not running"}};
  }
  const std::string line = req.dump() + "\n";
  json out = {{"ok", false}, {"error", "empty memory response"}};
  if (write_all(fd, line)) {
    const std::string reply = read_line(fd);
    if (!reply.empty()) {
      auto j = json::parse(reply, nullptr, false);
      if (j.is_object()) out = std::move(j);
    }
  }
  ::close(fd);
  return out;
}

Gate::Gate(Client& client) : client_(client) {
  path_ = (fs::temp_directory_path() / ("saga-mem-" + std::to_string(::getpid()) + ".sock")).string();
  if (path_.size() >= sizeof(sockaddr_un::sun_path)) throw std::runtime_error("memory socket path too long");
  listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listen_fd_ < 0) throw std::runtime_error("memory socket");
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, path_.c_str(), path_.size() + 1);
  ::unlink(path_.c_str());
  if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0 ||
      ::fchmod(listen_fd_, 0600) != 0 || ::listen(listen_fd_, 16) != 0) {
    ::close(listen_fd_);
    ::unlink(path_.c_str());
    throw std::runtime_error("cannot bind memory socket " + path_);
  }
  thread_ = std::thread([this] { serve(); });
}

Gate::~Gate() {
  stop_ = true;
  if (thread_.joinable()) thread_.join();
  if (listen_fd_ >= 0) ::close(listen_fd_);
  if (!path_.empty()) ::unlink(path_.c_str());
}

void Gate::serve() {
  while (!stop_) {
    pollfd p{listen_fd_, POLLIN, 0};
    if (::poll(&p, 1, 200) <= 0) continue;
    const int fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
    if (fd < 0) continue;
    handle(fd);
    ::close(fd);
  }
}

void Gate::handle(int fd) {
  ucred cred{};
  socklen_t cred_len = sizeof cred;
  if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) != 0 || cred.uid != ::getuid()) {
    write_all(fd, json({{"ok", false}, {"error", "memory socket is for this user only"}}).dump() + "\n");
    return;
  }
  const std::string line = read_line(fd);
  auto req = json::parse(line, nullptr, false);
  json res = req.is_object() ? json() : json{{"ok", false}, {"error", "bad request"}};
  if (req.is_object()) {
    try {
      std::lock_guard lk(mu_);
      res = gate_request(client_, req);
    } catch (const std::exception& e) {
      res = {{"ok", false}, {"error", e.what()}};
    }
  }
  write_all(fd, res.dump() + "\n");
}

}  // namespace saga::memwal

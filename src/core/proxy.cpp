#include "core/proxy.h"
#include "core/http.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <thread>

namespace saga::proxy {
namespace {
std::atomic<int> connections{0};
struct Fd {
  int n;
  explicit Fd(int fd = -1) : n(fd) {}
  ~Fd() { if (n >= 0) ::close(n); }
  Fd(const Fd&) = delete;
};
void nonblocking(int fd) { ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK); }
bool send_all(int fd, std::string_view text, const std::atomic<bool>& stop) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
  while (!text.empty() && !stop && std::chrono::steady_clock::now() < deadline) {
    pollfd p{fd, POLLOUT, 0};
    if (::poll(&p, 1, 100) <= 0) continue;
    const ssize_t n = ::send(fd, text.data(), text.size(), MSG_NOSIGNAL);
    if (n > 0) text.remove_prefix(static_cast<size_t>(n));
    else if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
    else return false;
  }
  return text.empty();
}
std::string header(int fd, const std::atomic<bool>& stop) {
  std::string out;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
  while (out.size() < 8192 && !stop && std::chrono::steady_clock::now() < deadline) {
    pollfd p{fd, POLLIN, 0};
    if (::poll(&p, 1, 100) <= 0) continue;
    char byte;
    const ssize_t n = ::recv(fd, &byte, 1, 0);
    if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
    if (n != 1) break;
    out += byte;
    if (out.ends_with("\r\n\r\n")) return out;
  }
  return {};
}
// Fixed-size queues and half-close propagation. A slow peer cannot grow a memory buffer.
void bridge(int a, int b, const std::atomic<bool>& stop) {
  nonblocking(a); nonblocking(b);
  struct Direction { std::array<char, 16384> data{}; size_t off = 0, len = 0; bool eof = false, shut = false; } ab, ba;
  size_t total = 0;
  auto idle = std::chrono::steady_clock::now();
  while (!stop && total <= 256 * 1024 * 1024 &&
         std::chrono::steady_clock::now() - idle < std::chrono::seconds(120)) {
    if (ab.eof && ab.off == ab.len && !ab.shut) { ::shutdown(b, SHUT_WR); ab.shut = true; }
    if (ba.eof && ba.off == ba.len && !ba.shut) { ::shutdown(a, SHUT_WR); ba.shut = true; }
    if (ab.shut && ba.shut) return;
    pollfd p[2] = {{a, 0, 0}, {b, 0, 0}};
    if (!ab.eof && ab.off == ab.len) p[0].events |= POLLIN;
    if (!ba.eof && ba.off == ba.len) p[1].events |= POLLIN;
    if (ba.off < ba.len) p[0].events |= POLLOUT;
    if (ab.off < ab.len) p[1].events |= POLLOUT;
    if (::poll(p, 2, 100) <= 0) continue;
    auto receive = [&](int fd, Direction& q, short events) {
      if (q.eof || q.off != q.len || !(events & (POLLIN | POLLHUP | POLLERR))) return;
      const ssize_t n = ::recv(fd, q.data.data(), q.data.size(), 0);
      if (n > 0) { q.off = 0; q.len = static_cast<size_t>(n); total += q.len; idle = std::chrono::steady_clock::now(); }
      else if (n == 0 || (errno != EINTR && errno != EAGAIN)) q.eof = true;
    };
    auto transmit = [&](int fd, Direction& q, short events) {
      if (q.off == q.len || !(events & (POLLOUT | POLLHUP | POLLERR))) return true;
      const ssize_t n = ::send(fd, q.data.data() + q.off, q.len - q.off, MSG_NOSIGNAL);
      if (n > 0) { q.off += static_cast<size_t>(n); idle = std::chrono::steady_clock::now(); return true; }
      return n < 0 && (errno == EINTR || errno == EAGAIN);
    };
    receive(a, ab, p[0].revents); receive(b, ba, p[1].revents);
    if (!transmit(b, ab, p[1].revents) || !transmit(a, ba, p[0].revents)) return;
  }
}
int unix_connect(const std::string& path) {
  if (path.size() >= sizeof(sockaddr_un::sun_path)) return -1;
  Fd fd(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (fd.n < 0) return -1;
  sockaddr_un address{}; address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
  if (::connect(fd.n, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) return -1;
  const int out = ::fcntl(fd.n, F_DUPFD_CLOEXEC, 3); nonblocking(out); return out;
}
struct Workers {
  struct Job { std::thread thread; std::shared_ptr<std::atomic<bool>> done; };
  std::vector<Job> jobs;
  Workers() { jobs.reserve(16); }
  ~Workers() { for (auto& j : jobs) if (j.thread.joinable()) j.thread.join(); }
  template<class F> void start(int fd, F fn) {
    std::erase_if(jobs, [](Job& j) { if (!j.done->load()) return false; j.thread.join(); return true; });
    if (jobs.size() >= 16 || connections.fetch_add(1) >= 64) {
      if (jobs.size() < 16) --connections;
      ::close(fd); return;
    }
    auto done = std::make_shared<std::atomic<bool>>(false);
    try {
      jobs.push_back({std::thread([fd, fn = std::move(fn), done] {
        Fd client(fd);
        try { fn(fd); } catch (...) {}
        --connections; *done = true;
      }), done});
    } catch (...) { --connections; ::close(fd); throw; }
  }
};
}  // namespace

std::string connect_host(const std::string& line) {
  constexpr std::string_view prefix = "CONNECT ";
  if (!line.starts_with(prefix)) return {};
  const auto end = line.find(' ', prefix.size());
  if (end == std::string::npos) return {};
  const std::string target = line.substr(prefix.size(), end - prefix.size());
  if (!target.ends_with(":443")) return {};
  const std::string version = line.substr(end + 1);
  if (version != "HTTP/1.1" && version != "HTTP/1.0") return {};
  const std::string host = target.substr(0, target.size() - 4);
  if (host.empty() || host.size() > 255 ||
      host.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:[]") != std::string::npos)
    return {};
  if (host.front() == '[') {
    if (host.back() != ']' || host.find(']', 1) != host.size() - 1) return {};
  } else if (host.find_first_of(":[]") != std::string::npos) return {};
  return host;
}

struct Broker::State {
  std::string directory, socket;
  Fd listener;
  std::atomic<bool> stop{false};
  std::thread thread;
  State() {
    std::string pattern = (std::filesystem::temp_directory_path() / "saga-net-XXXXXX").string();
    if (!::mkdtemp(pattern.data())) throw std::runtime_error("cannot create agent network broker directory");
    directory = pattern; socket = directory + "/proxy.sock";
    if (socket.size() >= sizeof(sockaddr_un::sun_path)) {
      std::filesystem::remove(directory); throw std::runtime_error("agent proxy socket path is too long");
    }
    listener.n = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, socket.c_str(), socket.size() + 1);
    if (listener.n < 0 || ::bind(listener.n, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0 ||
        ::chmod(socket.c_str(), 0600) < 0 || ::listen(listener.n, 16) < 0) {
      std::filesystem::remove_all(directory); throw std::runtime_error("cannot start agent network broker");
    }
    thread = std::thread([this] {
      Workers workers;
      while (!stop) {
        pollfd p{listener.n, POLLIN, 0};
        if (::poll(&p, 1, 100) <= 0 || !(p.revents & POLLIN)) continue;
        const int fd = ::accept4(listener.n, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (fd < 0) continue;
        try { workers.start(fd, [this](int client) {
          const std::string request = header(client, stop);
          const std::string host = connect_host(request.substr(0, request.find("\r\n")));
          Fd remote(host.empty() ? -1 : http::connect_public(host));
          if (remote.n < 0) {
            send_all(client, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", stop);
            return;
          }
          if (send_all(client, "HTTP/1.1 200 Connection Established\r\n\r\n", stop)) bridge(client, remote.n, stop);
        }); } catch (...) { stop = true; }
      }
    });
  }
  ~State() {
    stop = true;
    if (thread.joinable()) thread.join();
    std::error_code ec; std::filesystem::remove_all(directory, ec);
  }
};
Broker::Broker() : state_(std::make_unique<State>()) {}
Broker::~Broker() = default;
const std::string& Broker::path() const { return state_->socket; }

int exec(const std::string& socket_path, const std::vector<std::string>& argv) {
  if (argv.empty()) return 126;
  Fd listener(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
  sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (listener.n < 0 || ::bind(listener.n, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0 ||
      ::listen(listener.n, 16) < 0) return 126;
  socklen_t length = sizeof(address);
  if (::getsockname(listener.n, reinterpret_cast<sockaddr*>(&address), &length) < 0) return 126;
  const std::string proxy = "http://127.0.0.1:" + std::to_string(ntohs(address.sin_port));
  for (const char* name : {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"})
    ::setenv(name, proxy.c_str(), 1);
  for (const char* name : {"NO_PROXY", "no_proxy"}) ::setenv(name, "", 1);
  ::setenv("NODE_USE_ENV_PROXY", "1", 1);
  std::vector<char*> args;
  for (auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
  args.push_back(nullptr);
  // Fork before starting threads. The child only execs; provider credentials remain in its env.
  const pid_t pid = ::fork();
  if (pid < 0) return 126;
  if (pid == 0) { ::execvp(args[0], args.data()); _exit(127); }
  std::atomic<bool> stop{false};
  std::thread relay([&] {
    Workers workers;
    while (!stop) {
      pollfd p{listener.n, POLLIN, 0};
      if (::poll(&p, 1, 100) <= 0 || !(p.revents & POLLIN)) continue;
      const int fd = ::accept4(listener.n, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
      if (fd < 0) continue;
      try { workers.start(fd, [&](int client) {
        Fd broker(unix_connect(socket_path));
        if (broker.n >= 0) bridge(client, broker.n, stop);
      }); } catch (...) { stop = true; }
    }
  });
  int status = 0;
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
  stop = true; relay.join();
  return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
}  // namespace saga::proxy

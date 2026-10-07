#include "memwal/gate.h"
#include "core/compat.h"
#include "memwal/redact.h"

#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <vector>

namespace saga::memwal {
namespace fs = std::filesystem;

namespace {

constexpr size_t kMaxLine = 65536;
constexpr size_t kMaxReply = 8 * 1024 * 1024;

std::string read_line(int fd, size_t max_bytes = kMaxLine, int timeout_ms = 120000) {
  std::string s;
  char buf[2048];
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (s.size() < max_bytes) {
    pollfd p{fd, POLLIN, 0};
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
    if (remaining <= 0 || poll(&p, 1, static_cast<int>(remaining)) <= 0) break;
    const ssize_t n = ::read(fd, buf, sizeof buf);
    if (n <= 0) break;
    s.append(buf, static_cast<size_t>(n));
    if (s.find('\n') != std::string::npos) break;
  }
  const auto nl = s.find('\n');
  return nl == std::string::npos || nl > max_bytes ? std::string{} : s.substr(0, nl);
}

bool content_namespace(const std::string& uid, const std::string& ns) {
  const std::string prefix = "u:" + uid + ":";
  if (!ns.starts_with(prefix)) return false;
  const std::string suffix = ns.substr(prefix.size());
  return suffix == "facts" || suffix == "episodes" || suffix == "chat" || suffix == "checkpoints" ||
         suffix == "skills" || (suffix.starts_with("lessons:") && suffix.size() > 8);
}

bool write_all(int fd, const std::string& s) {
  size_t off = 0;
  while (off < s.size()) {
    const ssize_t n = ::send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
    if (n <= 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

}  // namespace

json gate_request(Client& client, const json& req, Store* store) {
  const std::string op = req.value("op", "");
  const std::string ns = req.value("ns", "");
  if (ns.empty() || ns.size() > 200) return {{"ok", false}, {"error", "namespace required"}};
  if (op == "remember") {
    if (ns.starts_with("harness:")) return {{"ok", false}, {"error", "harness:* namespaces are written by the harness only"}};
    const std::string text = req.value("text", "");
    if (text.empty() || text.size() > 32000) return {{"ok", false}, {"error", "text required"}};
    if (store && store->enabled() && !req.value("wait", true)) {
      // Same refusal as the client's, answered now rather than from the worker's log.
      if (const StorageText safe = prepare_for_storage(text); !safe.ok)
        return {{"ok", false}, {"error", safe.error.empty() ? "memory record refused" : safe.error}};
      store->put(ns, "memory", text);
      return {{"ok", true}, {"status", "queued"}, {"ns", ns}};
    }
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
    const std::string reply = read_line(fd, kMaxReply);
    if (!reply.empty()) {
      auto j = json::parse(reply, nullptr, false);
      if (j.is_object()) out = std::move(j);
    }
  }
  ::close(fd);
  return out;
}

Gate::Gate(Client& client, Store* store, std::string recall_uid, Observer observer)
    : client_(client), store_(store), recall_uid_(std::move(recall_uid)), observer_(std::move(observer)) {
  // The socket inode keeps the mode it was created with. fchmod on the fd does not change the
  // pathname another user would connect to, and umask is process-global, so the directory is 0700
  // and the bind itself happens under a temporary 077 umask that is restored before anything else.
  std::string tmpl = (fs::temp_directory_path() / "saga-mem-XXXXXX").string();
  std::vector<char> buf(tmpl.begin(), tmpl.end());
  buf.push_back('\0');
  if (::mkdtemp(buf.data()) == nullptr) throw std::runtime_error("cannot create memory socket directory");
  dir_ = buf.data();
  auto fail = [&](const std::string& why) {
    if (listen_fd_ >= 0) ::close(listen_fd_);
    listen_fd_ = -1;
    if (!path_.empty()) ::unlink(path_.c_str());
    ::rmdir(dir_.c_str());
    dir_.clear();
    path_.clear();
    throw std::runtime_error(why);
  };
  if (::chmod(dir_.c_str(), 0700) != 0) fail("cannot protect memory socket directory");
  path_ = dir_ + "/sock";
  if (path_.size() >= sizeof(sockaddr_un::sun_path)) fail("memory socket path too long");
  listen_fd_ = compat::socket_cloexec(AF_UNIX, SOCK_STREAM);
  if (listen_fd_ < 0) fail("memory socket");
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, path_.c_str(), path_.size() + 1);
  int bound = -1;
  {
    const mode_t prev = ::umask(077);
    bound = ::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr);
    ::umask(prev);
  }
  if (bound != 0 || ::chmod(path_.c_str(), 0600) != 0 || ::fchmod(listen_fd_, 0600) != 0 ||
      ::listen(listen_fd_, 16) != 0)
    fail("cannot bind memory socket " + path_);
  thread_ = std::thread([this] { serve(); });
}

Gate::~Gate() {
  stop_ = true;
  if (thread_.joinable()) thread_.join();
  {
    std::unique_lock lk(mu_);
    for (int fd : clients_) ::shutdown(fd, SHUT_RDWR);
    idle_.wait(lk, [&] { return active_ == 0; });
  }
  if (listen_fd_ >= 0) ::close(listen_fd_);
  if (!path_.empty()) ::unlink(path_.c_str());
  if (!dir_.empty()) ::rmdir(dir_.c_str());
}

void Gate::serve() {
  while (!stop_) {
    pollfd p{listen_fd_, POLLIN, 0};
    if (::poll(&p, 1, 200) <= 0) continue;
    const int fd = compat::accept_cloexec(listen_fd_);
    if (fd < 0) continue;
    // Each request on its own thread: a remember waits for Walrus to confirm the blob, and agents
    // working in parallel shouldn't queue their recalls behind it.
    {
      std::lock_guard lk(mu_);
      if (active_ >= (recall_uid_.empty() ? kMaxActive : 4)) {
        write_all(fd, json({{"ok", false}, {"error", "memory socket is busy, try again"}}).dump() + "\n");
        ::close(fd);
        continue;
      }
      ++active_;
      clients_.insert(fd);
    }
    std::thread([this, fd] {
      handle(fd);
      std::lock_guard lk(mu_);
      clients_.erase(fd);
      ::close(fd);
      if (--active_ == 0) idle_.notify_all();
    }).detach();
  }
}

void Gate::handle(int fd) {
  if (!recall_uid_.empty()) {
    const timeval timeout{2, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
  }
#ifdef __linux__
  ucred cred{};
  socklen_t cred_len = sizeof cred;
  const bool same_user = ::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == 0 && cred.uid == ::getuid();
#else
  uid_t peer_uid = 0;
  gid_t peer_gid = 0;
  const bool same_user = ::getpeereid(fd, &peer_uid, &peer_gid) == 0 && peer_uid == ::getuid();
#endif
  if (!same_user) {
    write_all(fd, json({{"ok", false}, {"error", "memory socket is for this user only"}}).dump() + "\n");
    return;
  }
  const std::string line = read_line(fd, kMaxLine, recall_uid_.empty() ? 120000 : 2000);
  auto req = json_nesting(line) > kMaxJsonDepth ? json() : json::parse(line, nullptr, false);
  json res = req.is_object() ? json() : json{{"ok", false}, {"error", "bad request"}};
  bool attempted = false;
  if (req.is_object()) {
    try {
      bool allowed = !stop_;
      if (!recall_uid_.empty()) {
        if (req.value("op", "") != "recall" || !content_namespace(recall_uid_, req.value("ns", ""))) {
          allowed = false;
          res = {{"ok", false}, {"error", "this run can only recall the current user's content namespaces"}};
        } else {
          std::lock_guard lk(mu_);
          if (recalls_ >= 8) {
            allowed = false;
            res = {{"ok", false}, {"error", "this run's memory recall limit has been reached"}};
          } else ++recalls_;
        }
      }
      if (allowed) {
        attempted = true;
        res = gate_request(client_, req, store_);
      } else if (res.is_null()) res = {{"ok", false}, {"error", "memory run ended"}};
    } catch (const std::exception& e) {
      res = {{"ok", false}, {"error", e.what()}};
    }
  }
  std::string reply = res.dump();
  if (reply.size() >= kMaxReply) {
    res = {{"ok", false}, {"error", "memory response exceeds its size limit; use a smaller recall limit"}};
    reply = res.dump();
  }
  if (attempted && observer_) {
    try { observer_(req, res); }
    catch (const std::exception&) {
      reply = json{{"ok", false}, {"error", "could not record the memory recall source"}}.dump();
    }
  }
  write_all(fd, reply + "\n");
}

}  // namespace saga::memwal

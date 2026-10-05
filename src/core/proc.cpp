#include "core/proc.h"
#include "core/secrets.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <chrono>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string_view>

namespace saga::proc {
Options::~Options() {
  secrets::clear(stdin_data);
  for (auto& [_, value] : env) secrets::clear(value);
}
namespace {

// Server credentials. Agents run untrusted instructions, so a child must not inherit these even
// when the caller puts them in Options::env. `saga mem` reaches memory through the local socket.
bool server_secret(std::string_view key) {
  return key == "MEMWAL_PRIVATE_KEY" || key == "SAGA_SESSION_SECRET" || key == "SAGA_ACCESS_CODE" ||
         key == "SAGA_GITHUB_CLIENT_SECRET" || key == "BOUNDLESS_API_KEY";
}

}  // namespace

bool on_path(const std::string& exe) {
  if (exe.find('/') != std::string::npos) return access(exe.c_str(), X_OK) == 0;
  const char* path = std::getenv("PATH");
  std::stringstream ss(path ? path : "");
  for (std::string dir; std::getline(ss, dir, ':');)
    if (!dir.empty() && access((dir + "/" + exe).c_str(), X_OK) == 0) return true;
  return false;
}

Result run(const std::vector<std::string>& argv, const Options& opt) {
  // A child that exits without reading its stdin must cost us EPIPE, not the whole server.
  static const bool sigpipe_ignored = (signal(SIGPIPE, SIG_IGN), true);
  (void)sigpipe_ignored;
  Result res;
  if ((opt.cancel && opt.cancel->load()) || (opt.session_cancel && opt.session_cancel->load())) {
    res.cancelled = true;
    return res;
  }
  if (argv.empty()) return res;
  int out_p[2]{-1,-1}, err_p[2]{-1,-1}, in_p[2]{-1,-1}, start_p[2]{-1,-1};
  if (pipe2(out_p, O_CLOEXEC) || pipe2(err_p, O_CLOEXEC) || pipe2(in_p, O_CLOEXEC) || pipe2(start_p, O_CLOEXEC)) {
    res.err = std::strerror(errno);
    for (int fd : {out_p[0], out_p[1], err_p[0], err_p[1], in_p[0], in_p[1], start_p[0], start_p[1]})
      if (fd >= 0) close(fd);
    return res;
  }

  // Build argv/envp before fork: only async-signal-safe calls in the child.
  std::vector<char*> args;
  for (auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
  args.push_back(nullptr);
  std::vector<std::string> env_store;
  for (char** e = environ; opt.inherit_env && *e; ++e) {
    std::string kv(*e);
    const auto eq = kv.find('=');
    const std::string key = kv.substr(0, eq);
    if (server_secret(key) || opt.env.contains(key)) continue;
    env_store.push_back(std::move(kv));
  }
  for (auto& [k, v] : opt.env) {
    if (!server_secret(k)) env_store.push_back(k + "=" + v);
  }
  std::vector<char*> envp;
  for (auto& s : env_store) envp.push_back(s.data());
  envp.push_back(nullptr);

  const pid_t pid = fork();
  if (pid == 0) {
    setpgid(0, 0);  // own process group so we can kill the whole tree
    close(start_p[1]);
    char ready = 0;
    ssize_t n;
    do { n = read(start_p[0], &ready, 1); } while (n < 0 && errno == EINTR);
    if (n != 1 || ready != 1) _exit(126);
    close(start_p[0]);
    dup2(in_p[0], 0);
    dup2(out_p[1], 1);
    dup2(opt.merge_stderr ? out_p[1] : err_p[1], 2);
    if (!opt.cwd.empty() && chdir(opt.cwd.c_str()) != 0) _exit(126);
    // Concurrent web requests may have private files/sockets open without CLOEXEC. Only stdio (and
    // the one descriptor the caller passes) belongs to this child; do not let those descriptors bypass
    // filesystem/network isolation.
    if (opt.pass_fd >= 0) {
      if (opt.pass_fd == 3 ? ::fcntl(3, F_SETFD, 0) < 0 : ::dup2(opt.pass_fd, 3) < 0) _exit(126);
    }
    if (::syscall(SYS_close_range, opt.pass_fd >= 0 ? 4u : 3u, ~0u, 0u) < 0) _exit(126);
    execvpe(args[0], args.data(), envp.data());
    _exit(127);
  }
  close(in_p[0]);
  close(out_p[1]);
  close(err_p[1]);
  close(start_p[0]);
  if (pid < 0) {
    res.err = std::strerror(errno);
    close(in_p[1]);
    close(out_p[0]);
    close(err_p[0]);
    close(start_p[1]);
    return res;
  }
  ::setpgid(pid, pid);  // establish cancellation's target even before the child gets scheduled
  bool ready = true;
  if (!opt.cgroup_procs.empty()) {
    const int fd = ::open(opt.cgroup_procs.c_str(), O_WRONLY | O_CLOEXEC);
    const std::string value = std::to_string(pid) + "\n";
    ready = fd >= 0 && ::write(fd, value.data(), value.size()) == static_cast<ssize_t>(value.size());
    if (fd >= 0) ::close(fd);
    if (!ready) res.err = "cannot apply agent resource limits";
  }
  const char start = ready ? 1 : 0;
  [[maybe_unused]] const ssize_t started = write(start_p[1], &start, 1);
  close(start_p[1]);
  // stdin is fed from the same loop as the output, non-blocking, so a child that never reads its
  // prompt still hits the deadline and cancel instead of stalling us in write().
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(opt.timeout_s);
  size_t in_off = 0;
  int in_fd = in_p[1];
  if (opt.stdin_data.empty()) {
    close(in_fd);
    in_fd = -1;
  } else {
    fcntl(in_fd, F_SETFL, fcntl(in_fd, F_GETFL) | O_NONBLOCK);
  }
  std::string line_buf;
  pollfd fds[3] = {{out_p[0], POLLIN, 0}, {err_p[0], POLLIN, 0}, {in_fd, POLLOUT, 0}};
  int open_fds = 2;
  char buf[8192];
  int status = 0;
  bool reaped = false;
  size_t output_bytes = 0;
  while (open_fds > 0 || !reaped) {
    if (!reaped) {
      const pid_t done = waitpid(pid, &status, WNOHANG);
      if (done == pid || (done < 0 && errno == ECHILD)) reaped = true;
    }
    if (reaped && open_fds == 0) break;
    if (std::chrono::steady_clock::now() > deadline) res.timed_out = true;
    if (opt.cancel && opt.cancel->load()) res.cancelled = true;
    if (opt.session_cancel && opt.session_cancel->load()) res.cancelled = true;
    if (res.timed_out || res.cancelled || res.output_limited) {
      kill(-pid, SIGTERM);
      usleep(300'000);
      kill(-pid, SIGKILL);
      break;
    }
    if (poll(fds, 3, 250) <= 0) continue;
    if (fds[2].fd >= 0 && (fds[2].revents & (POLLOUT | POLLERR | POLLHUP))) {
      const ssize_t n = write(fds[2].fd, opt.stdin_data.data() + in_off, opt.stdin_data.size() - in_off);
      if (n > 0) in_off += static_cast<size_t>(n);
      if ((n < 0 && errno != EAGAIN && errno != EINTR) || in_off >= opt.stdin_data.size()) {
        close(fds[2].fd);  // done, or the child closed its end (EPIPE)
        fds[2].fd = -1;
      }
    }
    for (int i = 0; i < 2; ++i) {
      if (fds[i].fd < 0 || !(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
      ssize_t n = read(fds[i].fd, buf, sizeof buf);
      if (n <= 0) {
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        close(fds[i].fd);
        fds[i].fd = -1;
        --open_fds;
        continue;
      }
      const size_t len = static_cast<size_t>(n);
      if (len > opt.max_output_bytes - std::min(output_bytes, opt.max_output_bytes)) {
        res.output_limited = true;
        break;
      }
      output_bytes += len;
      if (i == 1) {
        res.err.append(buf, static_cast<size_t>(n));
        continue;
      }
      res.out.append(buf, static_cast<size_t>(n));
      if (!opt.on_stdout_line) continue;
      line_buf.append(buf, len);
      for (size_t nl; (nl = line_buf.find('\n')) != std::string::npos;) {
        if (nl > opt.max_line_bytes) { res.output_limited = true; break; }
        std::string line = line_buf.substr(0, nl);
        line_buf.erase(0, nl + 1);
        try { opt.on_stdout_line(line); }
        catch (...) { res.output_limited = true; break; }
      }
      if (line_buf.size() > opt.max_line_bytes) res.output_limited = true;
      if (res.output_limited) break;
    }
  }
  if (!line_buf.empty() && opt.on_stdout_line && !res.output_limited && !res.timed_out && !res.cancelled) {
    try { opt.on_stdout_line(line_buf); }
    catch (...) { res.output_limited = true; kill(-pid, SIGKILL); }
  }
  for (auto& f : fds)
    if (f.fd >= 0) close(f.fd);  // includes stdin if the child exited without reading it all

  if (!reaped) while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
  res.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  return res;
}

}  // namespace saga::proc

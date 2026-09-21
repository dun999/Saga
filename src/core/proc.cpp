#include "core/proc.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace saga::proc {

bool on_path(const std::string& exe) {
  if (exe.find('/') != std::string::npos) return access(exe.c_str(), X_OK) == 0;
  const char* path = std::getenv("PATH");
  std::stringstream ss(path ? path : "");
  for (std::string dir; std::getline(ss, dir, ':');)
    if (!dir.empty() && access((dir + "/" + exe).c_str(), X_OK) == 0) return true;
  return false;
}

Result run(const std::vector<std::string>& argv, const Options& opt) {
  Result res;
  if (argv.empty()) return res;
  int out_p[2], err_p[2], in_p[2];
  if (pipe2(out_p, O_CLOEXEC) || pipe2(err_p, O_CLOEXEC) || pipe2(in_p, O_CLOEXEC)) {
    res.err = std::strerror(errno);
    return res;
  }

  // Build argv/envp before fork: only async-signal-safe calls in the child.
  std::vector<char*> args;
  for (auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
  args.push_back(nullptr);
  std::vector<std::string> env_store;
  for (char** e = environ; *e; ++e) {
    std::string kv(*e);
    if (!opt.env.contains(kv.substr(0, kv.find('=')))) env_store.push_back(std::move(kv));
  }
  for (auto& [k, v] : opt.env) env_store.push_back(k + "=" + v);
  std::vector<char*> envp;
  for (auto& s : env_store) envp.push_back(s.data());
  envp.push_back(nullptr);

  const pid_t pid = fork();
  if (pid == 0) {
    setpgid(0, 0);  // own process group so we can kill the whole tree
    dup2(in_p[0], 0);
    dup2(out_p[1], 1);
    dup2(opt.merge_stderr ? out_p[1] : err_p[1], 2);
    if (!opt.cwd.empty() && chdir(opt.cwd.c_str()) != 0) _exit(126);
    execvpe(args[0], args.data(), envp.data());
    _exit(127);
  }
  close(in_p[0]);
  close(out_p[1]);
  close(err_p[1]);
  if (pid < 0) {
    res.err = std::strerror(errno);
    close(in_p[1]);
    close(out_p[0]);
    close(err_p[0]);
    return res;
  }
  if (!opt.stdin_data.empty()) {
    size_t off = 0;
    while (off < opt.stdin_data.size()) {
      ssize_t n = write(in_p[1], opt.stdin_data.data() + off, opt.stdin_data.size() - off);
      if (n <= 0) break;
      off += static_cast<size_t>(n);
    }
  }
  close(in_p[1]);

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(opt.timeout_s);
  std::string line_buf;
  pollfd fds[2] = {{out_p[0], POLLIN, 0}, {err_p[0], POLLIN, 0}};
  int open_fds = 2;
  char buf[8192];
  while (open_fds > 0) {
    if (std::chrono::steady_clock::now() > deadline) res.timed_out = true;
    if (opt.cancel && opt.cancel->load()) res.cancelled = true;
    if (res.timed_out || res.cancelled) {
      kill(-pid, SIGTERM);
      usleep(300'000);
      kill(-pid, SIGKILL);
      break;
    }
    if (poll(fds, 2, 250) <= 0) continue;
    for (int i = 0; i < 2; ++i) {
      if (fds[i].fd < 0 || !(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
      ssize_t n = read(fds[i].fd, buf, sizeof buf);
      if (n <= 0) {
        close(fds[i].fd);
        fds[i].fd = -1;
        --open_fds;
        continue;
      }
      if (i == 1) {
        res.err.append(buf, static_cast<size_t>(n));
        continue;
      }
      res.out.append(buf, static_cast<size_t>(n));
      line_buf.append(buf, static_cast<size_t>(n));
      for (size_t nl; (nl = line_buf.find('\n')) != std::string::npos;) {
        std::string line = line_buf.substr(0, nl);
        line_buf.erase(0, nl + 1);
        if (opt.on_stdout_line) opt.on_stdout_line(line);
      }
    }
  }
  if (!line_buf.empty() && opt.on_stdout_line) opt.on_stdout_line(line_buf);
  for (auto& f : fds)
    if (f.fd >= 0) close(f.fd);

  int status = 0;
  waitpid(pid, &status, 0);
  res.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  return res;
}

}  // namespace saga::proc

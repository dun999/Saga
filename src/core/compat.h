#pragma once
// The few Linux calls Saga uses, with portable stand-ins so local serving also builds and runs on macOS.
// On Linux each helper is the atomic call it always was. The agent sandbox (bubblewrap, seccomp, cgroup
// v2) stays Linux-only: it is needed for a public, multi-user Saga, not for running one on your machine.
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif

#include <string>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0  // macOS has no per-call flag; main() ignores SIGPIPE for the whole process
#endif

namespace saga::compat {

#ifndef __linux__
inline bool cloexec(int fd, bool nonblock) {
  if (::fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) return false;
  return !nonblock || ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK) == 0;
}
#endif

// socket(2) with close-on-exec, and optionally non-blocking, set.
inline int socket_cloexec(int domain, int type, bool nonblock = false) {
#ifdef __linux__
  return ::socket(domain, type | SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0), 0);
#else
  const int fd = ::socket(domain, type, 0);
  if (fd >= 0 && !cloexec(fd, nonblock)) {
    ::close(fd);
    return -1;
  }
  return fd;
#endif
}

// accept(2) with close-on-exec, and optionally non-blocking, set on the new descriptor.
inline int accept_cloexec(int fd, bool nonblock = false) {
#ifdef __linux__
  return ::accept4(fd, nullptr, nullptr, SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0));
#else
  const int c = ::accept(fd, nullptr, nullptr);
  if (c >= 0 && !cloexec(c, nonblock)) {
    ::close(c);
    return -1;
  }
  return c;
#endif
}

// pipe(2) with close-on-exec on both ends. 0 on success, like pipe2.
inline int pipe_cloexec(int p[2]) {
#ifdef __linux__
  return ::pipe2(p, O_CLOEXEC);
#else
  if (::pipe(p) != 0) return -1;
  if (cloexec(p[0], false) && cloexec(p[1], false)) return 0;
  ::close(p[0]);
  ::close(p[1]);
  return -1;
#endif
}

// Closes every descriptor from `low` up, between fork and exec (async-signal-safe). `max_fd` bounds the
// loop where there is no close_range; compute it before fork.
inline bool close_from(int low, int max_fd) {
#ifdef __linux__
  (void)max_fd;
  return ::syscall(SYS_close_range, static_cast<unsigned>(low), ~0u, 0u) == 0;
#else
  for (int fd = low; fd < max_fd; ++fd) ::close(fd);
  return true;
#endif
}

// Absolute path of the running binary ("" if unknown).
std::string self_exe();

}  // namespace saga::compat

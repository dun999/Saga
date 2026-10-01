#include "core/secrets.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <utility>

namespace saga::secrets {
namespace fs = std::filesystem;
namespace {
constexpr std::string_view kPrefix = "SAGA1:";
constexpr size_t kMaxPrivateFile = 4 * 1024 * 1024;
struct Fd {
  int n = -1;
  explicit Fd(int value = -1) : n(value) {}
  ~Fd() { if (n >= 0) ::close(n); }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  Fd(Fd&& f) noexcept : n(std::exchange(f.n, -1)) {}
  Fd& operator=(Fd&& f) noexcept {
    if (this != &f) { if (n >= 0) ::close(n); n = std::exchange(f.n, -1); }
    return *this;
  }
};
// Pin each directory before opening the next. Renames cannot redirect a later file operation.
struct Parent {
  Fd fd;
  std::string name;
  Parent(const std::string& root, const std::string& rel, bool create = false) {
    const fs::path r(rel);
    if (r.empty() || r.is_absolute()) return;
    for (const auto& part : r)
      if (part == "." || part == ".." || part.empty()) return;
    fd = Fd(::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (fd.n < 0) return;
    for (auto it = r.begin(); it != r.end(); ++it) {
      if (std::next(it) == r.end()) { name = it->string(); return; }
      const std::string part = it->string();
      if (create && ::mkdirat(fd.n, part.c_str(), 0700) < 0 && errno != EEXIST) {
        fd = Fd(); return;
      }
      Fd next(::openat(fd.n, part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
      if (next.n < 0) { fd = Fd(); return; }
      fd = std::move(next);
    }
  }
  explicit operator bool() const { return fd.n >= 0 && !name.empty(); }
};
bool present(const Parent& p, const std::string& name) {
  struct stat st{};
  return ::fstatat(p.fd.n, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0;
}
std::optional<std::string> read_at(const Parent& p, const std::string& name) {
  Fd fd(::openat(p.fd.n, name.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
  struct stat st{};
  if (fd.n < 0 || ::fstat(fd.n, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
      st.st_size < 0 || static_cast<uint64_t>(st.st_size) > kMaxPrivateFile) return std::nullopt;
  std::string data;
  std::array<char, 8192> buf{};
  for (;;) {
    const ssize_t n = ::read(fd.n, buf.data(), buf.size());
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) return std::nullopt;
    if (n == 0) return data;
    if (static_cast<size_t>(n) > kMaxPrivateFile - data.size()) return std::nullopt;
    data.append(buf.data(), static_cast<size_t>(n));
  }
}
void write_at(const Parent& p, const std::string& name, const std::string& data) {
  if (!p || data.size() > kMaxPrivateFile) throw std::runtime_error("private file refused");
  const std::string tmp = name + ".tmp-" + crypto::random_hex(8);
  Fd fd(::openat(p.fd.n, tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (fd.n < 0) throw std::runtime_error("cannot create private file");
  try {
    size_t off = 0;
    while (off < data.size()) {
      const ssize_t n = ::write(fd.n, data.data() + off, data.size() - off);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) throw std::runtime_error("cannot write private file");
      off += static_cast<size_t>(n);
    }
    if (::fsync(fd.n) != 0 || ::renameat(p.fd.n, tmp.c_str(), p.fd.n, name.c_str()) != 0)
      throw std::runtime_error("cannot replace private file");
  } catch (...) { ::unlinkat(p.fd.n, tmp.c_str(), 0); throw; }
}
void shred_at(const Parent& p, const std::string& name) {
  Fd fd(::openat(p.fd.n, name.c_str(), O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
  struct stat st{};
  // Removing a hard link is safe; overwriting its shared inode is not.
  if (fd.n >= 0 && ::fstat(fd.n, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1) {
    std::array<char, 8192> zeros{};
    size_t left = static_cast<size_t>(std::min<off_t>(std::max<off_t>(st.st_size, 0), kMaxPrivateFile));
    while (left) {
      const ssize_t n = ::write(fd.n, zeros.data(), std::min(left, zeros.size()));
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) break;
      left -= static_cast<size_t>(n);
    }
    ::ftruncate(fd.n, 0);
  }
  ::unlinkat(p.fd.n, name.c_str(), 0);
}
}  // namespace
std::string key_id(const Key& k) { return crypto::sha256_hex(std::string(k.begin(), k.end())).substr(0, 16); }
bool is_sealed(const std::string& text) { return text.starts_with(kPrefix); }
std::string seal(const Key& k, const std::string& plaintext) {
  return std::string(kPrefix) + crypto::b64_encode(crypto::secretbox_seal(k, plaintext));
}
std::string open(const Key& k, const std::string& sealed) {
  if (!is_sealed(sealed)) throw std::runtime_error("not sealed");
  return crypto::secretbox_open(k, crypto::b64_decode(std::string_view(sealed).substr(kPrefix.size())));
}
std::optional<std::string> read_private_file(const std::string& root, const std::string& rel) {
  const Parent p(root, rel);
  return p ? read_at(p, p.name) : std::nullopt;
}
void write_private_file(const std::string& root, const std::string& rel, const std::string& data) {
  const Parent p(root, rel, true);
  write_at(p, p.name, data);
}
void seal_file(const Key& k, const std::string& root, const std::string& rel) {
  const Parent p(root, rel);
  if (!p || !present(p, p.name)) return;
  if (auto plain = read_at(p, p.name)) write_at(p, p.name + ".sealed", seal(k, *plain));
  shred_at(p, p.name);
}
void unseal_file(const Key& k, const std::string& root, const std::string& rel) {
  const Parent p(root, rel);
  if (!p) return;
  const auto text = read_at(p, p.name + ".sealed");
  if (!text) return;
  write_at(p, p.name, open(k, *text));
  ::unlinkat(p.fd.n, (p.name + ".sealed").c_str(), 0);
}
bool erase_file(const std::string& root, const std::string& rel) {
  const Parent p(root, rel);
  if (!p) return false;
  bool any = false;
  for (const auto& name : {p.name, p.name + ".sealed"})
    if (present(p, name)) { shred_at(p, name); any = true; }
  return any;
}
}  // namespace saga::secrets

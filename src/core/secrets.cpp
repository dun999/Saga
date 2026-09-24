#include "core/secrets.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <optional>
#include <stdexcept>

namespace saga::secrets {
namespace fs = std::filesystem;
namespace {

constexpr std::string_view kPrefix = "SAGA1:";

// Agents own everything in their home and can plant symlinks there, so a secret file is only ever
// touched through real directories below `root` and never followed if it is itself a link.
// Returns the path, or empty when any component on the way is a symlink or not a directory.
fs::path confined(const std::string& root, const std::string& rel) {
  const fs::path r(rel);
  if (r.is_absolute()) return {};
  fs::path p(root);
  std::error_code ec;
  for (auto it = r.begin(); it != r.end(); ++it) {
    if (*it == ".." || *it == ".") return {};
    p /= *it;
    if (std::next(it) == r.end()) break;
    const auto st = fs::symlink_status(p, ec);
    if (ec || !fs::is_directory(st)) return {};  // missing, a file, or a link: nothing to do here
  }
  return p;
}

// Read a regular file without following a symlink at the last component.
std::optional<std::string> slurp(const fs::path& p) {
  const int fd = ::open(p.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return std::nullopt;
  struct stat st{};
  std::optional<std::string> out;
  if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
    std::string data;
    char buf[8192];
    ssize_t n;
    while ((n = ::read(fd, buf, sizeof buf)) > 0) data.append(buf, static_cast<size_t>(n));
    if (n == 0) out = std::move(data);
  }
  ::close(fd);
  return out;
}

// Write with 0600 from the first byte into a fresh file (never through a planted link), then
// atomically replace; rename swaps out a link at `p` rather than writing through it.
void write_private(const fs::path& p, const std::string& data) {
  const fs::path tmp = p.string() + ".tmp";
  std::error_code ec;
  fs::remove(tmp, ec);
  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) throw std::runtime_error("cannot create " + tmp.string());
  size_t off = 0;
  while (off < data.size()) {
    const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
    if (n <= 0) {
      ::close(fd);
      fs::remove(tmp, ec);
      throw std::runtime_error("cannot write " + tmp.string());
    }
    off += static_cast<size_t>(n);
  }
  ::close(fd);
  fs::rename(tmp, p);
}

// Overwrite before unlinking, so a plaintext secret doesn't linger in freed blocks. A symlink is
// only unlinked: its target is not ours to zero.
void shred(const fs::path& p) {
  std::error_code ec;
  const int fd = ::open(p.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd >= 0) {
    struct stat st{};
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
      const std::string zeros(static_cast<size_t>(st.st_size), '\0');
      [[maybe_unused]] auto n = ::write(fd, zeros.data(), zeros.size());
    }
    ::close(fd);
  }
  fs::remove(p, ec);
}

bool present(const fs::path& p) {
  std::error_code ec;
  return fs::exists(fs::symlink_status(p, ec));
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

void seal_file(const Key& k, const std::string& root, const std::string& rel) {
  const fs::path p = confined(root, rel);
  if (p.empty() || !present(p)) return;
  const auto plain = slurp(p);
  if (plain) write_private(p.string() + ".sealed", seal(k, *plain));
  shred(p);  // a link or other non-file is removed unread
}

void unseal_file(const Key& k, const std::string& root, const std::string& rel) {
  const fs::path p = confined(root, rel);
  if (p.empty()) return;
  const fs::path sealed = p.string() + ".sealed";
  const auto text = slurp(sealed);
  if (!text) return;
  write_private(p, open(k, *text));
  std::error_code ec;
  fs::remove(sealed, ec);
}

bool erase_file(const std::string& root, const std::string& rel) {
  const fs::path p = confined(root, rel);
  if (p.empty()) return false;
  bool any = false;
  for (const fs::path& f : {p, fs::path(p.string() + ".sealed")}) {
    if (present(f)) {
      shred(f);
      any = true;
    }
  }
  return any;
}

}  // namespace saga::secrets

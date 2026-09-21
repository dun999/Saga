#include "core/secrets.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace saga::secrets {
namespace fs = std::filesystem;
namespace {

constexpr std::string_view kPrefix = "SAGA1:";

std::string slurp(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// Write with 0600 from the first byte, then atomically replace.
void write_private(const fs::path& p, const std::string& data) {
  fs::create_directories(p.parent_path());
  const fs::path tmp = p.string() + ".tmp";
  { std::ofstream(tmp, std::ios::binary | std::ios::trunc); }
  fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
  { std::ofstream(tmp, std::ios::binary | std::ios::trunc) << data; }
  fs::rename(tmp, p);
}

// Overwrite before unlinking, so a plaintext secret doesn't linger in freed blocks.
void shred(const fs::path& p) {
  std::error_code ec;
  const auto n = fs::file_size(p, ec);
  if (!ec && n > 0) {
    std::ofstream out(p, std::ios::binary | std::ios::in | std::ios::out);
    const std::string zeros(n, '\0');
    out.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
  }
  fs::remove(p, ec);
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

void seal_file(const Key& k, const std::string& path) {
  std::error_code ec;
  if (!fs::exists(path, ec)) return;
  write_private(path + ".sealed", seal(k, slurp(path)));
  shred(path);
}

void unseal_file(const Key& k, const std::string& path) {
  std::error_code ec;
  const std::string sealed = path + ".sealed";
  if (!fs::exists(sealed, ec)) return;
  write_private(path, open(k, slurp(sealed)));
  fs::remove(sealed, ec);
}

bool erase_file(const std::string& path) {
  std::error_code ec;
  bool any = false;
  for (const auto& p : {path, path + ".sealed"}) {
    if (fs::exists(p, ec)) {
      shred(p);
      any = true;
    }
  }
  return any;
}

}  // namespace saga::secrets

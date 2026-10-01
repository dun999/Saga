#pragma once
#include <optional>
// Encryption at rest for everything that can act as a user: provider tokens, API keys and the
// CLI login files in each user's agent home.
//
// A wallet signature derives a 32-byte vault key held in a short server session. Provider keys
// are derived from it for storage. Plaintext CLI logins exist only in private temporary storage.
#include <string>
#include <utility>

#include "core/crypto.h"

namespace saga::secrets {

struct Key : crypto::Bytes {
  Key() = default;
  explicit Key(size_t size) : crypto::Bytes(size) {}
  Key(size_t size, uint8_t value) : crypto::Bytes(size, value) {}
  Key(const crypto::Bytes& value) : crypto::Bytes(value) {}
  Key(crypto::Bytes&& value) noexcept : crypto::Bytes(std::move(value)) {}
  Key(const Key&) = default;
  Key(Key&& value) noexcept : crypto::Bytes(std::move(value)) {}
  Key& operator=(const Key& value);
  Key& operator=(Key&& value) noexcept;
  ~Key();  // zero the buffer even on exceptions and temporary copies
};
void clear(Key& key);  // overwrite the live buffer before release
void clear(crypto::Bytes& bytes);
void clear(std::string& text);
struct WipeString {
  std::string& text;
  ~WipeString() { clear(text); }
};
Key derive_key(const Key& vault, const std::string& uid, const std::string& provider);

// Short, non-secret fingerprint of a key (to tell "this is a different key" from "no key").
std::string key_id(const Key& k);

std::string seal(const Key& k, const std::string& plaintext);
std::string open(const Key& k, const std::string& sealed);  // throws on a wrong key or tampering
bool is_sealed(const std::string& text);

// Seal/unseal a file in place: `root/rel` ⇄ `root/rel.sealed`. Plaintext is shredded after sealing.
// `root` is trusted; nothing under it is: a symlink anywhere in `rel` is never followed.
void seal_file(const Key& k, const std::string& root, const std::string& rel);
void unseal_file(const Key& k, const std::string& root, const std::string& rel);
// Remove a secret file in either form. True if anything was deleted.
bool erase_file(const std::string& root, const std::string& rel);

// Descriptor-relative access in an agent-owned home. No directory or file symlinks are followed.
// Writes create missing real directories with 0700 and replace the file atomically with 0600.
std::optional<std::string> read_private_file(const std::string& root, const std::string& rel);
void write_private_file(const std::string& root, const std::string& rel, const std::string& data);

}  // namespace saga::secrets

#pragma once
// Encryption at rest for everything that can act as a user: provider tokens, API keys and the
// CLI login files in each user's agent home.
//
// The key is the user's *vault key*: 32 bytes their browser derives from a wallet signature over a
// fixed message and sends with each request (cookie `saga_vault`). The server never writes it
// down, so what sits on disk — "SAGA1:" + base64(nonce || XSalsa20-Poly1305 ciphertext) — cannot be
// opened without the user present.
#include <string>

#include "core/crypto.h"

namespace saga::secrets {

using Key = crypto::Bytes;  // 32 bytes

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

}  // namespace saga::secrets

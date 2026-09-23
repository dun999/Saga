#pragma once
// Secrets never go to Walrus. Memory is recalled into every later turn (and a handle-based identity
// can be claimed by anyone who types it), so a key someone pastes into chat would otherwise live in
// a blob forever and be handed back to whoever asks. Every write passes through redact_secrets()
// in the MemWal client, before the text leaves this process — the relayer never sees it either.
#include <string>

namespace saga::memwal {

inline constexpr const char* kRedacted = "[redacted secret]";

// Replaces credentials (API keys, tokens, private keys, passwords, seed phrases) with kRedacted.
// `found`, if given, receives how many were replaced.
std::string redact_secrets(const std::string& text, int* found = nullptr);

inline bool has_secret(const std::string& text) {
  int n = 0;
  redact_secrets(text, &n);
  return n > 0;
}

}  // namespace saga::memwal

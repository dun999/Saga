#pragma once
// Secrets never go to Walrus. Memory is recalled into every later turn (and a handle-based identity
// can be claimed by anyone who types it), so a key someone pastes into chat would otherwise live in
// a blob forever and be handed back to whoever asks. Every write passes through prepare_for_storage()
// in the MemWal client, before the text leaves this process — the relayer never sees it either.
//
// Scanning is iterative and linear. The previous std::regex rules recursed on the C++ library's
// matcher and could overflow the stack on a long input (GCC 15; the compiler this project's CI uses).
//
// Raw 32-byte values are ambiguous: a private seed, a hash, and a Sui address share one encoding, and
// entropy does not tell them apart. Unlabelled standalone 64-hex strings (with or without 0x) are
// removed from free text. Fields the application itself typed as public identifiers — uid, address,
// owner, wallet, blob_id, job_id, sha256 — are kept. That drops wallet addresses mentioned in prose.
#include <string>
#include <string_view>

namespace saga::memwal {

inline constexpr const char* kRedacted = "[redacted secret]";
inline constexpr const char* kNotStored = "[not stored]";
inline constexpr size_t kMaxStoredBytes = 256 * 1024;
inline constexpr int kMaxJsonDepth = 32;

// Greatest brace/bracket depth, ignoring brackets inside JSON strings.
// Stops and returns limit+1 once `limit` is exceeded (limit <= 0 scans the whole text).
int json_nesting(std::string_view text, int limit = kMaxJsonDepth);

struct StorageText {
  bool ok = true;
  std::string text;
  std::string error;
  int found = 0;
};

// Redacts secrets, or refuses. On refusal `ok` is false and `text` is kNotStored — never the input.
// A record that is too large or too deeply nested is refused rather than truncated: cutting a value
// in half can leave one side of a secret intact.
StorageText prepare_for_storage(const std::string& text);

// Replaces credentials with kRedacted. `found`, if given, receives how many were replaced.
// An input prepare_for_storage refuses yields kNotStored and found=1.
std::string redact_secrets(const std::string& text, int* found = nullptr);

inline bool has_secret(const std::string& text) {
  const StorageText r = prepare_for_storage(text);
  return !r.ok || r.found > 0;
}

}  // namespace saga::memwal

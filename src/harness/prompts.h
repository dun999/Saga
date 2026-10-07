#pragma once
#include <string_view>

namespace saga::harness {
// Fixed foundation, embedded from PROMPT.md. Feedback is shared knowledge, not a prompt mutation.
inline constexpr int kFoundationRevision = 5;
extern const std::string_view kSeedPrompt;
}  // namespace saga::harness

#pragma once
// "@mention" routing: split a message into per-agent instructions, Claude-Tag style.
//   "build the landing page, then @codex build the API and @grok review both"
//   → [primary: "build the landing page"], [codex: "build the API"], [grok: "review both"]
#include <string>
#include <vector>

namespace saga::router {

struct Segment {
  std::string agent;        // empty => primary agent
  std::string instruction;
};

// `known` = registered agent handles (lower-case). Unknown @words are left as text.
std::vector<Segment> split_mentions(const std::string& text, const std::vector<std::string>& known);

// Handoffs an agent requested in its output: lines of the form "@name <instruction>".
std::vector<Segment> find_handoffs(const std::string& output, const std::vector<std::string>& known);

}  // namespace saga::router

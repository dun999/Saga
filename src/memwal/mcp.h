#pragma once
// `saga mcp`: the user's Walrus memory as native agent tools, over MCP's stdio transport. Claude Code
// starts it for each run (see ClaudeCodeAgent::argv). Calls go through the memory socket like
// `saga mem`, so the delegate key stays in the Saga process.
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

namespace saga::memwal {

// One JSON-RPC line in, the reply to write out; nullopt for a notification or a line that isn't a request.
std::optional<nlohmann::json> mcp_reply(const std::string& line, const std::string& uid, const std::string& sock,
                                     bool read_only = false);

}  // namespace saga::memwal

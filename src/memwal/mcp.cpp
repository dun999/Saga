#include "memwal/mcp.h"

#include <cstdio>

#include "memwal/gate.h"
#include "memwal/redact.h"
#include "core/env.h"

namespace saga::memwal {
namespace {

json tool_list(const std::string& uid, bool read_only) {
  const std::string facts = shared_namespace(uid);
  const std::string spaces = facts + " (shared facts, decisions, corrections and handoffs, the default), " +
      user_namespace(uid, "chat") + " (saved transcripts; check truncation flags), " +
      user_namespace(uid, "checkpoints") + " (partial file snapshots). Legacy knowledge is included automatically";
  json tools = json::array({
      {{"name", "memory_recall"},
       {"description", "Semantic search over this user's Saga memory, stored as encrypted blobs on Walrus mainnet. "
                       "Use it when the user refers to something from before that your context does not cover. "
                       "Namespaces: " + spaces + "."},
       {"inputSchema", {{"type", "object"},
                        {"properties", {{"query", {{"type", "string"}, {"description", "what to look for"}}},
                                        {"namespace", {{"type", "string"}, {"description", "default " + facts}}},
                                        {"limit", {{"type", "integer"}, {"minimum", 1}, {"maximum", 20}}}}},
                        {"required", {"query"}}}}},
      {{"name", "memory_remember"},
       {"description", "Queue one durable, self-contained fact for this user's Walrus memory, in the third person "
                       "(\"User deploys to Fly.io\"). The write is queued, not yet confirmed on Walrus. Never store "
                       "secrets, keys or passwords. Check memory_recall for an equivalent first."},
       {"inputSchema", {{"type", "object"},
                        {"properties", {{"text", {{"type", "string"}}},
                                        {"namespace", {{"type", "string"}, {"description", "default " + facts}}}}},
                        {"required", {"text"}}}}},
  });
  if (read_only) tools.erase(1);
  return tools;
}

json tool_text(const std::string& text, bool error) {
  return {{"content", {{{"type", "text"}, {"text", text}}}}, {"isError", error}};
}

json call_tool(const json& params, const std::string& uid, const std::string& sock) {
  const std::string name = params.value("name", "");
  json args = params.value("arguments", json::object());
  if (!args.is_object()) args = json::object();
  auto str = [&](const char* k) { return args.contains(k) && args[k].is_string() ? args[k].get<std::string>() : ""; };
  const std::string ns = str("namespace").empty() ? shared_namespace(uid) : str("namespace");
  if (name != "memory_recall" && name != "memory_remember") return tool_text("unknown tool " + name, true);
  if (sock.empty()) return tool_text("Saga memory is not available in this run.", true);
  if (name == "memory_recall") {
    const int limit = args.contains("limit") && args["limit"].is_number_integer() ? args["limit"].get<int>() : 8;
    const json res = gate_transact(sock, {{"op", "recall"}, {"ns", ns}, {"limit", limit}, {"text", str("query")}});
    if (!res.value("ok", false)) return tool_text("recall failed: " + res.value("error", "unknown error"), true);
    std::string out;
    for (auto& m : res.value("hits", json::array())) {
      char distance[16];
      if (m.value("local", false))
        out += "- " + m.value("text", "") + "  [" + m.value("status", "queued") +
               (m.value("blob_id", "").empty() ? "; not yet confirmed on Walrus" : "; blob " + m.value("blob_id", "")) + "]\n";
      else {
        std::snprintf(distance, sizeof distance, "%.2f", m.value("distance", 0.0));
        out += "- " + m.value("text", "") + "  [distance " + distance + ", blob " + m.value("blob_id", "") + "]\n";
      }
    }
    return tool_text(out.empty() ? "No memories in " + ns + " match." : out, false);
  }
  const json res = gate_transact(sock, {{"op", "remember"}, {"ns", ns}, {"wait", false}, {"text", str("text")},
                                      {"agent", env::get("SAGA_AGENT")}, {"session", env::get("SAGA_SESSION")}});
  if (!res.value("ok", false)) return tool_text("not saved: " + res.value("error", "unknown error"), true);
  return tool_text(res.value("status", "queued") == "done" ? "Already saved on Walrus, blob " + res.value("blob_id", "") :
      "Queued for Walrus in " + res.value("ns", ns) + ". Saga confirms the blob in the background.", false);
}

}  // namespace

std::optional<json> mcp_reply(const std::string& line, const std::string& uid, const std::string& sock, bool read_only) {
  if (json_nesting(line) > kMaxJsonDepth) return std::nullopt;
  const auto req = json::parse(line, nullptr, false);
  if (!req.is_object() || !req.contains("id") || !req.contains("method")) return std::nullopt;  // notifications
  const std::string method = req["method"].is_string() ? req["method"].get<std::string>() : "";
  const json params = req.value("params", json::object());
  json reply = {{"jsonrpc", "2.0"}, {"id", req["id"]}};
  if (method == "initialize") {
    const json asked = params.is_object() ? params.value("protocolVersion", json()) : json();
    reply["result"] = {{"protocolVersion", asked.is_string() ? asked.get<std::string>() : "2025-06-18"},
                       {"capabilities", {{"tools", json::object()}}},
                       {"serverInfo", {{"name", "saga"}, {"version", "0.1.0"}}}};
  } else if (method == "tools/list") {
    reply["result"] = {{"tools", tool_list(uid, read_only)}};
  } else if (method == "tools/call" && params.is_object()) {
    reply["result"] = read_only && params.value("name", "") != "memory_recall"
                          ? tool_text("Only memory_recall is available in this run.", true)
                          : call_tool(params, uid, sock);
  } else if (method == "ping") {
    reply["result"] = json::object();
  } else {
    reply["error"] = {{"code", -32601}, {"message", "method not found"}};
  }
  return reply;
}

}  // namespace saga::memwal

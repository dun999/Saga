// Any OpenAI-compatible chat endpoint: xAI, OpenRouter, Groq, Together, Ollama, llama.cpp server, vLLM…
#include <chrono>

#include "agents/agent.h"
#include "core/env.h"
#include "core/http.h"
#include "memwal/redact.h"

namespace saga::agents {
namespace {

class OpenAIAgent : public Agent {
 public:
  using Agent::Agent;
  bool can_edit_files() const override { return false; }

  std::string unavailable_reason() const override {
    if (spec_.base_url.empty()) return "base_url not set";
    if (key().empty() && !spec_.api_key_env.empty()) return spec_.api_key_env + " not set";
    return "";
  }

  json account(const sandbox::Sandbox*) override {
    const std::string k = key();
    const std::string shown = !spec_.key_hint.empty() ? spec_.key_hint : k.size() > 4 ? k.substr(k.size() - 4) : "";
    if (spec_.locked) return {{"connected", unavailable_reason().empty()}, {"detail", "Built in, free for everyone"}, {"windows", json::array()}};
    return {{"connected", unavailable_reason().empty()},
            {"detail", shown.empty() ? "no API key" : "own API key ··" + shown},
            {"windows", json::array()}};
  }

  Result run(const Task& task, const EventFn& on_event) override {
    if (spec_.public_only && !http::is_https_url(spec_.base_url)) {
      Result refused;
      refused.error = "remote provider requires an HTTPS base URL";
      return refused;
    }
    const auto t0 = std::chrono::steady_clock::now();
    json messages = json::array();
    if (!task.system.empty()) messages.push_back({{"role", "system"}, {"content", task.system}});
    messages.push_back({{"role", "user"}, {"content", task.prompt}});
    const json body = {{"model", model_for(task)}, {"messages", messages}, {"stream", true}};

    http::Headers h = {{"Content-Type", "application/json"}, {"Accept", "text/event-stream"}};
    std::string credential = task.api_key.empty() ? key() : task.api_key;
    secrets::WipeString wipe{credential};
    memwal::SecretScope sensitive(credential);
    if (task.sensitive) task.sensitive->add(credential);
    if (!credential.empty()) h["Authorization"] = "Bearer " + credential;

    Result r;
    std::string pending;
    memwal::SecretStream safe_stream;
    auto resp = http::request(
        "POST", spec_.base_url + "/chat/completions", h, body.dump(), task.timeout_s,
        [&](std::string_view chunk) {
          if (task.cancel && task.cancel->load()) return false;
          if (task.sandbox && task.sandbox->cancel && task.sandbox->cancel->load()) return false;
          if (chunk.size() > 1024 * 1024 - std::min<size_t>(pending.size(), 1024 * 1024)) {
            r.error = "provider stream line exceeded its byte limit";
            return false;
          }
          pending.append(chunk);
          for (size_t nl; (nl = pending.find('\n')) != std::string::npos;) {
            std::string line = pending.substr(0, nl);
            pending.erase(0, nl + 1);
            if (!line.starts_with("data:")) continue;
            line.erase(0, 5);
            if (line.find("[DONE]") != std::string::npos) continue;
            if (memwal::json_nesting(line) > memwal::kMaxJsonDepth) {
              r.error = "provider response exceeded its JSON depth limit";
              return false;
            }
            auto j = json::parse(line, nullptr, false);
            if (j.is_discarded() || !j.contains("choices") || j["choices"].empty()) continue;
            const json d = j["choices"][0].value("delta", json::object());
            if (d.contains("content") && d["content"].is_string()) {
              const std::string piece = d["content"];
              r.text += piece;
              const std::string safe = safe_stream.take(piece);
              if (on_event && !safe.empty()) on_event({"delta", safe});
            }
          }
          return true;
        },
        spec_.public_only, 8 * 1024 * 1024, [&] {
          return (task.cancel && task.cancel->load()) ||
                 (task.sandbox && task.sandbox->cancel && task.sandbox->cancel->load());
        });
    r.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (!resp.ok() && r.error.empty()) {
      r.error = resp.error.empty() ? "HTTP " + std::to_string(resp.status) + ": " + resp.body.substr(0, 300)
                                   : resp.error;
    }
    r.ok = r.error.empty();
    r.text = memwal::redact_secrets(r.text);
    r.error = memwal::redact_secrets(r.error);
    const std::string remaining = safe_stream.take("", true);
    if (on_event && !remaining.empty()) on_event({"delta", remaining});
    if (h.contains("Authorization")) secrets::clear(h["Authorization"]);
    return r;
  }

 private:
  std::string key() const {
    if (!spec_.api_key.empty()) return spec_.api_key;
    return spec_.api_key_env.empty() ? "" : env::get(spec_.api_key_env.c_str());
  }
};

}  // namespace

std::unique_ptr<Agent> make_openai_agent(const Spec& spec) { return std::make_unique<OpenAIAgent>(spec); }

}  // namespace saga::agents

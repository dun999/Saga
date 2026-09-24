#pragma once
// Pluggable agent backends. A backend is either a coding CLI that acts inside a workspace
// (Claude Code, Codex, Grok) or a chat model behind an OpenAI-compatible API.
#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/sandbox.h"

namespace saga::agents {

using json = nlohmann::json;

struct Event {
  std::string type;   // "text" (whole block) | "delta" (streamed piece) | "tool" | "status"
  std::string text;
};
using EventFn = std::function<void(const Event&)>;

struct Task {
  std::string prompt;
  std::string system;     // harness-assembled context (memory, lessons, blackboard)
  std::string workspace;  // cwd for CLI agents
  const std::atomic<bool>* cancel = nullptr;
  int timeout_s = 900;
  std::map<std::string, std::string> env;  // extra env for CLI agents (SAGA_UID, SAGA_BIN…)
  // Set when agents run on the user's own accounts: the CLI runs inside that user's sandbox and
  // `workspace` is the in-sandbox path.
  const sandbox::Sandbox* sandbox = nullptr;
  std::string api_key;  // a user's own API key, unsealed for this call only
  std::string model;    // the user's pick for this agent; empty = the configured default
};

struct Result {
  bool ok = false;
  std::string text;   // final answer
  std::string error;
  std::vector<std::string> tools_used;
  double seconds = 0;
};

struct Spec {
  std::string name;         // what users type after '@'
  std::string kind;         // claude-code | codex | grok-cli | openai
  std::string model;
  std::string description;
  std::string base_url;     // openai
  std::string api_key_env;  // openai
  std::string permission_mode = "acceptEdits";  // claude-code
  std::vector<std::string> extra_args;
  std::string owner;    // uid for a user's own API agent; empty = shared
  std::string api_key;  // operator-configured key (host mode); never serialised to memory
  std::string key_hint; // last 4 chars of a user's own key, for display
  bool locked = false;  // model fixed by the operator and hidden from users
  bool public_only = false;  // a user's own API on a shared server: never reach the host's network
};

// Provider-side account state: sign-in and the provider's own usage windows (e.g. 5-hour, weekly).
struct Window {
  std::string label;       // "5-hour", "weekly", …
  double used_percent = 0;
  long resets_at = 0;      // unix seconds, 0 = unknown
};

class Agent {
 public:
  explicit Agent(Spec s) : spec_(std::move(s)) {}
  virtual ~Agent() = default;
  const Spec& spec() const { return spec_; }
  const std::string& name() const { return spec_.name; }
  const std::string& model_for(const Task& t) const { return t.model.empty() || spec_.locked ? spec_.model : t.model; }
  virtual bool can_edit_files() const { return true; }
  // Empty string when usable, else the reason it is not.
  virtual std::string unavailable_reason() const = 0;
  virtual Result run(const Task& task, const EventFn& on_event) = 0;
  // Is the user signed in with this provider, and how much of their plan is used? With a sandbox,
  // this is that user's own account. Implementations cache anything expensive; safe to call often.
  virtual json account(const sandbox::Sandbox* sb = nullptr) {
    (void)sb;
    return {{"connected", unavailable_reason().empty()}};
  }
  // Sign-in that opens a browser on this machine (the operator's own account); empty if N/A.
  virtual std::vector<std::string> login_argv() const { return {}; }
  // Headless device-code sign-in: prints a URL and a one-time code. Empty if N/A.
  virtual std::vector<std::string> device_login_argv() const { return {}; }
  virtual std::vector<std::string> logout_argv() const { return {}; }
  // Forget cached account state (after a sign-in or sign-out).
  virtual void invalidate(const sandbox::Sandbox* sb = nullptr) { (void)sb; }
  // Refresh provider usage with the smallest possible request (user-triggered). False if N/A.
  virtual bool probe_usage(const sandbox::Sandbox* sb = nullptr) {
    (void)sb;
    return false;
  }
  // True when a provider window is known to be exhausted; `why` explains.
  bool exhausted(const sandbox::Sandbox* sb = nullptr, std::string* why = nullptr);

  // Tool-free single completion, used by the harness "brain" for reflection/evolution.
  virtual Result complete(const std::string& system, const std::string& prompt,
                          const sandbox::Sandbox* sb = nullptr) {
    Task t{prompt, system, sb ? sandbox::kWork : "", nullptr, 300, {}, sb};
    return run(t, nullptr);
  }

 protected:
  Spec spec_;
};

std::unique_ptr<Agent> make_agent(const Spec& spec);
json window_json(const Window& w);
std::string window_label(long minutes);
Spec spec_from_json(const json& j);

}  // namespace saga::agents

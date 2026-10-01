// Adapters for coding-agent CLIs run headless, parsing their JSONL event streams, plus the
// provider account state each CLI exposes (sign-in, 5-hour / weekly usage windows).
//
// Every CLI call can run in one of two places: on the host as the operator (their own logins), or
// inside a user's sandbox on that user's own provider account (see core/sandbox.h).
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>

#include "agents/agent.h"
#include "core/crypto.h"
#include "core/proc.h"
#include "core/secrets.h"
#include "memwal/redact.h"

namespace saga::agents {
namespace fs = std::filesystem;

std::string window_label(long minutes) {
  if (minutes == 300) return "5-hour";
  if (minutes == 10080) return "weekly";
  if (minutes == 43200) return "monthly";
  if (minutes > 0 && minutes % 1440 == 0) return std::to_string(minutes / 1440) + "-day";
  if (minutes > 0 && minutes % 60 == 0) return std::to_string(minutes / 60) + "-hour";
  return std::to_string(minutes) + "-min";
}

json window_json(const Window& w) {
  return {{"label", w.label}, {"used_percent", w.used_percent}, {"resets_at", w.resets_at}};
}

bool Agent::exhausted(const sandbox::Sandbox* sb, std::string* why) {
  const json a = account(sb);
  for (auto& w : a.value("windows", json::array())) {
    if (w.value("used_percent", 0.0) < 100.0) continue;
    const long reset = w.value("resets_at", 0L);
    if (reset && reset < std::time(nullptr)) continue;  // window already rolled over
    if (why) *why = "@" + name() + " " + w.value("label", "usage") + " limit reached";
    return true;
  }
  return false;
}

namespace {

std::string brief(const json& input) {
  for (const char* k : {"command", "file_path", "path", "pattern", "url", "description"})
    if (input.contains(k) && input[k].is_string()) return input[k].get<std::string>().substr(0, 160);
  return "";
}

double since(std::chrono::steady_clock::time_point t0) {
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

// Whose provider account a call acts on: "" is the operator, else the user's agent home.
std::string key_of(const sandbox::Sandbox* sb) { return sb ? sb->home : ""; }

std::string home_of(const sandbox::Sandbox* sb) {
  if (sb) return sb->home;
  const char* h = std::getenv("HOME");
  return h ? h : "";
}

json codex_windows(const std::string& home);
void keep_codex_usage(const std::string& home);

// Run a CLI on the host, or inside the user's sandbox.
proc::Result exec(const std::vector<std::string>& argv, proc::Options o, const sandbox::Sandbox* sb) {
  if (!sb) return proc::run(argv, o);
  sandbox::Lease lease(sb);  // logins are plaintext only while calls run; the home is scrubbed after
  auto r = sandbox::run(*sb, argv, std::move(o));
  keep_codex_usage(sb->home);  // before the scrub takes the session files it was read from
  r.out = memwal::redact_secrets(r.out);
  r.err = memwal::redact_secrets(r.err);
  return r;
}

// Context for one CLI call, kept off the command line: argv is visible to every local user (ps), and
// the context carries the user's memories. The file is 0600, in the user's own agent home when
// sandboxed (so the CLI can read it), and deleted when the call ends.
class ContextFile {
 public:
  ContextFile(const std::string& text, const sandbox::Sandbox* sb) {
    if (text.empty()) return;
    const fs::path dir = sb ? fs::path(sb->home) / ".saga" : fs::temp_directory_path();
    const std::string name = "ctx-" + crypto::random_hex(8) + ".md";
    std::error_code ec;
    fs::create_directories(dir, ec);
    host_ = dir / name;
    root_ = sb ? sb->home : dir.string();
    rel_ = sb ? ".saga/" + name : name;
    secrets::write_private_file(root_, rel_, text);
    path_ = sb ? std::string(sandbox::kHome) + "/.saga/" + name : host_.string();
  }
  ~ContextFile() {
    if (!host_.empty()) {
      try { secrets::erase_file(root_, rel_); } catch (...) {}
    }
  }
  ContextFile(const ContextFile&) = delete;
  ContextFile& operator=(const ContextFile&) = delete;
  const std::string& path() const { return path_; }  // as the CLI sees it; "" = no context

 private:
  fs::path host_;
  std::string path_;
  std::string root_, rel_;
};

// Small TTL cache so account() can be polled by the UI without re-running CLIs each time.
struct Cached {
  std::mutex mu;
  json value;
  std::chrono::steady_clock::time_point at{};
  template <class F>
  json get(int ttl_s, F&& fill) {
    std::lock_guard lk(mu);
    if (value.is_null() || std::chrono::steady_clock::now() - at > std::chrono::seconds(ttl_s)) {
      value = fill();
      at = std::chrono::steady_clock::now();
    }
    return value;
  }
  void invalidate() {
    std::lock_guard lk(mu);
    value = nullptr;
  }
};

// Per-account state (one entry per user home, "" for the operator).
template <class T>
class PerAccount {
 public:
  T& operator[](const std::string& key) {
    std::lock_guard lk(mu_);
    auto& p = items_[key];
    if (!p) p = std::make_unique<T>();
    return *p;
  }

 private:
  std::mutex mu_;
  std::map<std::string, std::unique_ptr<T>> items_;
};

struct LastError {
  std::mutex mu;
  std::string text;
  void set(const std::string& t) {
    std::lock_guard lk(mu);
    text = t;
  }
  std::string get() {
    std::lock_guard lk(mu);
    return text;
  }
};

// The account a stream line belongs to, for parsers that record per-account state.
thread_local std::string tl_account;

class CliAgent : public Agent {
 public:
  using Agent::Agent;

  std::string unavailable_reason() const override {
    return proc::on_path(exe()) ? "" : exe() + " not found on PATH";
  }
  void invalidate(const sandbox::Sandbox* sb) override { status_[key_of(sb)].invalidate(); }

  Result run(const Task& task, const EventFn& on_event) override {
    const auto t0 = std::chrono::steady_clock::now();
    Result r;
    auto emit = [&](Event e) {
      e.text = memwal::redact_secrets(e.text);
      if (e.type == "tool") r.tools_used.push_back(e.text);
      if (on_event) on_event(e);
    };
    proc::Options o;
    o.cwd = task.workspace;
    o.timeout_s = task.timeout_s;
    o.cancel = task.cancel;
    o.env = task.env;
    tl_account = key_of(task.sandbox);
    o.on_stdout_line = [&](const std::string& line) {
      if (line.empty() || line[0] != '{') return;
      if (memwal::json_nesting(line) > memwal::kMaxJsonDepth)
        throw std::runtime_error("agent event exceeded its JSON depth limit");
      auto j = json::parse(line, nullptr, false);
      if (j.is_discarded()) return;
      const auto safe = memwal::prepare_for_storage("SAGA:event " + line);
      if (!safe.ok) return;
      j = json::parse(safe.text.substr(11), nullptr, false);
      if (j.is_discarded()) return;
      try {
        parse(j, r, emit);
      } catch (const json::exception&) {  // an event shaped unlike we expect: skip it, keep the run
      }
    };
    o.stdin_data = stdin_for(task);
    const ContextFile ctx(system_in_file() ? task.system : "", task.sandbox);
    auto p = exec(argv(task, ctx.path()), o, task.sandbox);
    r.seconds = since(t0);
    if (p.output_limited) r.error = "agent output exceeded its limit";
    else if (p.timed_out) r.error = "timed out after " + std::to_string(task.timeout_s) + "s";
    else if (p.cancelled) r.error = "cancelled";
    else if (r.error.empty() && p.exit_code != 0 && r.text.empty())
      r.error = "exit " + std::to_string(p.exit_code) + ": " + p.err.substr(0, 400);
    r.ok = r.error.empty();
    last_error_[key_of(task.sandbox)].set(r.ok ? "" : r.error.substr(0, 240));
    status_[key_of(task.sandbox)].invalidate();
    return r;
  }

 protected:
  virtual std::string exe() const = 0;
  // system_file: the task's context as a file path, when system_in_file(); else "".
  virtual std::vector<std::string> argv(const Task& t, const std::string& system_file) const = 0;
  virtual bool system_in_file() const { return false; }
  virtual std::string stdin_for(const Task&) const { return ""; }  // e.g. the prompt, off argv
  virtual void parse(const json& j, Result& r, const std::function<void(Event)>& emit) = 0;

  static std::string with_system(const Task& t) {
    return t.system.empty() ? t.prompt : "<context>\n" + t.system + "\n</context>\n\n" + t.prompt;
  }
  std::string last_error(const sandbox::Sandbox* sb) { return last_error_[key_of(sb)].get(); }

  PerAccount<Cached> status_;
  PerAccount<LastError> last_error_;
};

// Claude Code and Grok Build both emit Anthropic-Messages-shaped JSONL.
void parse_anthropic_stream(const json& j, Result& r, const std::function<void(Event)>& emit) {
  const std::string type = j.value("type", "");
  if (type == "assistant" && j.contains("message")) {
    for (auto& c : j["message"].value("content", json::array())) {
      const std::string ct = c.value("type", "");
      if (ct == "text") emit({"text", c.value("text", "")});
      else if (ct == "tool_use") emit({"tool", c.value("name", "tool") + " " + brief(c.value("input", json::object()))});
    }
  } else if (type == "result") {
    if (j.value("is_error", false)) {
      r.error = j.value("result", j.value("subtype", "error"));
    } else if (j.contains("result") && j["result"].is_string()) {
      r.text = j["result"].get<std::string>();
    }
  }
}

class ClaudeCodeAgent : public CliAgent {
 public:
  using CliAgent::CliAgent;

  Result complete(const std::string& system, const std::string& prompt, const sandbox::Sandbox* sb) override {
    const auto t0 = std::chrono::steady_clock::now();
    const ContextFile sys(system, sb);
    std::vector<std::string> a = {"claude", "-p", "--output-format", "json", "--tools", "", "--no-session-persistence"};
    if (!sys.path().empty()) a.insert(a.end(), {"--system-prompt-file", sys.path()});
    if (!spec_.model.empty()) a.insert(a.end(), {"--model", spec_.model});
    proc::Options o;
    o.timeout_s = 300;
    o.stdin_data = prompt;  // reflection traces quote the user; keep them off argv
    auto p = exec(a, o, sb);
    Result r;
    r.seconds = since(t0);
    if (p.output_limited || p.timed_out || p.cancelled) {
      r.error = p.output_limited ? "brain output exceeded its limit" : "brain timed out or was cancelled";
      return r;
    }
    if (memwal::json_nesting(p.out) > memwal::kMaxJsonDepth) {
      r.error = "brain response exceeded its JSON depth limit";
      return r;
    }
    auto j = json::parse(p.out, nullptr, false);
    if (j.is_object() && !j.value("is_error", false) && j.contains("result")) {
      r.text = j["result"].get<std::string>();
      r.ok = true;
    } else {
      r.error = "claude brain: " + (p.err.empty() ? p.out.substr(0, 300) : p.err.substr(0, 300));
    }
    return r;
  }

  json account(const sandbox::Sandbox* sb) override {
    json a;
    if (sb) {
      // A user's own Claude: a subscription token from `claude setup-token`, or an API key.
      const bool token = sb->env.contains("CLAUDE_CODE_OAUTH_TOKEN"), key = sb->env.contains("ANTHROPIC_API_KEY");
      a = {{"connected", token || key},
           {"detail", token ? "Claude subscription (token)" : key ? "Anthropic API key" : "not connected"}};
    } else {
      a = status_[""].get(120, [] {
        proc::Options o;
        o.timeout_s = 20;
        auto p = proc::run({"claude", "auth", "status"}, o);
        auto j = json::parse(p.out, nullptr, false);
        if (!j.is_object()) return json{{"connected", false}, {"detail", "not signed in"}};
        const bool in = j.value("loggedIn", false);
        const std::string how = j.value("authMethod", "");
        return json{{"connected", in},
                    {"detail", in ? (how == "claude.ai" ? "Claude subscription" : how) : "not signed in"},
                    {"account", j.value("email", "")}};
      });
    }
    const auto ws = windows(key_of(sb));
    json arr = json::array();
    for (auto& w : ws) arr.push_back(window_json(w));
    a["windows"] = arr;
    if (ws.empty() && a.value("connected", false)) a["windows_hint"] = "Usage windows appear after @claude's next run.";
    if (auto e = last_error(sb); !e.empty()) a["last_error"] = e;
    return a;
  }

  std::vector<std::string> login_argv() const override { return {"claude", "auth", "login"}; }
  std::vector<std::string> logout_argv() const override { return {"claude", "auth", "logout"}; }

  // Claude reports usage windows only inside a response stream, so ask the cheapest model for one word.
  bool probe_usage(const sandbox::Sandbox* sb) override {
    proc::Options o;
    o.timeout_s = 60;
    Result r;
    tl_account = key_of(sb);
    o.on_stdout_line = [&](const std::string& line) {
      auto j = json::parse(line, nullptr, false);
      if (j.is_discarded()) return;
      try {
        parse(j, r, [](Event) {});
      } catch (const json::exception&) {
      }
    };
    exec({"claude", "-p", "Reply with: ok", "--model", "haiku", "--output-format", "stream-json", "--verbose",
          "--tools", "", "--no-session-persistence"},
         o, sb);
    return !windows(key_of(sb)).empty();
  }

 protected:
  std::string exe() const override { return "claude"; }
  bool system_in_file() const override { return true; }
  std::string stdin_for(const Task& t) const override { return t.prompt; }
  std::vector<std::string> argv(const Task& t, const std::string& system_file) const override {
    std::vector<std::string> a = {"claude", "-p", "--output-format", "stream-json", "--verbose",
                                  "--permission-mode", spec_.permission_mode, "--no-session-persistence"};
    if (!system_file.empty()) a.insert(a.end(), {"--append-system-prompt-file", system_file});
    if (!model_for(t).empty()) a.insert(a.end(), {"--model", model_for(t)});
    // acceptEdits still asks before any shell command, and nobody can answer in -p mode, so the
    // memory command the prompt tells the agent to use has to be allowed up front.
    if (auto bin = t.env.find("SAGA_BIN"); bin != t.env.end() && !bin->second.empty())
      a.insert(a.end(), {"--allowedTools", "Bash(" + bin->second + " mem:*)"});
    a.insert(a.end(), spec_.extra_args.begin(), spec_.extra_args.end());
    return a;
  }
  void parse(const json& j, Result& r, const std::function<void(Event)>& emit) override {
    // Every run reports the subscription's rolling windows (five_hour, seven_day, …).
    if (j.value("type", "") == "rate_limit_event") {
      const json info = j.value("rate_limit_info", json::object());
      const json unified = info.value("unifiedWindows", json::object());
      std::vector<Window> ws;
      for (auto& [k, v] : unified.items()) {
        Window w;
        w.label = k == "five_hour" ? "5-hour" : k == "seven_day" ? "weekly" : k;
        w.used_percent = v.value("utilization", 0.0) * 100.0;
        w.resets_at = v.value("resetsAt", 0L);
        ws.push_back(w);
      }
      if (!ws.empty()) {
        std::lock_guard lk(win_mu_);
        windows_[tl_account] = ws;
      }
      return;
    }
    parse_anthropic_stream(j, r, emit);
  }

 private:
  std::vector<Window> windows(const std::string& key) {
    std::lock_guard lk(win_mu_);
    auto it = windows_.find(key);
    return it == windows_.end() ? std::vector<Window>{} : it->second;
  }
  std::mutex win_mu_;
  std::map<std::string, std::vector<Window>> windows_;
};

class GrokCliAgent : public CliAgent {
 public:
  using CliAgent::CliAgent;

  json account(const sandbox::Sandbox* sb) override {
    const std::string home = home_of(sb);
    json a = status_[key_of(sb)].get(30, [home, sb] {
      std::error_code ec;
      const auto p = fs::path(home) / ".grok" / "auth.json";
      const bool in = sb ? sandbox::has_login(*sb, ".grok/auth.json") : fs::exists(p, ec) && fs::file_size(p, ec) > 2;
      return json{{"connected", in}, {"detail", in ? "Grok account" : "not connected"}};
    });
    a["windows"] = json::array();  // Grok Build exposes a balance, not rolling windows
    if (auto e = last_error(sb); !e.empty()) a["last_error"] = e;
    return a;
  }

  std::vector<std::string> login_argv() const override { return {"grok", "login", "--oauth"}; }
  std::vector<std::string> device_login_argv() const override { return {"grok", "login", "--device-auth"}; }
  std::vector<std::string> logout_argv() const override { return {"grok", "logout"}; }

 protected:
  std::string exe() const override { return "grok"; }
  // Grok Build only takes the prompt as an argument.
  std::vector<std::string> argv(const Task& t, const std::string&) const override {
    std::vector<std::string> a = {"grok", "-p", with_system(t), "--output-format", "streaming-messages-json"};
    if (!t.workspace.empty()) a.insert(a.end(), {"--cwd", t.workspace});
    if (!model_for(t).empty()) a.insert(a.end(), {"--model", model_for(t)});
    a.insert(a.end(), spec_.extra_args.begin(), spec_.extra_args.end());
    return a;
  }
  void parse(const json& j, Result& r, const std::function<void(Event)>& emit) override {
    parse_anthropic_stream(j, r, emit);
    // Grok's result line has no `result` text; keep the last assistant text as the answer.
    if (j.value("type", "") == "assistant" && r.error.empty() && j.contains("message") && j["message"].is_object())
      for (auto& c : j["message"].value("content", json::array()))
        if (c.value("type", "") == "text") r.text = c.value("text", "");
  }
};

// Codex records the plan's rate-limit windows in its session rollouts (<home>/.codex/sessions).
const json* find_key(const json& j, const std::string& key) {
  if (j.is_object()) {
    if (auto it = j.find(key); it != j.end()) return &*it;
    for (auto& [k, v] : j.items())
      if (auto* f = find_key(v, key)) return f;
  } else if (j.is_array()) {
    for (auto& v : j)
      if (auto* f = find_key(v, key)) return f;
  }
  return nullptr;
}

// Only the plan's usage numbers survive a sandboxed run, in <home>/.saga (the session files they come
// from hold the whole conversation, and are scrubbed).
fs::path codex_usage_file(const std::string& home) { return fs::path(home) / ".saga" / "codex-usage.json"; }

json codex_windows_from_sessions(const std::string& home);

json codex_windows(const std::string& home) {
  json w = codex_windows_from_sessions(home);
  if (!w["windows"].empty()) return w;
  std::ifstream in(codex_usage_file(home));
  auto cached = json::parse(in, nullptr, false);
  return cached.is_object() && cached.contains("windows") ? cached : w;
}

void keep_codex_usage(const std::string& home) {
  const json w = codex_windows_from_sessions(home);
  if (w["windows"].empty()) return;
  std::error_code ec;
  fs::create_directories(codex_usage_file(home).parent_path(), ec);
  std::ofstream(codex_usage_file(home), std::ios::trunc) << w.dump();
}

json codex_windows_from_sessions(const std::string& home) {
  std::error_code ec;
  const fs::path root = fs::path(home) / ".codex" / "sessions";
  std::vector<std::pair<fs::file_time_type, fs::path>> files;
  for (auto it = fs::recursive_directory_iterator(root, ec); !ec && it != fs::recursive_directory_iterator();
       it.increment(ec)) {
    if (it->is_regular_file(ec) && it->path().extension() == ".jsonl")
      files.emplace_back(it->last_write_time(ec), it->path());
  }
  std::sort(files.begin(), files.end(), [](auto& a, auto& b) { return a.first > b.first; });
  for (size_t i = 0; i < files.size() && i < 25; ++i) {
    std::ifstream in(files[i].second);
    json latest;
    for (std::string line; std::getline(in, line);) {
      if (line.find("\"rate_limits\"") == std::string::npos) continue;
      auto j = json::parse(line, nullptr, false);
      if (j.is_discarded()) continue;
      if (auto* rl = find_key(j, "rate_limits"); rl && rl->is_object() && rl->value("primary", json()).is_object())
        latest = *rl;
    }
    if (latest.is_null()) continue;
    json ws = json::array();
    for (const char* k : {"primary", "secondary"}) {
      const json w = latest.value(k, json());
      if (!w.is_object()) continue;
      ws.push_back(window_json({window_label(w.value("window_minutes", 0L)), w.value("used_percent", 0.0),
                                w.value("resets_at", 0L)}));
    }
    return {{"windows", ws}, {"plan", latest.value("plan_type", "")}};
  }
  return {{"windows", json::array()}, {"plan", ""}};
}

class CodexAgent : public CliAgent {
 public:
  using CliAgent::CliAgent;

  json account(const sandbox::Sandbox* sb) override {
    const std::string home = home_of(sb);
    json a = status_[key_of(sb)].get(60, [sb, home] {
      proc::Options o;
      o.timeout_s = 20;
      auto p = exec({"codex", "login", "status"}, o, sb);
      const std::string out = p.out + p.err;
      const bool in = p.exit_code == 0 && out.find("Logged in") != std::string::npos;
      const auto line = out.find("Logged in");
      json r = {{"connected", in},
                {"detail", in ? out.substr(line, out.find('\n', line) - line) : "not connected"}};
      json w = codex_windows(home);
      r["windows"] = w["windows"];
      if (!w["plan"].get<std::string>().empty()) r["plan"] = w["plan"];
      return r;
    });
    if (auto e = last_error(sb); !e.empty()) a["last_error"] = e;
    return a;
  }

  std::vector<std::string> login_argv() const override { return {"codex", "login"}; }
  std::vector<std::string> device_login_argv() const override { return {"codex", "login", "--device-auth"}; }
  std::vector<std::string> logout_argv() const override { return {"codex", "logout"}; }

 protected:
  std::string exe() const override { return "codex"; }
  std::string stdin_for(const Task& t) const override { return with_system(t); }
  std::vector<std::string> argv(const Task& t, const std::string&) const override {
    std::vector<std::string> a = {"codex", "exec", "--json", "--skip-git-repo-check", "-s", "workspace-write"};
    if (!t.workspace.empty()) a.insert(a.end(), {"-C", t.workspace});
    if (!model_for(t).empty()) a.insert(a.end(), {"-m", model_for(t)});
    a.insert(a.end(), spec_.extra_args.begin(), spec_.extra_args.end());
    a.push_back("-");  // the prompt comes on stdin
    return a;
  }
  void parse(const json& j, Result& r, const std::function<void(Event)>& emit) override {
    const std::string type = j.value("type", "");
    if (type == "item.started" || type == "item.completed") {
      const json it = j.value("item", json::object());
      const std::string kind = it.value("type", "");
      if (kind == "agent_message" && type == "item.completed") {
        r.text = it.value("text", "");
        emit({"text", r.text});
      } else if (kind == "command_execution" && type == "item.started") {
        emit({"tool", "shell " + it.value("command", "").substr(0, 160)});
      } else if (kind == "file_change" && type == "item.completed") {
        std::string files;
        for (auto& c : it.value("changes", json::array())) files += c.value("path", "") + " ";
        emit({"tool", "edit " + files});
      } else if (kind == "reasoning" && type == "item.completed") {
        emit({"status", it.value("text", "").substr(0, 200)});
      }
      // `error` items are non-fatal warnings (e.g. metadata fallbacks); ignore.
    } else if (type == "turn.failed") {
      const json err = j.value("error", json::object());
      r.error = err.is_object() ? err.value("message", "codex turn failed") : "codex turn failed";
    }
  }
};

}  // namespace

std::unique_ptr<Agent> make_openai_agent(const Spec& spec);  // openai_agent.cpp

std::unique_ptr<Agent> make_agent(const Spec& spec) {
  if (spec.kind == "claude-code") return std::make_unique<ClaudeCodeAgent>(spec);
  if (spec.kind == "codex") return std::make_unique<CodexAgent>(spec);
  if (spec.kind == "grok-cli") return std::make_unique<GrokCliAgent>(spec);
  if (spec.kind == "openai") return make_openai_agent(spec);
  throw std::invalid_argument("unknown agent kind: " + spec.kind);
}

Spec spec_from_json(const json& j) {
  Spec s;
  s.name = j.at("name").get<std::string>();
  s.kind = j.at("kind").get<std::string>();
  s.model = j.value("model", "");
  s.description = j.value("description", "");
  s.base_url = j.value("base_url", "");
  s.api_key_env = j.value("api_key_env", "");
  s.permission_mode = j.value("permission_mode", s.permission_mode);
  s.extra_args = j.value("extra_args", std::vector<std::string>{});
  s.owner = j.value("owner", "");
  s.locked = j.value("locked", false);
  return s;
}

}  // namespace saga::agents

#pragma once
// The Saga harness: memory-grounded context assembly, @mention routing across agents with a shared
// blackboard, and an online self-improvement loop (Reflexion lessons, Voyager skills, GEPA prompts).
// Every durable artifact — transcripts, work checkpoints, lessons, prompts — is a Walrus blob.
#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "agents/registry.h"
#include "harness/prompts.h"
#include "core/proc.h"
#include "core/secrets.h"
#include "memwal/store.h"

namespace saga::harness {

using json = nlohmann::json;
using Emit = std::function<void(const json&)>;  // UI event stream (NDJSON)

struct Options {
  std::string workspaces_dir = "workspaces";
  std::string saga_bin;       // absolute path of this binary, for `saga mem` inside agents
  int max_steps = 6;          // total agent runs per turn, handoffs included
  int evolve_every = 3;       // negative critiques before a prompt mutation
  int agent_timeout_s = 900;
  std::string keys_path;      // own API keys (0600 file on this host, never in memory)
  // Bring-your-own accounts: each user signs in to Claude / Codex / Grok with their own account,
  // and every agent run happens inside that user's sandbox (core/sandbox.h). Off = operator's logins.
  bool user_accounts = false;
  std::string homes_dir = "agent-homes";  // per-user agent homes (provider credentials live here)
  std::string github_client_id;           // OAuth App; empty = token paste only
  std::string github_client_secret;       // with the id: "Connect GitHub" redirects to github.com and back
  std::string mem_sock;                    // host-mode `saga mem` socket; delegate key stays here
};

struct Step {
  std::string agent, instruction, requested_by, output, error;
  bool fallback = false;
  double seconds = 0;
  std::vector<std::string> tools;
  json files = json::array();  // checkpointed changes
};

struct Turn {
  std::string id, uid, session, message, workspace;
  int prompt_version = 0;
  std::vector<Step> steps;
  std::vector<std::string> recalled;  // memories that shaped this turn (shown in UI / article)
  std::string history;                // the last few exchanges of this chat, for follow-ups
  int rating = 0;            // last signal: +1 / -1, from the user or implicit
  bool user_rated = false;
  bool done = false;
  // Playbook rules and lessons that were in the agents' context, as credit ids ("b3", "lesson:<blob>")
  // with their text, so reflection can say which ones helped or hurt.
  std::vector<std::pair<std::string, std::string>> in_context;
  secrets::Key vault;  // the user's vault key for this turn (memory only; also used by reflection)
  std::shared_ptr<std::atomic<bool>> cancel = std::make_shared<std::atomic<bool>>(false);
};

// Namespace scheme, shared with `saga mem` and the web API.
std::string ns_user(const std::string& uid, const char* what);
std::string ns_lessons(const std::string& agent);
std::string memory_protocol(const std::string& uid, const std::string& agent, bool can_run_shell,
                            const std::string& saga_bin);

class Harness {
 public:
  Harness(agents::Registry& reg, memwal::Store& store, Options opt);
  ~Harness();  // waits for background reflection

  void boot(const Emit& log = nullptr);  // restore hot namespaces + load prompt population
  std::string chat(const std::string& uid, const std::string& session, const std::string& message,
                   const Emit& emit, const secrets::Key& vault = {});       // returns turn id
  json feedback(const std::string& turn_id, int rating, const std::string& comment);
  bool cancel(const std::string& turn_id);
  // Queue critiques and run one evolution now, replayed on this user's rated turns (`saga evolve`).
  json evolve_now(const std::string& uid, const std::vector<std::string>& critiques);

  // Read-side views, all served from Walrus Memory.
  json memory_view(const std::string& uid, const std::string& query);
  json memory_stats(const std::string& uid);  // {blobs, bytes}: everything this user has on Walrus
  json chat_history(const std::string& uid);
  json chat_transcript(const std::string& uid, const std::string& session);
  json checkpoints(const std::string& uid, const std::string& session);
  json restore_checkpoints(const std::string& uid, const std::string& session);
  json state() const;
  // Agents as the user sees them: provider sign-in, 5-hour/weekly windows, runs today.
  json agents_view(const std::string& uid, const secrets::Key& vault);
  json roster(const std::string& uid) {  // cheap: names/kinds only, for @-autocomplete
    seed_user(uid);
    return reg_.roster(uid);
  }
  json connect_agent(const std::string& uid, const std::string& name, const secrets::Key& vault);
  json connect_status(const std::string& uid, const std::string& name);
  json set_credential(const std::string& uid, const std::string& name, const std::string& kind,
                      const std::string& value, const secrets::Key& vault);  // token / API key
  json disconnect_agent(const std::string& uid, const std::string& name);
  json probe_agent(const std::string& uid, const std::string& name, const secrets::Key& vault);
  json add_agent(const std::string& uid, const json& body, const secrets::Key& vault);  // own API key
  json remove_agent(const std::string& uid, const std::string& name);
  json set_model(const std::string& uid, const std::string& agent, const std::string& model);  // "" = default
  json models_view(const std::string& uid);  // per agent: default, the user's pick, suggestions
  // GitHub: connect (token or device flow), pick a repo per chat, open a PR from the agents' work.
  json github_status(const std::string& uid, const secrets::Key& vault);
  json github_set_token(const std::string& uid, const std::string& token, const secrets::Key& vault);
  json github_device(const std::string& uid, const secrets::Key& vault);
  std::string github_authorize_url(const std::string& redirect_uri, const std::string& state) const;  // "" = not set up
  json github_oauth_finish(const std::string& uid, const std::string& code, const std::string& redirect_uri,
                           const secrets::Key& vault);
  json github_disconnect(const std::string& uid);
  json github_repos(const std::string& uid, const secrets::Key& vault);
  json github_attach(const std::string& uid, const std::string& session, const std::string& full_name,
                     const secrets::Key& vault);
  json github_repo(const std::string& uid, const std::string& session, const secrets::Key& vault);
  json github_open_pr(const std::string& uid, const std::string& session, const std::string& title,
                      const secrets::Key& vault);
  // Vault: "ok" | "missing" (no key sent) | "mismatch" (secrets were sealed under another key).
  json vault_status(const std::string& uid, const secrets::Key& vault);
  json vault_reset(const std::string& uid, const secrets::Key& vault);  // forget old sealed secrets

  std::string workspace_for(const std::string& uid, const std::string& session) const;
  bool user_accounts() const { return opt_.user_accounts; }
  agents::Registry& registry() { return reg_; }
  memwal::Store& store() { return store_; }
  PromptPool& prompts() { return prompts_; }

 private:
  std::string build_context(Turn& t, const agents::Agent& agent, const std::string& instruction,
                            const std::vector<memwal::Memory>& facts, const std::vector<memwal::Memory>& episodes,
                            const std::vector<memwal::Memory>& skills, const Emit& emit);
  void run_step(Turn& t, Step& s, const std::string& context, const Emit& emit);
  void apply_directives(Turn& t, const Step& s, const Emit& emit);
  json reflect(const Turn& t, int rating, const std::string& comment);
  // One learning signal on a finished turn: scores its prompt version, keeps it as a replay case, reflects.
  json rate(const std::shared_ptr<Turn>& t, int rating, const std::string& comment, bool implicit);
  void rate_later(const std::shared_ptr<Turn>& t, int rating, const std::string& why);  // implicit signal
  void evolve_in_background(const std::string& uid, const secrets::Key& vault);
  std::vector<ReplayCase> replay_cases(const std::string& uid);
  std::shared_ptr<Turn> last_turn(const std::string& uid, const std::string& session);
  std::string session_history(const std::string& uid, const std::string& session);
  void seed_user(const std::string& uid);
  std::string github_token(const std::string& uid, const secrets::Key& vault);
  // Run git for this user's chat workspace: in their sandbox (user accounts) or on the host.
  proc::Result git(const std::string& uid, const std::string& workspace, const secrets::Key& vault,
                   const std::vector<std::string>& args, const std::string& token = "", int timeout_s = 120);
  std::string repo_context(const Turn& t);
  // The user's sandbox when running on their own accounts; nullopt = operator mode.
  std::optional<sandbox::Sandbox> sandbox_for(const std::string& uid, const std::string& workspace,
                                              const secrets::Key& vault);
  void persist_user_agents(const std::string& uid);
  void record_usage(const std::string& uid, const std::string& agent, const agents::Result& r);
  std::vector<json> recall_records(const std::string& ns, const std::string& kind, const std::string& query,
                                   int limit);

  agents::Registry& reg_;
  memwal::Store& store_;
  Options opt_;
  PromptPool prompts_;
  mutable std::mutex mu_;
  std::map<std::string, std::shared_ptr<Turn>> turns_;  // this process only; Walrus is the record
  std::vector<std::thread> background_;
  std::map<std::string, std::vector<std::string>> session_turns_;  // "<uid>/<session>" → turn ids, in order
  std::atomic<bool> evolving_{false};

  struct Usage {
    std::string day;
    int runs = 0;
    double seconds = 0;
  };
  std::map<std::string, std::map<std::string, Usage>> usage_;  // uid -> agent -> today
  std::set<std::string> seeded_;
  std::map<std::string, std::map<std::string, std::string>> model_picks_;  // uid → agent → model
  std::string model_pick(const std::string& uid, const std::string& agent) const;
  std::set<std::string> connecting_;                           // host-mode sign-ins in progress
  struct DeviceLogin {
    std::string url, code, status = "starting", error;          // starting|waiting|done|failed
  };
  std::map<std::string, std::shared_ptr<DeviceLogin>> device_;
  std::map<std::string, std::shared_ptr<DeviceLogin>> gh_device_;  // uid → GitHub device sign-in  // "<uid>/<agent>" → device-code sign-in
};

}  // namespace saga::harness

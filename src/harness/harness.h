#pragma once
// The Saga harness: memory-grounded context assembly, @mention routing across agents with a shared
// blackboard, and an online self-improvement loop (Reflexion lessons, Voyager skills, GEPA prompts).
// Every durable artifact — transcripts, work checkpoints, lessons, prompts — is a Walrus blob.
#include <atomic>
#include <functional>
#include <future>
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
  bool trace = false;         // print each turn's phases and timings to stderr
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
  // Runs of built-in agents that spend the operator's own keys, shared by every signed-in user.
  // 0 disables the cap. A user's own OpenAI agent, and a user-mode CLI on their sandbox login, are not counted.
  int operator_daily_runs = 1000;
  int max_background = 32;                 // reflections, sign-ins, and evolution waiting to run
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
  std::time_t started = 0;
  // Playbook rules and lessons that were in the agents' context, as credit ids ("b3", "lesson:<blob>")
  // with their text, so reflection can say which ones helped or hurt.
  std::vector<std::pair<std::string, std::string>> in_context;
  secrets::Key vault;  // cleared when the turn finishes
  std::shared_ptr<memwal::SecretScope> sensitive;
  std::shared_ptr<std::atomic<bool>> session_cancel;
  std::shared_ptr<std::atomic<bool>> cancel = std::make_shared<std::atomic<bool>>(false);
};

// Namespace scheme, shared with `saga mem` and the web API.
std::string ns_user(const std::string& uid, const char* what);
std::string ns_lessons(const std::string& agent, const std::string& uid);
// Write one restored checkpoint file under `root` without following links; false = refused.
bool write_in_workspace(const std::string& root, const std::string& rel, const std::string& content);
std::string memory_protocol(const std::string& uid, const std::string& agent, bool can_run_shell,
                            const std::string& saga_bin);

class Harness {
 public:
  Harness(agents::Registry& reg, memwal::Store& store, Options opt);
  ~Harness();  // waits for background reflection

  void boot(const Emit& log = nullptr);  // restore hot namespaces + load prompt population
  std::string chat(const std::string& uid, const std::string& session, const std::string& message,
                   const Emit& emit, const secrets::Key& vault = {});       // returns turn id
  // Only the user who ran a turn can rate or cancel it.
  json feedback(const std::string& uid, const std::string& turn_id, int rating, const std::string& comment,
                const secrets::Key& vault = {});
  bool cancel(const std::string& uid, const std::string& turn_id);
  void cancel_active(const std::string& uid);  // logout: stop this user's live turns and sign-ins
  void end_session(const std::string& uid);  // also discard connections the user did not remember
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
  json connect_agent(const std::string& uid, const std::string& name, const secrets::Key& vault, bool remember = true);
  json connect_status(const std::string& uid, const std::string& name, const secrets::Key& vault);
  json set_credential(const std::string& uid, const std::string& name, const std::string& kind,
                      const std::string& value, const secrets::Key& vault, bool remember = true);  // token / API key
  json disconnect_agent(const std::string& uid, const std::string& name, const secrets::Key& vault);
  json probe_agent(const std::string& uid, const std::string& name, const secrets::Key& vault);
  json add_agent(const std::string& uid, const json& body, const secrets::Key& vault);  // own API key
  json remove_agent(const std::string& uid, const std::string& name, const secrets::Key& vault);
  json set_model(const std::string& uid, const std::string& agent, const std::string& model);  // "" = default
  json models_view(const std::string& uid);  // per agent: default, the user's pick, suggestions
  // GitHub: connect (token or device flow), pick a repo per chat, open a PR from the agents' work.
  json github_status(const std::string& uid, const secrets::Key& vault);
  json github_set_token(const std::string& uid, const std::string& token, const secrets::Key& vault,
                        const std::string& source = "pat", const std::atomic<bool>* cancelled = nullptr,
                        bool remember = true);
  json github_device(const std::string& uid, const secrets::Key& vault, bool remember = true);
  std::string github_authorize_url(const std::string& redirect_uri, const std::string& state) const;  // "" = not set up
  json github_oauth_finish(const std::string& uid, const std::string& code, const std::string& redirect_uri,
                           const secrets::Key& vault, bool remember = true);
  json github_disconnect(const std::string& uid, const secrets::Key& vault);
  json github_repos(const std::string& uid, const secrets::Key& vault);
  json github_attach(const std::string& uid, const std::string& session, const std::string& full_name,
                     const secrets::Key& vault);
  json github_repo(const std::string& uid, const std::string& session, const secrets::Key& vault);
  json github_open_pr(const std::string& uid, const std::string& session, const std::string& title,
                      const secrets::Key& vault);
  // Where a user's connections live: the wallet address, or for a username "<uid>~<key id>" (see .cpp).
  std::string keyring(const std::string& uid, const secrets::Key& vault) const;
  // Vault: "ok" | "missing" (no key sent) | "mismatch" (secrets were sealed under another key).
  json vault_status(const std::string& uid, const secrets::Key& vault);
  json vault_reset(const std::string& uid, const secrets::Key& vault);  // forget old sealed secrets

  std::string workspace_for(const std::string& uid, const std::string& session) const;
  bool user_accounts() const { return opt_.user_accounts; }
  agents::Registry& registry() { return reg_; }
  memwal::Store& store() { return store_; }
  PromptPool& prompts(const std::string& uid);

 private:
  std::string build_context(Turn& t, const agents::Agent& agent, const std::string& instruction,
                            const std::vector<memwal::Memory>& facts, const std::vector<memwal::Memory>& episodes,
                            const std::vector<memwal::Memory>& skills, std::vector<memwal::Memory> lessons,
                            const Emit& emit);
  // Memory reads run beside the turn, never in front of it: a slow relayer can't hold a reply hostage.
  struct PendingRecall;
  std::shared_ptr<PendingRecall> recall_async(std::string query, std::string ns, memwal::RecallOptions opt);
  void run_step(Turn& t, Step& s, const std::string& context, const Emit& emit);
  void apply_directives(Turn& t, const Step& s, const Emit& emit);
  json reflect(const Turn& t, int rating, const std::string& comment, const secrets::Key& vault,
               const std::shared_ptr<std::atomic<bool>>& cancelled);
  // One learning signal on a finished turn: scores its prompt version, keeps it as a replay case, reflects.
  json rate(const std::shared_ptr<Turn>& t, int rating, const std::string& comment, bool implicit,
            const secrets::Key& vault, const std::shared_ptr<std::atomic<bool>>& cancelled);
  void rate_later(const std::shared_ptr<Turn>& t, int rating, const std::string& why,
                  const secrets::Key& vault);  // implicit signal
  void evolve_in_background(const std::string& uid, const secrets::Key& vault,
                            const std::shared_ptr<std::atomic<bool>>& cancelled);
  std::shared_ptr<std::atomic<bool>> operation_cancel(const std::string& uid);
  json account_keys();
  bool save_connection(const std::string& uid, const std::string& provider, const json& slot,
                       bool remember, bool api = false, const std::atomic<bool>* cancelled = nullptr);
  bool forget_connection(const std::string& uid, const std::string& provider, bool api = false);
  std::vector<ReplayCase> replay_cases(const std::string& uid);
  std::shared_ptr<Turn> last_turn(const std::string& uid, const std::string& session);
  std::string session_history(const std::string& uid, const std::string& session);
  void seed_user(const std::string& uid);
  std::string github_token(const std::string& uid, const secrets::Key& vault);
  std::string api_key_for(const std::string& uid, const std::string& agent, const secrets::Key& vault);
  // Run git for this user's chat workspace: in their sandbox (user accounts) or on the host.
  proc::Result git(const std::string& uid, const std::string& workspace, const secrets::Key& vault,
                   const std::vector<std::string>& args, const std::string& token = "", int timeout_s = 120);
  proc::Result git_argv(const std::string& uid, const std::string& workspace, const secrets::Key& vault,
                        const std::vector<std::string>& argv, const std::string& token, int timeout_s);
  std::string repo_context(const Turn& t);
  // The user's sandbox when running on their own accounts; nullopt = operator mode.
  std::optional<sandbox::Sandbox> sandbox_for(const std::string& uid, const std::string& workspace,
                                              const secrets::Key& vault, const std::string& provider = "");
  void persist_user_agents(const std::string& uid);
  void record_usage(const std::string& uid, const std::string& agent, const agents::Result& r);
  std::vector<json> recall_records(const std::string& ns, const std::string& kind, const std::string& query,
                                   int limit, bool* failed = nullptr);

  agents::Registry& reg_;
  memwal::Store& store_;
  Options opt_;
  struct Learning {
    PromptPool pool;
    std::once_flag loaded;
    std::atomic<bool> evolving{false};
    Learning(memwal::Store& store, const std::string& uid) : pool(store, ns_user(uid, "learning")) {}
  };
  Learning& learning_for(const std::string& uid);
  std::mutex learning_mu_;
  std::map<std::string, std::unique_ptr<Learning>> learning_;
  mutable std::mutex mu_;
  std::map<std::string, std::shared_ptr<std::atomic<bool>>> active_contexts_;
  std::mutex credentials_mu_;
  json session_keys_ = json::object();  // encrypted session-only connections; never written to disk
  std::map<std::string, std::shared_ptr<Turn>> turns_;  // this process only; Walrus is the record
  void prune_turns();  // caller holds mu_
  struct BgJob {
    std::thread thread;
    std::shared_ptr<std::atomic<bool>> done;
  };
  // Caller holds mu_. Joins only jobs that have already finished, so a job blocked on mu_ is left alone.
  void reap_background_locked();
  bool spawn_locked(std::function<void()> fn);  // false when max_background jobs are still running
  // False when this run would spend the operator's daily budget and that budget is used up.
  bool take_operator_run(const agents::Agent& agent);
  std::vector<BgJob> background_;
  std::string operator_day_;
  int operator_runs_ = 0;
  std::vector<std::future<void>> recalls_;  // in-flight memory reads (pruned as they finish)
  std::map<std::string, std::vector<std::string>> session_turns_;  // "<uid>/<session>" → turn ids, in order

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
    std::atomic<bool> cancel{false};                            // a newer sign-in replaced this one
  };
  std::map<std::string, std::shared_ptr<DeviceLogin>> device_;
  std::map<std::string, std::shared_ptr<DeviceLogin>> gh_device_;  // uid → GitHub device sign-in  // "<uid>/<agent>" → device-code sign-in
};

}  // namespace saga::harness

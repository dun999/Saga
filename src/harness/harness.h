#pragma once
// The Saga harness: memory-grounded context assembly, @mention routing across agents with a shared
// blackboard and one shared knowledge namespace per user.
// Every durable memory, transcript and work checkpoint is a Walrus blob.
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
  int max_background = 32;                 // provider sign-ins and other background work
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
  json recall_sources = json::array();  // recall batches, preserved with the transcript on Walrus
  std::string history;                // the last few exchanges of this chat, for follow-ups
  int rating = 0;            // explicit user rating for this turn
  bool user_rated = false;
  std::atomic<bool> done{false};  // set by the turn's thread, read by the next turn and by feedback
  std::time_t started = 0;
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
// Read one file under `root` the same way: every step opened relative to its parent without following
// links, no hidden (dot) components, a regular file of at most `max_bytes`. nullopt = refused or missing.
std::optional<std::string> read_in_workspace(const std::string& root, const std::string& rel, size_t max_bytes);
std::string memory_protocol(const std::string& uid, const std::string& agent, bool can_run_shell,
                            const std::string& saga_bin, bool native_tools = false, bool read_only = false);

class Harness {
 public:
  Harness(agents::Registry& reg, memwal::Store& store, Options opt);
  ~Harness();  // waits for background work

  void boot(const Emit& log = nullptr);
  std::string chat(const std::string& uid, const std::string& session, const std::string& message,
                   const Emit& emit, const secrets::Key& vault = {});       // returns turn id
  // Only the user who ran a turn can rate or cancel it.
  json feedback(const std::string& uid, const std::string& turn_id, int rating, const std::string& comment,
                const secrets::Key& vault = {});
  bool cancel(const std::string& uid, const std::string& turn_id);
  void cancel_active(const std::string& uid);  // logout: stop this user's live turns and sign-ins
  void end_session(const std::string& uid);  // also discard connections the user did not remember
  // Shared knowledge plus legacy content, with original blob IDs preserved for provenance.
  json memory_view(const std::string& uid, const std::string& query);
  json memory_stats(const std::string& uid);  // {blobs, bytes}: everything this user has on Walrus
  json chat_history(const std::string& uid);
  json chat_transcript(const std::string& uid, const std::string& session);
  // Remove a chat from this server's history; shared memory, archives and files stay intact.
  json delete_chat(const std::string& uid, const std::string& session);
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
  // Username + password sign-in. The first sign-in claims a name that has no memory yet; the Argon2id
  // verifier and the vault salt stay in the 0600 keys file, never in memory. Fills `vault` with the
  // password-derived key that seals this user's credentials. Returns {uid, created} or {error}.
  // After 5 wrong passwords a name waits 30 s, doubling to 15 min, before another check runs (no Argon2
  // work while it waits). `may_create` false refuses to claim a new name.
  json password_login(const std::string& name, const std::string& password, secrets::Key& vault,
                      bool may_create = true);
  // Where a user's connections live: the wallet address or signed-in username, or "<uid>~guest".
  std::string keyring(const std::string& uid, const secrets::Key& vault) const;
  bool keeps_credentials(const std::string& uid, const secrets::Key& vault) const;
  // Vault: "ok" | "missing" (no key sent) | "mismatch" (secrets were sealed under another key).
  json vault_status(const std::string& uid, const secrets::Key& vault);
  json vault_reset(const std::string& uid, const secrets::Key& vault);  // forget old sealed secrets

  std::string workspace_for(const std::string& uid, const std::string& session) const;
  // The page a live preview opens: index.html at the top of the chat's workspace or up to two folders
  // down (a cloned repo, a site/ folder), newest first. "" = nothing to preview yet.
  std::string preview_entry(const std::string& uid, const std::string& session) const;
  bool user_accounts() const { return opt_.user_accounts; }
  agents::Registry& registry() { return reg_; }
  memwal::Store& store() { return store_; }

 private:
  std::string build_context(Turn& t, const agents::Agent& agent,
                            const std::vector<memwal::Memory>& memories, const Emit& emit);
  // Memory reads run beside the turn, never in front of it: a slow relayer can't hold a reply hostage.
  struct PendingRecall;
  std::shared_ptr<PendingRecall> recall_async(std::string query, std::string ns, memwal::RecallOptions opt);
  void run_step(Turn& t, Step& s, const std::function<std::string(const agents::Agent&)>& context_for,
                const Emit& emit);
  void apply_directives(Turn& t, const Step& s, const Emit& emit);
  std::shared_ptr<std::atomic<bool>> operation_cancel(const std::string& uid);
  json account_keys();
  bool save_connection(const std::string& uid, const std::string& provider, const json& slot,
                       bool remember, bool api = false, const std::atomic<bool>* cancelled = nullptr);
  bool forget_connection(const std::string& uid, const std::string& provider, bool api = false);
  std::string session_history(const std::string& uid, const std::string& session);
  std::string deleted_chat_path(const std::string& uid, const std::string& session) const;
  bool chat_deleted(const std::string& uid, const std::string& session) const;
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
  bool take_operator_run(const agents::Agent& agent, const std::string& uid);
  std::vector<BgJob> background_;
  struct LoginFailures {
    int count = 0;
    std::chrono::steady_clock::time_point until{};
  };
  std::mutex login_mu_;
  std::map<std::string, LoginFailures> login_failures_;  // username → wrong passwords in a row
  std::map<std::string, std::pair<std::string, int>> operator_user_runs_;  // uid → (day, built-in runs)
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
  std::map<std::string, std::shared_future<void>> seeding_;  // uid → settings read, done or in flight
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

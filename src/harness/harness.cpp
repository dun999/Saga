#include "harness/harness.h"
#include "core/http.h"
#include "memwal/redact.h"
#include "memwal/gate.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sodium.h>

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <future>
#include <regex>
#include <thread>

#include "core/crypto.h"
#include "core/proc.h"
#include "github/github.h"
#include "router/mentions.h"

namespace saga::harness {
namespace fs = std::filesystem;

namespace {  // keys-file helpers (defined with the agent-account code below)
json read_keys(const std::string& path);
bool update_keys(const std::string& path, const std::function<void(json&)>& edit);
json make_slot(const std::string& value, const secrets::Key& vault,
               const std::string& uid, const std::string& provider);
std::string open_slot(const json& slot, const secrets::Key& vault,
                      const std::string& uid, const std::string& provider);
json read_marker(const std::string& workspace);
}  // namespace

namespace {

std::string today() {
  const std::time_t t = std::time(nullptr);
  std::tm tm{};
  gmtime_r(&t, &tm);
  char b[16];
  std::strftime(b, sizeof b, "%Y-%m-%d", &tm);
  return b;
}

std::string clip(const std::string& s, size_t n) {
  if (s.size() <= n) return s;
  size_t cut = n;
  while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80) --cut;  // UTF-8 boundary
  return s.substr(0, cut) + "…";
}

constexpr size_t kCheckpointBudget = 40'000;  // bytes of file content per checkpoint blob
constexpr size_t kCheckpointFileMax = 16'000;

using Snapshot = std::map<std::string, std::string>;  // relative path -> sha256

// Hash every regular file in the workspace so a step's changes can be checkpointed to Walrus.
Snapshot snapshot(const std::string& root) {
  Snapshot snap;
  std::error_code ec;
  if (!fs::exists(root, ec)) return snap;
  for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
       it != fs::recursive_directory_iterator(); it.increment(ec)) {
    if (ec) break;
    const std::string name = it->path().filename().string();
    if (it->is_directory() && (name == ".git" || name == "node_modules" || name == "target" || name == ".venv")) {
      it.disable_recursion_pending();
      continue;
    }
    // A symlink is never followed: an agent could point one at a host file its sandbox can't see.
    if (it->is_symlink() || !it->is_regular_file() || it->file_size(ec) > 1'000'000) continue;
    std::ifstream in(it->path(), std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    snap[it->path().lexically_relative(root).string()] = crypto::sha256_hex(ss.str());
  }
  return snap;
}

std::string read_file(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// A restorable path stays inside the workspace.
bool safe_relative(const std::string& rel) {
  if (rel.empty() || rel[0] == '/' || rel.find('\0') != std::string::npos) return false;
  for (const auto& part : fs::path(rel))
    if (part == "..") return false;
  return true;
}

constexpr size_t kMemoryContextBytes = 400;

json memories_json(const std::vector<memwal::Memory>& ms, size_t text_limit = 300) {
  json arr = json::array();
  for (auto& m : ms) {
    json item = {{"text", clip(m.text, text_limit)}, {"distance", m.distance}, {"blob_id", m.blob_id},
                 {"text_truncated", m.text.size() > text_limit}};
    if (!m.namespace_.empty()) item["namespace"] = m.namespace_;
    if (!m.kind.empty()) item["kind"] = m.kind;
    if (!m.agent.empty()) item["agent"] = m.agent;
    if (!m.id.empty()) item["id"] = m.id;
    item["status"] = m.status;
    if (m.local || m.distance > 0.75) item["background"] = true;
    if (m.local) { item["local"] = true; item["distance"] = nullptr; }
    if (m.score) item["score"] = *m.score;
    if (!m.created_at.empty()) item["created_at"] = m.created_at;
    arr.push_back(std::move(item));
  }
  return arr;
}

// Persist the same excerpts sent to the model, rather than re-running a search when a chat is opened.
// Batches preserve the actual query and distinguish an empty match from a failed read.
void record_recall(Turn& t, const std::string& ns, const std::string& query,
                   const std::vector<memwal::Memory>& memories, bool failed, const Emit& emit,
                   const std::string& agent = "", int step = -1, const std::vector<memwal::Memory>& background = {}) {
  json items = memories_json(memories, kMemoryContextBytes);
  for (auto item : memories_json(background, kMemoryContextBytes)) {  // given as context, not matched to the query
    item["background"] = true;
    items.push_back(std::move(item));
  }
  json batch = {{"ns", ns}, {"query", clip(query, 400)}, {"query_truncated", query.size() > 400},
                {"status", failed ? "unavailable" : "ok"}, {"items", items}};
  if (!agent.empty()) batch["agent"] = agent;
  if (step >= 0) batch["step"] = step;
  t.recall_sources.push_back(batch);
  if (emit) {
    batch["type"] = "recall";
    emit(batch);
  }
}

bool is_capacity_error(const std::string& e) {
  static const std::regex re("usage limit|balance exhausted|402|429|rate.?limit|quota|not supported|"
                             "not found on PATH|not set|unauthori[sz]ed|401|connect to server|resolve host|limit reached|not connected",
                             std::regex::icase);
  return std::regex_search(e, re);
}

}  // namespace

json model_options(const std::string& kind);

// Restore runs on the host, outside the sandbox, into a directory agents control. Every step is
// opened relative to its parent with O_NOFOLLOW, so a symlink an agent planted (or swaps in mid-way)
// can't redirect the write, and a hard-linked file is refused rather than truncated.
bool write_in_workspace(const std::string& root, const std::string& rel, const std::string& content) {
  if (!safe_relative(rel)) return false;
  std::vector<std::string> parts;
  for (const auto& part : fs::path(rel))
    if (!part.empty() && part != ".") parts.push_back(part.string());
  if (parts.empty()) return false;
  int dir = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  for (size_t i = 0; dir >= 0 && i + 1 < parts.size(); ++i) {
    ::mkdirat(dir, parts[i].c_str(), 0755);  // EEXIST is fine; openat decides
    const int next = ::openat(dir, parts[i].c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    ::close(dir);
    dir = next;
  }
  if (dir < 0) return false;
  bool ok = false;
  const int fd = ::openat(dir, parts.back().c_str(), O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0644);
  ::close(dir);
  if (fd < 0) return false;
  struct stat st{};
  if (::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1 && ::ftruncate(fd, 0) == 0) {
    ok = true;
    for (size_t off = 0; ok && off < content.size();) {
      const ssize_t n = ::write(fd, content.data() + off, content.size() - off);
      if (n <= 0) ok = false;
      else off += static_cast<size_t>(n);
    }
  }
  ::close(fd);
  return ok;
}

std::optional<std::string> read_in_workspace(const std::string& root, const std::string& rel, size_t max_bytes) {
  if (!safe_relative(rel)) return std::nullopt;
  std::vector<std::string> parts;
  for (const auto& part : fs::path(rel))
    if (!part.empty() && part != ".") parts.push_back(part.string());
  if (parts.empty()) return std::nullopt;
  for (auto& p : parts)
    if (p.starts_with(".")) return std::nullopt;  // .git, .env, editor state: never served
  int dir = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  for (size_t i = 0; dir >= 0 && i + 1 < parts.size(); ++i) {
    const int next = ::openat(dir, parts[i].c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    ::close(dir);
    dir = next;
  }
  if (dir < 0) return std::nullopt;
  const int fd = ::openat(dir, parts.back().c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  ::close(dir);
  if (fd < 0) return std::nullopt;
  std::optional<std::string> out;
  struct stat st{};
  if (::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && static_cast<size_t>(st.st_size) <= max_bytes) {
    std::string body(static_cast<size_t>(st.st_size), '\0');
    size_t off = 0;
    while (off < body.size()) {
      const ssize_t n = ::read(fd, body.data() + off, body.size() - off);
      if (n <= 0) break;
      off += static_cast<size_t>(n);
    }
    body.resize(off);
    out = std::move(body);
  }
  ::close(fd);
  return out;
}

std::string ns_user(const std::string& uid, const char* what) { return memwal::user_namespace(uid, what); }
std::string ns_lessons(const std::string& agent, const std::string& uid) {
  return ns_user(uid, "lessons") + ":" + agent;
}

// Injected into every agent's context: what Saga's memory is and how to use it.
std::string memory_protocol(const std::string& uid, const std::string& agent, bool can_run_shell,
                            const std::string& saga_bin, bool native_tools, bool read_only) {
  (void)agent;
  const auto shared = memwal::shared_namespace(uid);
  std::string p = "\n## Shared memory — Walrus mainnet\n"
      "Every teammate reads the same knowledge namespace: " + shared + ". It contains useful facts, "
      "decisions, user corrections, procedures and handoffs. Records retain their author and session. "
      "Confirmed memories are encrypted Walrus blobs under this deployment's MemWal account. "
      "Older facts, episodes, skills and agent lessons are included automatically, with their original blob IDs.\n"
      "New memories are immediately available to teammates while storage completes in the background. "
      "A queued or running memory has not yet been confirmed on Walrus; only a returned blob ID confirms storage.\n"
      "Transcripts and eligible checkpoints are saved automatically in " + ns_user(uid, "chat") + " and " +
      ns_user(uid, "checkpoints") + ". These archives are separate from knowledge retrieval.\n"
      "To propose a NEW durable fact grounded in the user or verified observations, write one line:\n"
      "#remember <one self-contained fact, including its project and uncertainty where relevant>\n"
      "Check the supplied knowledge for an equivalent first. For a correction, say what it supersedes. "
      "Do not duplicate transcripts or save drafts. Never store credentials, access tokens, keys or passwords.\n";
  if (native_tools)
    p += "Use memory_recall for missing past context (default namespace " + shared + "). " +
         (read_only ? std::string("Use #remember for new facts.\n") :
                      std::string("memory_remember queues a fact through the same capture path as #remember.\n"));
  else if (can_run_shell && !saga_bin.empty())
    p += "Search memory from the shell:\n  " + saga_bin + " mem recall \"<query>\" [--limit N]\n" +
         (read_only ? "" : "  " + saga_bin + " mem remember \"<fact>\"\n") +
         "The default namespace is " + shared + ".\n";
  if (native_tools || (can_run_shell && !saga_bin.empty()))
    p += "If a handoff lacks history details, recall the original transcript in " + ns_user(uid, "chat") +
         " using its project, teammate and date as query terms. Searching history does not require running git.\n";
  if (read_only)
    p += "This run can read only this user's content (at most eight searches). "
         "Propose writes with #remember.\n";
  return p;
}

Harness::Harness(agents::Registry& reg, memwal::Store& store, Options opt)
    : reg_(reg), store_(store), opt_(std::move(opt)) {
  store_.legacy_agents(reg_.names());
}

Harness::~Harness() {
  // Drain provider sign-ins and other outstanding background work.
  for (;;) {
    std::vector<BgJob> bg;
    {
      std::lock_guard lk(mu_);
      bg.swap(background_);
    }
    if (bg.empty()) break;
    for (auto& j : bg)
      if (j.thread.joinable()) j.thread.join();
  }
}

void Harness::reap_background_locked() {
  for (auto it = background_.begin(); it != background_.end();) {
    if (!it->done || !it->done->load()) {
      ++it;
      continue;
    }
    if (it->thread.joinable()) it->thread.join();
    it = background_.erase(it);
  }
}

bool Harness::spawn_locked(std::function<void()> fn) {
  reap_background_locked();
  if (static_cast<int>(background_.size()) >= std::max(opt_.max_background, 1)) return false;
  auto done = std::make_shared<std::atomic<bool>>(false);
  background_.push_back(BgJob{std::thread([fn = std::move(fn), done]() mutable {
                                 try {
                                   fn();
                                 } catch (const std::exception&) {
                                   std::fprintf(stderr, "[background] operation failed\n");
                                 } catch (...) {
                                   std::fprintf(stderr, "[background] unknown error\n");
                                 }
                                 done->store(true);
                               }),
                               done});
  return true;
}

bool Harness::take_operator_run(const agents::Agent& agent, const std::string& uid) {
  // Empty owner is a built-in. In host mode every built-in spends the operator's login. In user
  // mode only a built-in with an operator API key does — a user's sandbox login is their own bill.
  if (!agent.spec().owner.empty()) return true;
  if (opt_.user_accounts && agent.spec().api_key_env.empty()) return true;
  if (opt_.operator_daily_runs <= 0) return true;
  std::lock_guard lk(mu_);
  const std::string day = today();
  if (operator_day_ != day) {
    operator_day_ = day;
    operator_runs_ = 0;
  }
  if (operator_runs_ >= opt_.operator_daily_runs) return false;
  // On a shared Saga, accounts are cheap to make: one of them may spend a tenth of the day's budget.
  if (opt_.user_accounts) {
    auto& [user_day, runs] = operator_user_runs_[uid];
    if (user_day != day) user_day = day, runs = 0;
    if (runs >= std::max(10, opt_.operator_daily_runs / 10)) return false;
    ++runs;
    if (operator_user_runs_.size() > 10000) std::erase_if(operator_user_runs_, [&](auto& e) { return e.second.first != day; });
  }
  ++operator_runs_;
  return true;
}

void Harness::boot(const Emit& log) {
  auto say = [&](const std::string& m) {
    if (log) log({{"type", "log"}, {"text", m}});
  };
  // Keep as little about connections as possible. Older versions left key hints in the keys file and
  // CLI transcripts in agent homes; nothing runs yet, so both can go now.
  if (fs::exists(opt_.keys_path))
    update_keys(opt_.keys_path, [](json& keys) {
      std::function<void(json&)> drop = [&](json& j) {
        if (!j.is_object()) return;
        j.erase("hint");
        for (auto& [k, v] : j.items()) drop(v);
      };
      drop(keys);
    });
  if (opt_.user_accounts) {
    std::error_code ec;
    for (auto it = fs::directory_iterator(opt_.homes_dir, ec); !ec && it != fs::directory_iterator(); it.increment(ec))
      if (fs::is_directory(fs::symlink_status(it->path(), ec))) sandbox::scrub_home(it->path().string(), true);
  }
  say("each user has one shared knowledge namespace");
}

std::string Harness::build_context(Turn& t, const agents::Agent& agent,
                                   const std::vector<memwal::Memory>& memories, const Emit& emit) {
  std::string c = std::string(kSeedPrompt) + "\n\n";
  // Without it a model can't answer "how many weeks until …" and guesses from its training data.
  c += "## Today\nToday is " + today() + " (UTC).\n\n";
  // Identity: the base prompt speaks as Saga. Only the primary agent *is* Saga; a mentioned teammate
  // answers as itself, so "@claude who are you?" gets Claude Code, not Saga.
  if (&agent == reg_.primary())
    c += "## Who you are\nYou are Saga, the assistant the user is talking to. If asked what model or company is "
         "behind you, say you are Saga; don't name an underlying model or provider.\n\n";
  else
    c += "## Who you are\nYou are @" + agent.name() + " (" + agent.spec().description + "), one agent on the Saga "
         "team. In the prompt above, \"Saga\" is the product you work inside, not you: if asked who you are, say you "
         "are @" + agent.name() + " working in Saga.\n\n";
  c += "## Team\nYou are @" + agent.name() + " in a Saga team working for one user. Teammates:";
  for (auto& r : reg_.roster(t.uid))
    if (r["name"] != agent.name() && r["unavailable"].get<std::string>().empty())
      c += " @" + r["name"].get<std::string>() + " (" + r["description"].get<std::string>() +
           (r.value("edits_files", false) ? "; reads, edits and runs code in the workspace" : "") + ");";
  c += "\nTo hand part of the work to a teammate, write a line on its own: `@name <precise instruction>`. "
       "Only do this when it clearly helps; otherwise finish the work yourself.\n";
  if (agent.can_edit_files()) {
    c += "Shared workspace (every teammate sees the same files): " +
         (opt_.user_accounts ? std::string(sandbox::kWork) : t.workspace) + "\n";
    c += "For a requested static page or browser game, create the actual files in the shared workspace, "
         "including index.html at the workspace root or at most two directories below it. Saga discovers "
         "that file and opens its HTML, CSS, JavaScript and assets in the user's Preview panel. A running "
         "development server or an agent browser tool is not required for this static preview. Report the "
         "saved entry path; code pasted into the chat alone cannot open a preview.\n";
  } else
    c += "You cannot read or edit files, see the repository, or run commands. When the user wants something built, "
         "changed or checked in their workspace or repository, hand it to a teammate who works in the workspace "
         "(`@name <precise instruction>` on its own line) instead of saying you will do it yourself. Otherwise put "
         "any code inline in fenced blocks.\n";

  auto section = [&](const char* title, const std::vector<memwal::Memory>& ms) {
    if (ms.empty()) return;
    c += "\n## " + std::string(title) + "\n";
    for (auto& m : ms) c += "- " + clip(m.text, kMemoryContextBytes) +
        (m.status == "done" ? "" : " [" + m.status + "; not yet confirmed on Walrus]") + "\n";
  };
  std::vector<memwal::Memory> relevant, background;
  for (const auto& m : memories)
    (m.local || m.distance > 0.75 ? background : relevant).push_back(m);
  section("Shared knowledge for this user (Walrus Memory)", relevant);
  section("Other shared knowledge (recent or weakly matched hints)", background);
  std::vector<memwal::Memory> fresh;
  for (auto& m : store_.local_memories(memwal::shared_namespace(t.uid))) {
    if (fresh.size() == 8) break;
    if (std::none_of(memories.begin(), memories.end(), [&](const auto& known) { return known.id == m.id; }))
      fresh.push_back(std::move(m));
  }
  section("New shared knowledge this session (queued writes are not yet confirmed on Walrus)", fresh);
  if (!fresh.empty()) {
    for (const auto& m : fresh) t.recalled.push_back(m.text);
    record_recall(t, memwal::shared_namespace(t.uid), "New shared memory this session", fresh, false, emit,
                  agent.name(), static_cast<int>(t.steps.size()) - 1);
  }
  c += t.history;
  c += repo_context(t);
  // Sandboxed agents query a per-run, user-scoped gate; the delegate key stays on the server.
  const bool memory_access = store_.enabled() && agent.can_edit_files() && !opt_.saga_bin.empty();
  if (store_.enabled()) c += memory_protocol(t.uid, agent.name(), memory_access,
                       opt_.user_accounts ? "/mnt/bin/saga" : opt_.saga_bin,
                       memory_access && (opt_.user_accounts || !opt_.mem_sock.empty()) &&
                           agent.spec().kind == "claude-code", opt_.user_accounts && memory_access);
  else c += "\n## Memory availability\nMemory is disabled for this run. No Walrus recall or memory tools "
            "are available, and transcripts, episodes, facts and checkpoints are not saved to Walrus. "
            "Work from this conversation and the available workspace. Do not claim anything was recalled, "
            "queued or saved to memory, and do not emit #remember directives.\n";

  if (!t.steps.empty()) {
    c += "\n## Blackboard — work already done in this task\n";
    for (auto& s : t.steps) {
      if (s.output.empty() && s.error.empty()) continue;
      c += "### @" + s.agent + ": " + clip(s.instruction, 200) + "\n" +
           (s.error.empty() ? clip(s.output, 1500) : "FAILED: " + clip(s.error, 300)) + "\n";
    }
  }
  return c;
}

void Harness::run_step(Turn& t, Step& s,
                       const std::function<std::string(const agents::Agent&)>& context_for, const Emit& emit) {
  agents::Agent* agent = reg_.find(s.agent, t.uid);
  const size_t idx = &s - t.steps.data();
  // Gate on availability, the user's own sign-in and the provider's usage windows, then record
  // what actually ran.
  auto attempt = [&](agents::Agent* a) {
    agents::Result res;
    if (t.cancel->load() || (t.session_cancel && t.session_cancel->load())) {
      res.error = "cancelled";
      return res;
    }
    std::string why = a ? a->unavailable_reason() : "unknown agent";
    auto sb = a ? sandbox_for(t.uid, t.workspace, t.vault, a->spec().kind)
                      : std::optional<sandbox::Sandbox>{};
    if (sb) sb->sensitive = t.sensitive;
    if (sb) sb->cancel = t.session_cancel;
    const sandbox::Sandbox* sbp = sb ? &*sb : nullptr;
    if (why.empty() && sbp && !a->account(sbp).value("connected", false))
      why = "@" + a->name() + " is not connected — connect your account in Agents";
    if (why.empty()) a->exhausted(sbp, &why);
    if (!why.empty()) {
      res.error = why;
      return res;
    }
    if (a && !take_operator_run(*a, t.uid)) {
      res.error = "today's budget for the built-in assistant is used up; add your own agent with + to keep going";
      return res;
    }
    std::string working_dir = sbp ? sandbox::kWork : t.workspace;
    if (a->spec().kind == "grok-cli") {
      const json repo = read_marker(t.workspace);
      if (repo.is_object()) {
        const std::string dir = repo.value("dir", "");
        const fs::path path = fs::path(t.workspace) / dir;
        std::error_code ec;
        if (fs::is_directory(fs::symlink_status(path, ec)) &&
            fs::is_directory(fs::symlink_status(path / ".git", ec)))
          working_dir = sbp ? std::string(sandbox::kWork) + "/" + dir : path.string();
      }
    }
    agents::Task task{s.instruction, context_for(*a), working_dir, t.cancel.get(),
                      opt_.agent_timeout_s, {}, sbp};
    std::mutex recall_mu;
    std::unique_ptr<memwal::Gate> memory_gate;
    if (sb && a->can_edit_files() && store_.enabled() && !sb->runner.empty()) {
      memory_gate = std::make_unique<memwal::Gate>(*store_.client(), &store_, t.uid,
          [&](const json& req, const json& reply) {
            std::vector<memwal::Memory> hits;
            for (const auto& m : reply.value("hits", json::array()))
              {
                memwal::Memory hit{m.value("blob_id", ""), m.value("text", ""),
                    m.contains("distance") && m["distance"].is_number() ? m["distance"].get<double>() : 0.0};
                hit.namespace_ = m.value("namespace", "");
                hit.kind = m.value("kind", "");
                hit.agent = m.value("agent", "");
                hit.id = m.value("id", "");
                hit.status = m.value("status", "done");
                hit.local = m.value("local", false);
                hits.push_back(std::move(hit));
              }
            std::lock_guard lk(recall_mu);
            for (const auto& m : hits) t.recalled.push_back(m.text);
            record_recall(t, req.value("ns", ""), req.value("text", ""), hits,
                          !reply.value("ok", false), emit, a->name(), static_cast<int>(idx));
          });
      sb->memory_sock = memory_gate->path();
      task.env = {{"SAGA_UID", t.uid}, {"SAGA_BIN", "/mnt/bin/saga"},
                  {"SAGA_MEM_SOCK", sandbox::kMemorySock}, {"SAGA_MEM_READ_ONLY", "1"},
                  {"SAGA_AGENT", a->name()}, {"SAGA_SESSION", t.session}};
      for (const auto& [key, value] : task.env) sb->env[key] = value;
    }
    if (!sbp && store_.enabled()) {
      task.env = {{"SAGA_UID", t.uid}, {"SAGA_BIN", opt_.saga_bin},
                  {"SAGA_AGENT", a->name()}, {"SAGA_SESSION", t.session}};
      if (!opt_.mem_sock.empty()) task.env["SAGA_MEM_SOCK"] = opt_.mem_sock;
    }
    task.model = model_pick(t.uid, a->name());
    task.sensitive = t.sensitive;
    if (!a->spec().owner.empty())
      task.api_key = api_key_for(t.uid, a->name(), t.vault);
    if (t.cancel->load()) { res.error = "cancelled"; return res; }
    res = a->run(task, [&](const agents::Event& e) {
      if (emit) emit({{"type", "agent"}, {"step", idx}, {"agent", a->name()},
                      {"kind", e.type}, {"text", clip(e.text, 4000)}});
    });
    if (!task.api_key.empty()) sodium_memzero(task.api_key.data(), task.api_key.size());
    record_usage(t.uid, a->name(), res);
    return res;
  };
  agents::Result r = attempt(agent);

  // Capacity failure on a teammate → hand the work to the primary so the user still gets a result.
  agents::Agent* primary = reg_.primary();
  if (!r.ok && primary && agent != primary && !t.cancel->load() && is_capacity_error(r.error)) {
    if (emit)
      emit({{"type", "fallback"}, {"step", idx}, {"from", s.agent}, {"to", primary->name()}, {"reason", clip(r.error, 200)}});
    s.fallback = true;
    s.agent = primary->name();
    r = attempt(primary);
  }
  s.output = r.text;
  s.error = r.error;
  s.seconds = r.seconds;
  s.tools = r.tools_used;
}

struct Harness::PendingRecall {
  std::mutex mu;
  std::condition_variable cv;
  bool done = false;
  bool failed = false;
  std::string query;
  std::vector<memwal::Memory> hits;
};

std::shared_ptr<Harness::PendingRecall> Harness::recall_async(std::string query, std::string ns,
                                                             memwal::RecallOptions opt) {
  auto r = std::make_shared<PendingRecall>();
  r->query = query;
  auto f = std::async(std::launch::async, [this, r, query = std::move(query), ns = std::move(ns), opt] {
    std::vector<memwal::Memory> hits;
    bool failed = false;
    try {
      hits = store_.recall(query, ns, opt, &failed);
    } catch (...) {
      failed = true;
    }
    std::lock_guard lk(r->mu);
    r->hits = std::move(hits);
    r->failed = failed;
    r->done = true;
    r->cv.notify_all();
  });
  std::lock_guard lk(mu_);
  std::erase_if(recalls_, [](auto& x) { return x.wait_for(std::chrono::seconds(0)) == std::future_status::ready; });
  recalls_.push_back(std::move(f));
  return r;
}

std::string Harness::chat(const std::string& uid, const std::string& session, const std::string& message,
                          const Emit& emit, const secrets::Key& vault) {
  // `saga serve --trace` prints where each turn spends its time (stderr).
  const bool tracing = opt_.trace;
  const auto t0 = std::chrono::steady_clock::now();
  auto trace = [&](const std::string& what) {
    if (tracing)
      std::fprintf(stderr, "[trace %s] %6.2fs %s\n", session.c_str(),
                   std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count(), what.c_str());
  };
  auto t = std::make_shared<Turn>();
  t->vault = vault;
  t->sensitive = std::make_shared<memwal::SecretScope>();
  // A turn that ends early (a read that must not be skipped failed) still ends: prune_turns() only
  // drops finished turns.
  struct ClearTurnVault {
    std::shared_ptr<Turn> turn;
    ~ClearTurnVault() { secrets::clear(turn->vault); turn->sensitive.reset(); turn->done = true; }
  } clear_vault{t};
  t->id = crypto::uuid4();
  t->uid = uid;
  const auto session_cancel = operation_cancel(uid);
  t->session_cancel = session_cancel;
  t->session = session;
  t->message = message;
  t->started = std::time(nullptr);
  {
    // Register before starting reads so deletion cannot race a new turn into this session.
    std::lock_guard lk(mu_);
    if (chat_deleted(uid, session)) throw std::runtime_error("This chat was deleted. Start a new chat.");
    prune_turns();
    turns_[t->id] = t;
    session_turns_[uid + "/" + session].push_back(t->id);
  }
  t->workspace = workspace_for(uid, session);
  fs::create_directories(t->workspace);

  // One knowledge search for the whole team. Legacy namespaces are read by the store only when
  // they exist; prompts are fixed and never require a learning-state read.
  auto memory_r = recall_async(message, memwal::shared_namespace(uid), {.limit = 12, .recency_weight = 0.2});
  auto seed_f = std::async(std::launch::async, [this, uid] { seed_user(uid); });
  auto history_f = std::async(std::launch::async, [this, uid, session] { return session_history(uid, session); });
  auto await = [](const std::shared_ptr<PendingRecall>& r) {
    std::unique_lock lk(r->mu);
    r->cv.wait(lk, [&] { return r->done; });
    return r->hits;
  };
  // Route: split @mentions into an ordered plan; agents can extend it with their own @handoffs.
  auto plan_queue = [&](const std::vector<std::string>& names) {
    std::vector<router::Segment> plan = router::split_mentions(message, names);
    if (plan.empty()) plan.push_back({"", message});
    std::vector<std::pair<router::Segment, std::string>> queue;  // segment, requested_by
    for (auto& seg : plan) {
      if (seg.agent.empty()) seg.agent = reg_.primary()->name();
      const bool dup = std::any_of(queue.begin(), queue.end(), [&](auto& q) {
        return q.first.agent == seg.agent && q.first.instruction == seg.instruction;
      });
      if (!dup) queue.push_back({seg, "user"});  // "@saga @saga hi" runs once
    }
    return queue;
  };
  if (emit) emit({{"type", "turn"}, {"turn_id", t->id}, {"workspace", t->workspace}, {"memory_enabled", store_.enabled()}});
  trace("turn started, reads in flight");

  t->prompt_version = kFoundationRevision;
  seed_f.get();
  t->history = history_f.get();
  const auto names = reg_.names(uid);
  store_.legacy_agents(names);
  auto queue = plan_queue(names);
  const auto memories = await(memory_r);
  for (const auto& m : memories) t->recalled.push_back(m.text);
  if (store_.enabled())
    record_recall(*t, memwal::shared_namespace(uid), message, memories, memory_r->failed, emit);
  trace("shared knowledge, settings and chat history ready");

  t->steps.reserve(opt_.max_steps);
  for (size_t qi = 0; qi < queue.size() && static_cast<int>(t->steps.size()) < opt_.max_steps; ++qi) {
    if (t->cancel->load()) break;
    auto [seg, by] = queue[qi];
    Step& s = t->steps.emplace_back();
    s.agent = seg.agent.empty() ? reg_.primary()->name() : seg.agent;
    s.instruction = seg.instruction;
    s.requested_by = by;
    const size_t idx = t->steps.size() - 1;
    if (emit)
      emit({{"type", "step"}, {"step", idx}, {"agent", s.agent}, {"instruction", s.instruction}, {"requested_by", by}});

    auto context_for = [&](const agents::Agent& target) {
      return build_context(*t, target, memories, emit);
    };
    const Snapshot before = snapshot(t->workspace);
    trace("@" + s.agent + " running");
    run_step(*t, s, context_for, emit);
    trace("@" + s.agent + " finished");

    // Checkpoint: every file this step created or changed goes to Walrus, restorable later.
    const Snapshot after = snapshot(t->workspace);
    json files = json::array();
    size_t budget = kCheckpointBudget;
    for (auto& [path, sha] : after) {
      auto it = before.find(path);
      if (it != before.end() && it->second == sha) continue;
      const std::string body = read_file(fs::path(t->workspace) / path);
      json f = {{"path", path}, {"sha256", sha}, {"bytes", body.size()}};
      const bool text = body.find('\0') == std::string::npos;
      if (text && body.size() <= kCheckpointFileMax && body.size() <= budget) {
        f["content"] = body;
        budget -= body.size();
      }
      files.push_back(f);
    }
    if (!files.empty()) {
      s.files = files;
      store_.put(ns_user(uid, "checkpoints"), "checkpoint",
                 memwal::encode_record("checkpoint", {{"session", session}, {"turn", t->id}, {"step", idx},
                                                      {"agent", s.agent}, {"ts", std::time(nullptr)},
                                                      {"instruction", clip(s.instruction, 300)}, {"files", files}}),
                 t->id + ":" + std::to_string(idx));
      json names = json::array();
      for (auto& f : files) names.push_back({{"path", f["path"]}, {"bytes", f["bytes"]}, {"saved", f.contains("content")}});
      if (emit) emit({{"type", "checkpoint"}, {"step", idx}, {"agent", s.agent}, {"files", names}});
    }
    apply_directives(*t, s, emit);
    if (emit)
      emit({{"type", "step_done"}, {"step", idx}, {"agent", s.agent}, {"ok", s.error.empty()}, {"error", s.error},
            {"seconds", s.seconds}, {"output", clip(s.output, 20000)}, {"fallback", s.fallback}});

    for (auto& h : router::find_handoffs(s.output, names)) {
      const bool dup = std::any_of(queue.begin(), queue.end(), [&](auto& q) {
        return q.first.agent == h.agent && q.first.instruction == h.instruction;
      });
      if (!dup && h.agent != s.agent) {
        queue.push_back({h, s.agent});
      }
    }
  }

  // Episode memory: what happened, compactly, for future continuity. A cancelled turn is in the
  // transcript; as an episode it would only be recalled as noise.
  if (!t->cancel->load() && !t->steps.empty()) {
    std::string ep = "Episode " + today() + ": user asked \"" + clip(memwal::redact_secrets(message), 240) + "\". ";
    for (auto& s : t->steps)
      ep += "@" + s.agent + (s.fallback ? " (fallback)" : "") + (s.error.empty() ? " did: " : " failed: ") +
            clip(s.error.empty() ? s.output : s.error, 220) + " ";
    store_.remember(uid, memwal::redact_secrets(ep), "episode", "", session, t->id);
  }

  const std::string final_text = t->steps.empty() ? "" : t->steps.back().output;

  // Transcript: the conversation itself lives on Walrus, so history survives any restart or machine.
  json steps = json::array();
  for (auto& s : t->steps) {
    const std::string output = memwal::redact_secrets(s.output);
    steps.push_back({{"agent", s.agent}, {"instruction", clip(memwal::redact_secrets(s.instruction), 400)},
                     {"requested_by", s.requested_by}, {"fallback", s.fallback}, {"ok", s.error.empty()},
                     {"output", clip(output, 6000)}, {"output_truncated", output.size() > 6000},
                     {"error", s.error}});
  }
  const std::string user_message = memwal::redact_secrets(message);
  store_.put(ns_user(uid, "chat"), "chat",
             memwal::encode_record("chat", {{"session", session}, {"turn", t->id}, {"ts", std::time(nullptr)},
                                            {"user", clip(user_message, 4000)}, {"user_truncated", user_message.size() > 4000},
                                            {"steps", steps},
                                            {"prompt_version", t->prompt_version},
                                            {"memory_enabled", store_.enabled()}, {"recall_sources", t->recall_sources}}),
             t->id);

  t->done = true;
  if (emit) emit({{"type", "done"}, {"turn_id", t->id}, {"prompt_version", t->prompt_version}, {"final", clip(final_text, 20000)}});
  return t->id;
}

json Harness::feedback(const std::string& uid, const std::string& turn_id, int rating,
                       const std::string& comment, const secrets::Key& vault) {
  (void)vault;
  if (rating != 1 && rating != -1) return {{"error", "rating must be 1 or -1"}};
  if (comment.size() > 4096) return {{"error", "comment must be at most 4096 bytes"}};
  std::shared_ptr<Turn> t;
  {
    std::lock_guard lk(mu_);
    auto it = turns_.find(turn_id);
    if (it == turns_.end() || it->second->uid != uid) return {{"error", "unknown turn"}};
    t = it->second;
    if (!t->done) return {{"error", "wait for the turn to finish"}};
    if (t->user_rated) return {{"error", "already rated"}};
    t->rating = rating;
    t->user_rated = true;
  }
  json out = {{"rating", rating}, {"saved", false}};
  if (!comment.empty()) {
    const std::string correction = "User feedback on \"" + clip(memwal::redact_secrets(t->message), 180) +
                                   "\": " + comment;
    auto saved = store_.remember(uid, correction, "correction", "", t->session, t->id);
    out["saved"] = saved.value("ok", false);
    out["memory_status"] = saved.value("status", "not stored");
    if (!saved.value("ok", false)) out["memory_error"] = saved.value("error", "not stored");
  }
  return out;
}

// Finished turns stay in memory for a while so they can be rated and followed up; after that the
// transcript on Walrus is the only copy (session_history falls back to it).
void Harness::prune_turns() {
  constexpr std::time_t kKeep = 12 * 3600;
  const std::time_t cutoff = std::time(nullptr) - kKeep;
  std::erase_if(turns_, [&](const auto& kv) { return kv.second->done && kv.second->started < cutoff; });
  for (auto it = session_turns_.begin(); it != session_turns_.end();) {
    std::erase_if(it->second, [&](const std::string& id) { return !turns_.contains(id); });
    it = it->second.empty() ? session_turns_.erase(it) : std::next(it);
  }
}

std::string Harness::session_history(const std::string& uid, const std::string& session) {
  constexpr size_t kTurns = 4;
  std::vector<std::pair<std::string, std::string>> ex;  // user message, final answer
  auto answer = [](const std::string& agent, const std::string& output, const std::string& error) {
    return agent + ": " + (error.empty() ? "" : "[Failed: " + clip(error, 240) + "] ") + output;
  };
  {
    std::lock_guard lk(mu_);
    if (auto it = session_turns_.find(uid + "/" + session); it != session_turns_.end())
      for (auto& id : it->second)
        if (auto t = turns_.find(id); t != turns_.end() && t->second->done && !t->second->steps.empty())
          ex.push_back({t->second->message, answer(t->second->steps.back().agent, t->second->steps.back().output,
                                                 t->second->steps.back().error)});
  }
  if (ex.empty()) {  // a chat reopened after a restart: its transcript is on Walrus
    for (auto& r : chat_transcript(uid, session)["turns"]) {
      const json steps = r.value("steps", json::array());
      if (!steps.empty()) {
        const auto& step = steps.back();
        ex.push_back({r.value("user", ""), answer(step.value("agent", ""), step.value("output", ""),
                       step.value("ok", true) ? "" : step.value("error", "run failed"))});
      }
    }
  }
  if (ex.empty()) return "";
  std::string h = "\n## Previous conversation turns (context, not pending tasks)\n";
  for (size_t i = ex.size() > kTurns ? ex.size() - kTurns : 0; i < ex.size(); ++i)
    h += "User: " + clip(memwal::redact_secrets(ex[i].first), 600) + "\n@" + clip(ex[i].second, 1200) + "\n";
  return h;
}

bool Harness::cancel(const std::string& uid, const std::string& turn_id) {
  std::lock_guard lk(mu_);
  auto it = turns_.find(turn_id);
  if (it == turns_.end() || it->second->uid != uid) return false;
  it->second->cancel->store(true);
  return true;
}

void Harness::cancel_active(const std::string& uid) {
  std::lock_guard lk(mu_);
  if (auto it = active_contexts_.find(uid); it != active_contexts_.end()) {
    it->second->store(true);
    active_contexts_.erase(it);
  }
  for (auto& [_, turn] : turns_)
    if (turn->uid == uid) turn->cancel->store(true);
  const std::string prefix = uid + "/";
  for (auto& [name, login] : device_)
    if (name.starts_with(prefix)) { login->cancel = true; login->status = "failed"; login->error = "sign-in was cancelled"; }
  if (auto it = gh_device_.find(uid); it != gh_device_.end()) {
    it->second->cancel = true;
    it->second->status = "failed";
    it->second->error = "sign-in was cancelled";
  }
}

std::shared_ptr<std::atomic<bool>> Harness::operation_cancel(const std::string& uid) {
  std::lock_guard lk(mu_);
  auto& flag = active_contexts_[uid];
  if (!flag) flag = std::make_shared<std::atomic<bool>>(false);
  return flag;
}

void Harness::end_session(const std::string& uid) {
  cancel_active(uid);
  {
    std::lock_guard lk(mu_);
    std::erase_if(device_, [&](const auto& item) { return item.first.starts_with(uid + "/"); });
    gh_device_.erase(uid);
  }
  {
    std::lock_guard lk(credentials_mu_);
    session_keys_.erase(uid);
    if (session_keys_.contains("#creds")) session_keys_["#creds"].erase(uid);
  }
  sandbox::end_session(fs::absolute(fs::path(opt_.homes_dir) / uid).string());
  for (auto* agent : reg_.visible(uid)) {
    const auto& kind = agent->spec().kind;
    sandbox::Sandbox sb;
    const std::string scope = kind == "claude-code" ? "claude" : kind == "codex" ? "codex" :
                              kind == "grok-cli" ? "grok" : "utility";
    sb.home = fs::absolute(fs::path(opt_.homes_dir) / uid / scope).string();
    agent->invalidate(&sb);
  }
}

json Harness::memory_view(const std::string& uid, const std::string& query) {
  bool failed = false;
  const std::string q = query.empty() ? "user facts decisions corrections and past work" : query;
  auto memories = store_.recall(q, memwal::shared_namespace(uid), {.limit = 30}, &failed);
  return {{"namespace", memwal::shared_namespace(uid)}, {"items", memories_json(memories, 1200)},
          {"status", failed ? "unavailable" : "ok"}};
}

json Harness::memory_stats(const std::string& uid) {
  long blobs = 0, bytes = 0;
  if (auto* c = store_.enabled() ? store_.client() : nullptr) {
    std::vector<std::future<json>> stats;
    for (const char* k : {"shared", "facts", "episodes", "chat", "checkpoints", "settings", "cases"})
      stats.push_back(std::async(std::launch::async, [c, ns = ns_user(uid, k)] {
        try {
          return c->stats(ns);
        } catch (const std::exception&) {  // a namespace that was never written has no stats
          return json::object();
        }
      }));
    for (auto& f : stats) {
      const json s = f.get();
      blobs += s.value("memory_count", 0L);
      bytes += s.value("storage_bytes", 0L);
    }
  }
  return {{"blobs", blobs}, {"bytes", bytes}};
}

json Harness::state() const {
  json writes = json::array();
  for (auto& w : store_.recent(30)) writes.push_back(w.to_json());
  return {{"memory_enabled", store_.enabled()},
          {"blobs_written_this_session", store_.blobs_written()},
          {"agents", reg_.roster()},
          {"recent_writes", writes},
          {"account_id", store_.client() ? store_.client()->account_id() : ""}};
}

std::string Harness::preview_entry(const std::string& uid, const std::string& session) const {
  const fs::path root = workspace_for(uid, session);
  std::string best;
  fs::file_time_type newest{};
  std::error_code ec;
  for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
       !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
    const std::string name = it->path().filename().string();
    if (it->is_symlink(ec) || name.starts_with(".") || name == "node_modules") {
      if (it->is_directory(ec)) it.disable_recursion_pending();
      continue;
    }
    if (it->is_directory(ec)) {
      if (it.depth() >= 2) it.disable_recursion_pending();
      continue;
    }
    if (name != "index.html" || !it->is_regular_file(ec)) continue;
    const auto when = it->last_write_time(ec);
    if (best.empty() || when > newest) {
      best = it->path().lexically_relative(root).string();
      newest = when;
    }
  }
  return best;
}

std::string Harness::workspace_for(const std::string& uid, const std::string& session) const {
  const auto p = fs::absolute(fs::path(opt_.workspaces_dir) / uid / session);
  fs::create_directories(p);
  return p.string();
}

// `#remember <fact>` lines in any agent's output become user facts on Walrus.
void Harness::apply_directives(Turn& t, const Step& s, const Emit& emit) {
  if (!store_.enabled()) return;
  std::istringstream in(s.output);
  for (std::string line; std::getline(in, line);) {
    const auto p = line.find_first_not_of(" \t>*-`");
    if (p == std::string::npos || line.compare(p, 9, "#remember") != 0) continue;
    std::string fact = line.substr(p + 9);
    fact.erase(0, fact.find_first_not_of(" :\t"));
    while (!fact.empty() && (fact.back() == '`' || fact.back() == ' ' || fact.back() == '\r')) fact.pop_back();
    if (fact.size() < 4) continue;
    // A "fact" that carries a credential is dropped whole: "User's key is [redacted]" is worth nothing.
    if (memwal::has_secret(fact)) {
      if (emit) emit({{"type", "agent"}, {"step", -1}, {"agent", s.agent}, {"kind", "status"}, {"text", "skipped a #remember that contained a secret"}});
      continue;
    }
    const auto saved = store_.remember(t.uid, clip(fact, 600), "fact", s.agent, t.session, t.id);
    if (emit && saved.value("ok", false))
      emit({{"type", "remember"}, {"agent", s.agent}, {"text", clip(fact, 600)},
            {"status", saved.value("status", "queued")}});
  }
}

std::vector<json> Harness::recall_records(const std::string& ns, const std::string& kind, const std::string& query,
                                          int limit, bool* failed) {
  std::vector<json> out;
  for (auto& m : store_.recall(query, ns, {.limit = limit, .recent = true}, failed)) {
    if (auto j = memwal::decode_record(m.text, kind)) {
      (*j)["blob_id"] = m.blob_id;
      out.push_back(std::move(*j));
    }
  }
  std::sort(out.begin(), out.end(), [](const json& a, const json& b) { return a.value("ts", 0L) > b.value("ts", 0L); });
  return out;
}

std::string Harness::deleted_chat_path(const std::string& uid, const std::string& session) const {
  // Keep markers outside agent workspaces and checkpoints. Hash both components so names cannot
  // escape the directory or collide between users. Back up this directory with the server's config.
  const fs::path root = opt_.keys_path.empty() ? fs::path(opt_.workspaces_dir) / ".deleted-chats"
                                            : fs::path(opt_.keys_path).parent_path() / "deleted-chats";
  return (root / crypto::sha256_hex(json::array({uid, session}).dump())).string();
}

bool Harness::chat_deleted(const std::string& uid, const std::string& session) const {
  // An unreadable marker directory is an error, never permission to reopen a deleted chat.
  return fs::exists(fs::symlink_status(deleted_chat_path(uid, session)));
}

json Harness::delete_chat(const std::string& uid, const std::string& session) {
  std::lock_guard lk(mu_);
  for (const auto& [_, turn] : turns_)
    if (turn->uid == uid && turn->session == session && !turn->done.load())
      return {{"error", "Stop the response and wait for it to finish before deleting this chat."}, {"busy", true}};

  try {
    const fs::path path = deleted_chat_path(uid, session);
    const auto root = path.parent_path();
    if (!root.parent_path().empty()) fs::create_directories(root.parent_path());
    if (::mkdir(root.c_str(), 0700) != 0 && errno != EEXIST)
      return {{"error", "Could not save the chat deletion. Try again."}};
    const int dir = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return {{"error", "Could not save the chat deletion. Try again."}};
    const int fd = ::openat(dir, path.filename().c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    const bool saved = fd >= 0 || errno == EEXIST;
    if (fd >= 0) ::close(fd);
    ::close(dir);
    if (!saved) return {{"error", "Could not save the chat deletion. Try again."}};
  } catch (const fs::filesystem_error&) {
    return {{"error", "Could not save the chat deletion. Try again."}};
  }

  // Do not touch the store: facts, corrections, episodes and original Walrus records are retained.
  std::erase_if(turns_, [&](const auto& entry) { return entry.second->uid == uid && entry.second->session == session; });
  session_turns_.erase(uid + "/" + session);
  return {{"ok", true}, {"session", session}};
}

json Harness::chat_history(const std::string& uid) {
  std::map<std::string, json> sessions;
  bool failed = false;
  auto records = recall_records(ns_user(uid, "chat"), "chat", "conversation with the user", 100, &failed);
  if (failed) return {{"error", "Could not read chats from Walrus. Try again."}};
  for (auto& r : records) {
    const std::string sid = r.value("session", "");
    if (sid.empty()) continue;
    auto& s = sessions[sid];
    const long ts = r.value("ts", 0L);
    if (s.is_null()) s = {{"session", sid}, {"updated", ts}, {"started", ts}, {"title", ""}, {"turns", 0}};
    s["turns"] = s["turns"].get<int>() + 1;
    s["updated"] = std::max(s["updated"].get<long>(), ts);
    if (ts <= s["started"].get<long>() || s["title"].get<std::string>().empty()) {
      s["started"] = ts;
      s["title"] = clip(r.value("user", ""), 80);
    }
  }
  json arr = json::array();
  for (auto& [k, v] : sessions)
    if (!chat_deleted(uid, k)) arr.push_back(v);
  std::sort(arr.begin(), arr.end(), [](const json& a, const json& b) { return a["updated"] > b["updated"]; });
  return arr;
}

json Harness::chat_transcript(const std::string& uid, const std::string& session) {
  const json deleted = {{"session", session}, {"turns", json::array()}, {"deleted", true},
                        {"error", "This chat was deleted. Saved memory is still available."}};
  if (chat_deleted(uid, session)) return deleted;
  json turns = json::array();
  bool failed = false;
  auto records = recall_records(ns_user(uid, "chat"), "chat", "conversation with the user", 100, &failed);
  if (chat_deleted(uid, session)) return deleted;  // deletion may have completed during the read
  if (failed) return {{"error", "Could not read this chat from Walrus. Try again."}};
  for (auto& r : records)
    if (r.value("session", "") == session) turns.push_back(r);
  std::sort(turns.begin(), turns.end(), [](const json& a, const json& b) { return a["ts"] < b["ts"]; });
  return {{"session", session}, {"turns", turns}};
}

json Harness::checkpoints(const std::string& uid, const std::string& session) {
  json arr = json::array();
  bool failed = false;
  auto records = recall_records(ns_user(uid, "checkpoints"), "checkpoint", "workspace file checkpoint", 100, &failed);
  if (failed) return {{"error", "Could not read checkpoints from Walrus. Try again."}};
  for (auto& r : records) {
    if (!session.empty() && r.value("session", "") != session) continue;
    json files = json::array();
    for (auto& f : r.value("files", json::array()))
      files.push_back({{"path", f.value("path", "")}, {"bytes", f.value("bytes", 0)}, {"saved", f.contains("content")}});
    arr.push_back({{"session", r.value("session", "")}, {"turn", r.value("turn", "")}, {"agent", r.value("agent", "")},
                   {"ts", r.value("ts", 0L)}, {"instruction", r.value("instruction", "")}, {"files", files},
                   {"blob_id", r.value("blob_id", "")}});
  }
  return arr;
}

// Rebuild a session's workspace from Walrus checkpoints (latest version of each file wins).
json Harness::restore_checkpoints(const std::string& uid, const std::string& session) {
  bool failed = false;
  auto recs = recall_records(ns_user(uid, "checkpoints"), "checkpoint", "workspace file checkpoint", 100, &failed);
  if (failed) return {{"error", "Could not read checkpoints from Walrus. No files were restored. Try again."}};
  std::sort(recs.begin(), recs.end(), [](const json& a, const json& b) { return a.value("ts", 0L) < b.value("ts", 0L); });
  std::map<std::string, std::string> latest;
  std::set<std::string> missing;
  for (auto& r : recs) {
    if (r.value("session", "") != session) continue;
    for (auto& f : r.value("files", json::array())) {
      const std::string path = f.value("path", "");
      if (!safe_relative(path)) continue;
      if (f.contains("content") && f["content"].is_string()) {
        latest[path] = f["content"];
        missing.erase(path);
      } else {
        latest.erase(path);  // An older saved body is not the latest version.
        missing.insert(path);
      }
    }
  }
  const fs::path root = workspace_for(uid, session);
  json restored = json::array(), skipped = json::array();
  for (const auto& path : missing) skipped.push_back(path);
  for (auto& [path, content] : latest)
    (write_in_workspace(root.string(), path, content) ? restored : skipped).push_back(path);
  return {{"session", session}, {"workspace", root.string()}, {"restored", restored}, {"skipped", skipped}};
}

// ---- agents per user: provider accounts, usage, own API keys --------------------------
// A user's own API agents are specs on Walrus (u:<uid>:settings, kind "agents"); the API keys
// themselves never go to memory — they live in a 0600 file on the Saga host.
namespace {
json read_keys(const std::string& path) {
  std::ifstream in(path);
  auto j = json::parse(in, nullptr, false);
  return j.is_object() ? j : json::object();
}
// Every change is read-modify-write of the whole file, so changes are serialized: two requests
// saving at once would otherwise drop one user's credentials, or race on the temp file.
bool update_keys(const std::string& path, const std::function<void(json&)>& edit) {
  static std::mutex mu;
  std::lock_guard lk(mu);
  try {
    json j = read_keys(path);
    edit(j);
    fs::create_directories(fs::path(path).parent_path());
    const std::string tmp = path + ".tmp";
    { std::ofstream(tmp, std::ios::trunc); }  // 0600 before any secret is written
    fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
    { std::ofstream(tmp, std::ios::trunc) << j.dump(2); }
    fs::rename(tmp, path);
    return true;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "[keys] could not save %s\n", path.c_str());
    return false;
  }
}
// Version 2 derives a separate key for each wallet and provider. Old slots are read with the
// wallet key once and upgraded when that wallet next unlocks.
json make_slot(const std::string& value, const secrets::Key& vault,
               const std::string& uid, const std::string& provider) {
  if (vault.size() == 32) {
    auto key = secrets::derive_key(vault, uid, provider);
    const std::string sealed = secrets::seal(key, value);
    secrets::clear(key);
    return {{"version", 2}, {"sealed", sealed}};
  }
  return {{"plain", value}};
}
std::string open_slot(const json& slot, const secrets::Key& vault,
                      const std::string& uid, const std::string& provider) {
  if (!slot.is_object()) return slot.is_string() ? slot.get<std::string>() : "";
  if (slot.contains("plain")) return slot.value("plain", "");
  if (vault.size() != 32 || !slot.contains("sealed")) return "";
  try {
    if (slot.value("version", 1) == 2) {
      auto key = secrets::derive_key(vault, uid, provider);
      const std::string plain = secrets::open(key, slot.value("sealed", ""));
      secrets::clear(key);
      return plain;
    }
    return secrets::open(vault, slot.value("sealed", ""));
  } catch (...) {
    return "";  // sealed under a different vault key
  }
}
void upgrade_slot(json& slot, const secrets::Key& vault,
                  const std::string& uid, const std::string& provider) {
  if (!slot.is_object() || !slot.contains("sealed") || slot.value("version", 1) == 2) return;
  try {
    std::string plain = secrets::open(vault, slot.value("sealed", ""));
    secrets::WipeString wipe{plain};
    slot = make_slot(plain, vault, uid, provider);
    if (!plain.empty()) sodium_memzero(plain.data(), plain.size());
  } catch (...) {  // damaged ciphertext or a different wallet key: leave it sealed
  }
}
std::string hint(const std::string& key) { return key.size() > 4 ? key.substr(key.size() - 4) : ""; }
}  // namespace

json Harness::account_keys() {
  std::lock_guard lk(credentials_mu_);
  json keys = read_keys(opt_.keys_path);
  keys.merge_patch(session_keys_);
  return keys;
}

bool Harness::save_connection(const std::string& uid, const std::string& provider, const json& slot,
                              bool remember, bool api, const std::atomic<bool>* cancelled) {
  std::lock_guard lk(credentials_mu_);
  bool saved = false;
  if (!update_keys(opt_.keys_path, [&](json& keys) {
    if (cancelled && cancelled->load()) return;
    json& accounts = api ? keys[uid] : keys["#creds"][uid];
    if (!accounts.is_object()) accounts = json::object();
    accounts.erase(provider);
    if (remember) { accounts[provider] = slot; accounts[provider]["remember"] = true; }
    saved = true;
  }) || !saved) return false;
  json& accounts = api ? session_keys_[uid] : session_keys_["#creds"][uid];
  if (!accounts.is_object()) accounts = json::object();
  accounts.erase(provider);
  if (!remember) { accounts[provider] = slot; accounts[provider]["remember"] = false; }
  return true;
}

bool Harness::forget_connection(const std::string& uid, const std::string& provider, bool api) {
  std::lock_guard lk(credentials_mu_);
  if (!update_keys(opt_.keys_path, [&](json& keys) {
    if (api) { if (keys.contains(uid) && keys[uid].is_object()) keys[uid].erase(provider); }
    else if (keys.contains("#creds") && keys["#creds"].contains(uid)) keys["#creds"][uid].erase(provider);
  })) return false;
  if (api) { if (session_keys_.contains(uid)) session_keys_[uid].erase(provider); }
  else if (session_keys_.contains("#creds") && session_keys_["#creds"].contains(uid))
    session_keys_["#creds"][uid].erase(provider);
  return true;
}

void Harness::seed_user(const std::string& uid) {
  std::promise<void> ready;
  std::shared_future<void> pending;
  {
    std::lock_guard lk(mu_);
    if (auto it = seeding_.find(uid); it != seeding_.end()) pending = it->second;
    else seeding_[uid] = ready.get_future().share();
  }
  // Another request is reading this user's settings already: wait for it rather than run a turn
  // without the user's own agents.
  if (pending.valid()) return pending.wait();
  // If the relayer can't be reached, try again on the user's next request instead of leaving them
  // without their agents and model picks until a restart.
  bool chats_failed = false, settings_failed = false;
  struct Finish {
    Harness* h;
    const std::string& uid;
    std::promise<void>& ready;
    bool ok = false;
    ~Finish() {
      if (!ok) {
        std::lock_guard lk(h->mu_);
        h->seeding_.erase(uid);
      }
      ready.set_value();
    }
  } finish{this, uid, ready};
  // Both reads at once. Today's runs per agent are rebuilt from the Walrus transcripts (idempotent,
  // since seeding can repeat).
  auto chats_f = std::async(std::launch::async, [&] {
    return recall_records(ns_user(uid, "chat"), "chat", "conversation with the user", 100, &chats_failed);
  });
  // Settings are snapshots and the newest of each kind wins. One wide read covers both kinds, so a
  // run of model changes can't push the newest agents snapshot out of the result.
  std::optional<json> picks, agents_rec;
  for (auto& m : store_.recall("user settings: model picks and api agents", ns_user(uid, "settings"),
                               {.limit = 50, .recent = true}, &settings_failed)) {
    auto newer = [](std::optional<json>& slot, std::optional<json> rec) {
      if (rec && (!slot || rec->value("ts", 0L) > slot->value("ts", 0L))) slot = std::move(rec);
    };
    newer(picks, memwal::decode_record(m.text, "models"));
    newer(agents_rec, memwal::decode_record(m.text, "agents"));
  }
  const auto chats = chats_f.get();
  const std::time_t now = std::time(nullptr);
  std::tm tm{};
  gmtime_r(&now, &tm);
  tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
  const long midnight = static_cast<long>(timegm(&tm));
  std::map<std::string, int> runs;
  for (auto& c : chats) {
    if (c.value("ts", 0L) < midnight) continue;
    for (auto& st : c.value("steps", json::array())) runs[st.value("agent", "")]++;
  }
  {
    std::lock_guard lk(mu_);
    for (auto& [agent, n] : runs) {
      auto& e = usage_[uid][agent];
      if (e.day != today()) e = {today(), 0, 0};
      e.runs = std::max(e.runs, n);
    }
  }
  // The user's model picks.
  if (picks) {
    // Name the object: before C++23 a range-for over a temporary's items() iterates freed memory.
    const json models = picks->value("models", json::object());
    std::lock_guard lk(mu_);
    for (auto& [agent, model] : models.items())
      if (model.is_string()) model_picks_[uid][agent] = model.get<std::string>();
  }
  // The user's own API agents.
  if (agents_rec)
    for (auto& a : agents_rec->value("agents", json::array())) {
      if (!a.is_object() || !a.contains("name") || !a["name"].is_string()) continue;
      agents::Spec spec = agents::spec_from_json(a);
      spec.kind = "openai";
      spec.owner = uid;
      spec.public_only = true;
      reg_.add(spec);
    }
  finish.ok = !chats_failed && !settings_failed;
}

void Harness::record_usage(const std::string& uid, const std::string& agent, const agents::Result& r) {
  std::lock_guard lk(mu_);
  auto& e = usage_[uid][agent];
  if (e.day != today()) e = {today(), 0, 0};
  e.runs++;
  e.seconds += r.seconds;
}

// ---- bring-your-own provider accounts ---------------------------------------------------
// Credentials: Claude's subscription token / API key live in the 0600 keys file under "#creds";
// Codex and Grok keep their own login files inside the user's agent home. Neither ever enters
// Walrus memory, and neither is visible to any other user's sandbox.
namespace {
constexpr const char* kCreds = "#creds";  // '#' can't appear in a uid, so no clash with API-agent keys

bool is_wallet(const std::string& uid) {
  return uid.size() > 2 && uid.starts_with("0x") &&
         std::all_of(uid.begin() + 2, uid.end(), [](unsigned char c) { return std::isxdigit(c); });
}

std::string strip_ansi(const std::string& s) {
  static const std::regex ansi("\x1B\\[[0-9;?]*[A-Za-z]");
  return std::regex_replace(s, ansi, "");
}
}  // namespace

// Where a user's connections (provider logins, API keys, GitHub) live. Only a wallet can hold them:
// its session proves the owner and its signature derives the vault key, which remains in server
// memory for that session. A username is guest mode — anyone can type it — so it
// gets an empty keyring nothing is ever saved to. '~' never appears in a uid.
namespace {
const json kWalletOnly = {{"error", "Sign in with a wallet or a password to connect accounts. Guest usernames can't keep credentials."}};
// Claude, ChatGPT and Grok accounts are connected by wallet users only; a username account brings its
// own API agents instead.
const json kProviderWalletOnly = {{"error", "Sign in with a wallet to connect your own Claude, ChatGPT or Grok account. "
                                            "Username accounts can add their own API agents."}};
}  // namespace

// A wallet, or a username registered with a password and signed in (its vault key is present): both
// seal credentials under a key only they can produce. A guest username has no secret, so it keeps none,
// whatever key a caller hands in.
bool Harness::keeps_credentials(const std::string& uid, const secrets::Key& vault) const {
  if (is_wallet(uid)) return true;
  return vault.size() == 32 && read_keys(opt_.keys_path).value("#accounts", json::object()).contains(uid);
}

std::string Harness::keyring(const std::string& uid, const secrets::Key& vault) const {
  return keeps_credentials(uid, vault) ? uid : uid + "~guest";
}

json Harness::password_login(const std::string& name, const std::string& password, secrets::Key& vault,
                             bool may_create) {
  if (password.size() < 8 || password.size() > 256) return {{"error", "Use a password of 8 to 256 characters."}};
  {
    std::lock_guard lk(login_mu_);
    const auto now = std::chrono::steady_clock::now();
    if (auto it = login_failures_.find(name); it != login_failures_.end() && it->second.until > now) {
      const auto wait = std::chrono::duration_cast<std::chrono::seconds>(it->second.until - now).count() + 1;
      return {{"error", "Too many wrong passwords for this username. Try again in " + std::to_string(wait) + " s."}};
    }
  }
  auto failed = [&] {
    std::lock_guard lk(login_mu_);
    auto& f = login_failures_[name];
    if (++f.count >= 5) {
      const int doublings = std::min(f.count - 5, 5);  // 30 s … 16 min
      f.until = std::chrono::steady_clock::now() + std::chrono::seconds(std::min(30 << doublings, 900));
    }
    if (login_failures_.size() > 10000) std::erase_if(login_failures_, [](auto& e) { return e.second.count < 5; });
    return json{{"error", "Wrong username or password."}};
  };
  crypto::init();
  // One sign-in at a time: each Argon2id run holds 64 MB, and a name is claimed exactly once.
  static std::mutex mu;
  std::lock_guard lk(mu);
  const json account = read_keys(opt_.keys_path).value("#accounts", json::object()).value(name, json());
  std::string salt_hex;
  bool created = false;
  if (account.is_object()) {
    const std::string verifier = account.value("verifier", "");
    if (verifier.empty() || crypto_pwhash_str_verify(verifier.c_str(), password.data(), password.size()) != 0)
      return failed();
    salt_hex = account.value("salt", "");
    std::lock_guard flk(login_mu_);
    login_failures_.erase(name);
  } else {
    if (!may_create) return {{"error", "Too many new accounts from your network. Try again later, or sign in with a wallet."}};
    // A name with memory but no password was made before passwords (a guest on this machine, or the
    // operator's own tests on the same MemWal account): its memory isn't the first claimant's to read.
    if (store_.enabled()) {
      for (const char* k : {"shared", "facts", "episodes", "chat", "checkpoints", "settings", "cases"}) {
        try {
          if (store_.client()->stats(ns_user(name, k)).value("memory_count", 0L) > 0)
            return {{"error", "That username is taken. Pick another, or sign in with a wallet."}};
        } catch (const std::exception&) {
          return {{"error", "Can't check that username right now. Try again in a minute."}};
        }
      }
    }
    char verifier[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(verifier, password.data(), password.size(), crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
      return {{"error", "The server is busy. Try again."}};
    salt_hex = crypto::random_hex(crypto_pwhash_SALTBYTES);
    bool saved = false;
    update_keys(opt_.keys_path, [&](json& keys) {
      json& accounts = keys["#accounts"];
      if (!accounts.is_object()) accounts = json::object();
      if (accounts.contains(name)) return;
      accounts[name] = {{"verifier", std::string(verifier)}, {"salt", salt_hex}, {"created", std::time(nullptr)}};
      saved = true;
    });
    if (!saved) return {{"error", "Couldn't save the account. Try again."}};
    created = true;
  }
  // The vault key comes from the password; Saga never stores it.
  crypto::Bytes salt;
  try {
    salt = crypto::from_hex(salt_hex);
  } catch (const std::exception&) {
  }
  if (salt.size() != crypto_pwhash_SALTBYTES) return {{"error", "This account's record is damaged."}};
  vault.assign(32, 0);
  if (crypto_pwhash(vault.data(), vault.size(), password.data(), password.size(), salt.data(),
                    crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    secrets::clear(vault);
    return {{"error", "The server is busy. Try again."}};
  }
  return {{"uid", name}, {"created", created}};
}

std::optional<sandbox::Sandbox> Harness::sandbox_for(const std::string& uid, const std::string& workspace,
                                                     const secrets::Key& vault, const std::string& provider) {
  if (!opt_.user_accounts || uid.empty()) return std::nullopt;
  const std::string ring = keyring(uid, vault);
  const std::string scope = provider == "claude-code" ? "claude" :
                            provider == "codex" ? "codex" :
                            provider == "grok-cli" ? "grok" :
                            provider == "git" ? "git" : "utility";
  const fs::path root = fs::absolute(fs::path(opt_.homes_dir) / ring);
  sandbox::Sandbox sb;
  sb.home = (root / scope).string();
  for (const auto& dir : {root, root / scope}) {
    fs::create_directories(dir.parent_path());
    if (!fs::create_directory(dir) && !fs::is_directory(fs::symlink_status(dir)))
      throw std::runtime_error("provider home must be a real private directory");
    fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace);
  }
  sb.workspace = workspace;
  sb.runner = opt_.saga_bin;
  sb.cancel = operation_cancel(uid);
  if (scope == "codex" || scope == "grok") {
    sb.login_file = scope == "codex" ? ".codex/auth.json" : ".grok/auth.json";
    if (vault.size() == 32) {
      sb.vault = secrets::derive_key(vault, uid, scope);
      // Older deployments kept both CLI logins in one home and sealed them with the raw vault key.
      // Move each login to its own home on first unlock, without exposing one provider to another.
      static std::mutex migration_mu;
      std::lock_guard lk(migration_mu);
      if (!sandbox::has_login(sb, sb.login_file)) {
        auto legacy = secrets::read_private_file(root.string(), sb.login_file + ".sealed");
        bool sealed = legacy.has_value();
        if (!legacy) legacy = secrets::read_private_file(root.string(), sb.login_file);
        if (legacy) {
          secrets::WipeString wipe_legacy{*legacy};
          try {
            std::string plain = sealed ? secrets::open(vault, *legacy) : *legacy;
            secrets::WipeString wipe{plain};
            secrets::write_private_file(sb.home, sb.login_file + ".sealed", secrets::seal(sb.vault, plain));
            secrets::erase_file(root.string(), sb.login_file);
            if (!plain.empty()) sodium_memzero(plain.data(), plain.size());
          } catch (...) {  // unreadable legacy login stays sealed until the right wallet unlocks
          }
        }
      }
    }
  }
  if (scope == "claude") {
    const json cred = account_keys().value(kCreds, json::object()).value(ring, json::object())
                          .value("claude", json::object());
    std::string value = open_slot(cred.value("secret", json()), vault, uid, "claude");
    secrets::WipeString wipe{value};
    if (!value.empty() && cred.value("kind", "") == "oauth_token") sb.env["CLAUDE_CODE_OAUTH_TOKEN"] = value;
    if (!value.empty() && cred.value("kind", "") == "api_key") sb.env["ANTHROPIC_API_KEY"] = value;
  }
  return sb;
}

json Harness::agents_view(const std::string& uid, const secrets::Key& vault) {
  seed_user(uid);
  const std::string ring = keyring(uid, vault);
  const json api_keys = account_keys().value(ring, json::object());
  json out = json::array();
  for (auto& r : reg_.roster(uid)) {
    const std::string name = r["name"];
    agents::Agent* a = reg_.find(name, uid);
    const auto sb = a ? sandbox_for(uid, "", vault, a->spec().kind) : std::optional<sandbox::Sandbox>{};
    const sandbox::Sandbox* sbp = sb ? &*sb : nullptr;
    Usage e;
    {
      std::lock_guard lk(mu_);
      e = usage_[uid][name];
    }
    if (e.day != today()) e = {today(), 0, 0};
    r["runs_today"] = e.runs;
    r["model_pick"] = model_pick(uid, name);
    if (a && !a->spec().locked) {
      r["model_default"] = a->spec().model;
      r["model_options"] = model_options(a->spec().kind);
    }
    r["seconds_today"] = static_cast<int>(e.seconds);
    r["account"] = a ? a->account(r["custom"].get<bool>() ? nullptr : sbp) : json::object();
    // An own-API-key agent's settings travel with memory; its key only with the wallet's keyring.
    if (a && r["custom"].get<bool>() && !a->spec().locked) {
      std::string key = open_slot(api_keys.value(name, json()), vault, uid, name);
      secrets::WipeString wipe{key};
      r["account"]["detail"] = key.empty() ? "no API key from you" : "own API key ··" + hint(key);
    }
    // How this agent can be connected, in this deployment mode.
    json how = json::array();
    if (a && !r["custom"].get<bool>()) {
      if (opt_.user_accounts) {
        const std::string kind = a->spec().kind;
        if (kind == "claude-code") how = {"token", "api_key"};
        else if (kind == "codex") how = {"device", "api_key"};
        else if (!a->device_login_argv().empty()) how = {"device"};
      } else if (!a->login_argv().empty()) {
        how = {"browser"};
      }
    }
    r["connect"] = how;
    r["can_connect"] = !how.empty();
    {
      std::lock_guard lk(mu_);
      if (auto d = device_.find(ring + "/" + name); d != device_.end() && d->second->status == "waiting")
        r["device"] = {{"url", d->second->url}, {"code", d->second->code}};
    }
    out.push_back(r);
  }
  return out;
}

json Harness::connect_agent(const std::string& uid, const std::string& name, const secrets::Key& vault, bool remember) {
  agents::Agent* a = reg_.find(name);
  if (!a) return {{"error", "unknown agent"}};
  if (opt_.user_accounts && !is_wallet(uid)) return keeps_credentials(uid, vault) ? kProviderWalletOnly : kWalletOnly;
  if (opt_.user_accounts && vault.size() != 32) return {{"error", "unlock your vault first (sign in again)"}};

  if (!opt_.user_accounts) {
    // Operator mode: the provider's own browser sign-in on the Saga host.
    if (a->login_argv().empty()) return {{"error", "this agent has no sign-in flow"}};
    std::string cmd;
    for (auto& p : a->login_argv()) cmd += (cmd.empty() ? "" : " ") + p;
    std::lock_guard lk(mu_);
    if (connecting_.contains(a->name())) return {{"ok", true}, {"command", cmd}, {"already", true}};
    connecting_.insert(a->name());
    if (!spawn_locked([this, a] {
          proc::Options o;
          o.timeout_s = 600;
          proc::run(a->login_argv(), o);
          a->invalidate(nullptr);
          std::lock_guard lk2(mu_);
          connecting_.erase(a->name());
        })) {
      connecting_.erase(a->name());
      return {{"error", "the server is busy — try again shortly"}};
    }
    return {{"ok", true}, {"command", cmd}};
  }

  // User mode: device-code sign-in inside the user's sandbox, so the login lands in their home.
  if (a->device_login_argv().empty()) return {{"error", "@" + name + " connects with a token or API key"}};
  const std::string key = keyring(uid, vault) + "/" + a->name();
  auto st = std::make_shared<DeviceLogin>();
  {
    std::lock_guard lk(mu_);
    // Every Connect starts a fresh code: the old one may have been refused (e.g. ChatGPT's device-code
    // setting was off) and the user fixed that since. Its CLI is stopped.
    if (auto it = device_.find(key); it != device_.end()) it->second->cancel = true;
    device_[key] = st;
  }
  const auto sb = sandbox_for(uid, "", vault, a->spec().kind);
  sandbox::remember_login(*sb, remember);
  auto ready = std::make_shared<std::promise<void>>();
  auto fut = ready->get_future();
  {
    std::lock_guard lk(mu_);
    if (!spawn_locked([this, a, st, sb = *sb, ready] {
      static const std::regex url_re(R"(https://[^\s]+)"), code_re(R"(\b[A-Z0-9]{4}-[A-Z0-9]{4,6}\b)");
      bool signalled = false;
      proc::Options o;
      o.timeout_s = 900;  // device codes expire in 15 minutes
      o.merge_stderr = true;
      o.cancel = &st->cancel;
      o.on_stdout_line = [&](const std::string& raw) {
        const std::string line = strip_ansi(raw);
        std::smatch m;
        std::lock_guard lk2(mu_);
        if (st->url.empty() && std::regex_search(line, m, url_re)) st->url = m.str();
        if (st->code.empty() && std::regex_search(line, m, code_re)) st->code = m.str();
        if (!signalled && !st->url.empty() && !st->code.empty()) {
          st->status = "waiting";
          signalled = true;
          ready->set_value();
        }
      };
      proc::Result p;
      {
        sandbox::Lease lease(&sb);  // the login the CLI writes is sealed with the user's key on release
        p = sandbox::run(sb, a->device_login_argv(), o);
      }
      if (st->cancel) {
        const std::string rel = a->spec().kind == "codex" ? ".codex/auth.json" : ".grok/auth.json";
        sandbox::forget_login(sb, rel);
      }
      a->invalidate(&sb);
      std::lock_guard lk2(mu_);
      st->status = p.exit_code == 0 && !st->cancel ? "done" : "failed";
      if (p.exit_code != 0) st->error = p.timed_out ? "sign-in timed out" : strip_ansi(p.out).substr(0, 240);
      if (!signalled) ready->set_value();
    })) {
      st->status = "failed";
      st->error = "the server is busy — try again shortly";
      ready->set_value();
    }
  }
  // Hand the URL + code to the browser as soon as the CLI prints them; the CLI keeps waiting.
  fut.wait_for(std::chrono::seconds(25));
  std::lock_guard lk(mu_);
  if (st->status == "waiting") return {{"ok", true}, {"url", st->url}, {"code", st->code}};
  return {{"error", st->error.empty() ? "@" + name + " did not start a sign-in" : st->error}};
}

json Harness::connect_status(const std::string& uid, const std::string& name, const secrets::Key& vault) {
  const std::string ring = keyring(uid, vault);
  std::lock_guard lk(mu_);
  auto it = device_.find(ring + "/" + name);
  if (it == device_.end()) return {{"status", "none"}};
  return {{"status", it->second->status}, {"error", it->second->error}};
}

json Harness::set_credential(const std::string& uid, const std::string& name, const std::string& kind,
                             const std::string& value, const secrets::Key& vault, bool remember) {
  if (!opt_.user_accounts) return {{"error", "this Saga runs agents on the operator's own accounts"}};
  if (!is_wallet(uid)) return keeps_credentials(uid, vault) ? kProviderWalletOnly : kWalletOnly;
  if (vault.size() != 32) return {{"error", "unlock your vault first (sign in again)"}};
  agents::Agent* a = reg_.find(name);
  if (!a) return {{"error", "unknown agent"}};
  std::string v = value.substr(0, 4096);
  secrets::WipeString wipe{v};
  memwal::SecretScope sensitive(v);
  const auto sb = sandbox_for(uid, "", vault, a->spec().kind);
  if (a->spec().kind == "claude-code") {
    // Tokens from `claude setup-token` start sk-ant-oat…, API keys sk-ant-api….
    if (kind == "oauth_token" && !v.starts_with("sk-ant-oat")) return {{"error", "that doesn't look like a token from `claude setup-token` (sk-ant-oat…)"}};
    if (kind == "api_key" && !v.starts_with("sk-ant-")) return {{"error", "that doesn't look like an Anthropic API key (sk-ant-…)"}};
    if (kind != "oauth_token" && kind != "api_key") return {{"error", "unknown credential type"}};
    const json slot = {{"kind", kind}, {"secret", make_slot(v, vault, uid, "claude")}};
    if (!save_connection(uid, "claude", slot, remember, false, sb->cancel.get()))
      return {{"error", "couldn't save the credential on the Saga host"}};
    a->invalidate(sb ? &*sb : nullptr);
    return {{"ok", true}};
  }
  if (a->spec().kind == "codex" && kind == "api_key") {
    sandbox::remember_login(*sb, remember);
    // Codex stores the key in the user's own CODEX_HOME.
    proc::Options o;
    o.timeout_s = 30;
    o.stdin_data = v;
    o.merge_stderr = true;
    proc::Result p;
    {
      sandbox::Lease lease(&*sb);
      p = sandbox::run(*sb, {"codex", "login", "--with-api-key"}, o);
    }
    a->invalidate(&*sb);
    if (p.exit_code != 0) return {{"error", "codex rejected the key: " + strip_ansi(p.out).substr(0, 200)}};
    return {{"ok", true}};
  }
  return {{"error", "@" + name + " doesn't take a " + kind}};
}

json Harness::disconnect_agent(const std::string& uid, const std::string& name, const secrets::Key& vault) {
  agents::Agent* a = reg_.find(name);
  if (!a) return {{"error", "unknown agent"}};
  if (!opt_.user_accounts) {
    // Operator mode: Connect ran the provider's own sign-in on the Saga host, so Disconnect runs its
    // sign-out there too. That signs this machine's CLI out for every program that uses it.
    if (a->logout_argv().empty()) return {{"error", "@" + name + " has nothing to disconnect"}};
    std::string cmd;
    for (auto& p : a->logout_argv()) cmd += (cmd.empty() ? "" : " ") + p;
    proc::Options o;
    o.timeout_s = 30;
    o.merge_stderr = true;
    const proc::Result p = proc::run(a->logout_argv(), o);
    a->invalidate(nullptr);
    if (p.exit_code != 0) return {{"error", "`" + cmd + "` failed: " + strip_ansi(p.out).substr(0, 200)}};
    return {{"ok", true}, {"deleted", json::array({cmd})}};
  }
  // Only provider CLIs have a login to delete. Anything else (the built-in @saga) would fall through to
  // erasing the Grok login below.
  const std::string& kind = a->spec().kind;
  if (kind != "claude-code" && kind != "codex" && kind != "grok-cli") return {{"error", "@" + name + " has nothing to disconnect"}};
  if (!keeps_credentials(uid, vault)) return kWalletOnly;
  cancel_active(uid);
  // Disconnect deletes the credential outright (sealed or not).
  const std::string ring = keyring(uid, vault);
  const auto sb = sandbox_for(uid, "", vault, a->spec().kind);
  json deleted = json::array();
  if (a->spec().kind == "claude-code") {
    if (!forget_connection(uid, "claude")) return {{"error", "couldn't delete the Claude credential on the Saga host"}};
    deleted.push_back("claude token / API key");
  } else {
    const std::string rel = a->spec().kind == "codex" ? ".codex/auth.json" : ".grok/auth.json";
    if (sandbox::forget_login(*sb, rel)) deleted.push_back(rel);
    // Remove an old shared-home login too, including when its vault key cannot be reproduced.
    secrets::erase_file(fs::absolute(fs::path(opt_.homes_dir) / ring).string(), rel);
  }
  a->invalidate(&*sb);
  {
    std::lock_guard lk(mu_);
    if (auto it = device_.find(ring + "/" + a->name()); it != device_.end()) it->second->cancel = true;
    device_.erase(ring + "/" + a->name());
  }
  const bool gone = a->spec().kind == "claude-code"
                        ? !account_keys().value(kCreds, json::object()).value(ring, json::object()).contains("claude")
                        : !sandbox::has_login(*sb, a->spec().kind == "codex" ? ".codex/auth.json" : ".grok/auth.json");
  return {{"ok", gone}, {"deleted", deleted}};
}

json Harness::vault_status(const std::string& uid, const secrets::Key& vault) {
  if (vault.size() != 32) return {{"state", "missing"}};
  if (!keeps_credentials(uid, vault)) return {{"state", "guest"}};  // guests keep no credentials
  const std::string id = secrets::key_id(vault);
  std::string known;
  update_keys(opt_.keys_path, [&](json& keys) {
    known = keys.value("#vault", json::object()).value(uid, "");
    if (known.empty()) keys["#vault"][uid] = known = id;  // first key for this user becomes their vault
    if (known != id) return;
    if (keys.contains(kCreds) && keys[kCreds].contains(uid) && keys[kCreds][uid].is_object())
      for (auto& [provider, account] : keys[kCreds][uid].items()) {
        if (!account.is_object()) continue;
        for (const char* field : {"secret", "who"})
          if (account.contains(field)) upgrade_slot(account[field], vault, uid, provider);
      }
    if (keys.contains(uid) && keys[uid].is_object())
      for (auto& [agent, slot] : keys[uid].items()) upgrade_slot(slot, vault, uid, agent);
  });
  return {{"state", known == id ? "ok" : "mismatch"}};
}

// The user's secrets were sealed under a key this browser can't reproduce: drop them and adopt this key.
// Only a wallet can do this: its session proves the owner. A guest username has nothing to reset.
json Harness::vault_reset(const std::string& uid, const secrets::Key& vault) {
  if (vault.size() != 32) return {{"error", "no vault key"}};
  if (!keeps_credentials(uid, vault)) return {{"error", "only a signed-in account's vault can be reset"}};
  end_session(uid);
  if (!update_keys(opt_.keys_path, [&](json& keys) {
        if (keys.contains(kCreds)) keys[kCreds].erase(uid);
        if (keys.contains(uid) && keys[uid].is_object())
          for (auto it = keys[uid].begin(); it != keys[uid].end();)
            it = it->is_object() && it->contains("sealed") ? keys[uid].erase(it) : std::next(it);
        keys["#vault"][uid] = secrets::key_id(vault);
      }))
    return {{"error", "couldn't update the vault on the Saga host"}};
  for (const auto& [provider, rel] : {std::pair{"codex", ".codex/auth.json"},
                                      std::pair{"grok-cli", ".grok/auth.json"}})
    if (const auto sb = sandbox_for(uid, "", vault, provider)) sandbox::forget_login(*sb, rel);
  const std::string legacy_home = fs::absolute(fs::path(opt_.homes_dir) / uid).string();
  for (auto& rel : sandbox::kLoginFiles) secrets::erase_file(legacy_home, rel);
  for (auto* a : reg_.visible(uid)) a->invalidate(nullptr);
  return {{"ok", true}};
}

// The key for one of the user's own API agents, from their keyring. A local operator-mode Saga used
// to keep these under the bare uid in the clear; that spelling still works there.
std::string Harness::api_key_for(const std::string& uid, const std::string& agent, const secrets::Key& vault) {
  const json keys = account_keys();
  std::string k = open_slot(keys.value(keyring(uid, vault), json::object()).value(agent, json()), vault, uid, agent);
  if (k.empty() && !opt_.user_accounts) {
    const json legacy = keys.value(uid, json::object()).value(agent, json());
    if (legacy.is_object() && legacy.contains("plain")) k = legacy.value("plain", "");
  }
  return k;
}

json Harness::probe_agent(const std::string& uid, const std::string& name, const secrets::Key& vault) {
  agents::Agent* a = reg_.find(name);
  if (!a) return {{"error", "unknown agent"}};
  const auto sb = sandbox_for(uid, "", vault, a->spec().kind);
  const sandbox::Sandbox* sbp = sb ? &*sb : nullptr;
  // Refresh: forget the cached status, then ask for usage where the provider only reports it in a
  // response (Claude). The others (Codex) are re-read from what their CLI last recorded.
  a->invalidate(sbp);
  const bool probed = a->probe_usage(sbp);
  json account = a->account(sbp);
  if (!probed && account.value("windows", json::array()).empty())
    return {{"error", "@" + name + " did not report usage windows"}};
  return {{"ok", true}, {"account", account}};
}

json Harness::add_agent(const std::string& uid, const json& body, const secrets::Key& vault) {
  seed_user(uid);
  agents::Spec spec;
  spec.kind = "openai";
  spec.owner = uid;
  spec.public_only = true;
  spec.name = body.value("name", "");
  // Handles are case-insensitive: store the key under the name the registry will look up.
  std::transform(spec.name.begin(), spec.name.end(), spec.name.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  spec.base_url = body.value("base_url", "");
  while (!spec.base_url.empty() && spec.base_url.back() == '/') spec.base_url.pop_back();
  spec.model = body.value("model", "");
  spec.description = body.value("description", "");
  std::string key = body.value("api_key", "");
  secrets::WipeString wipe{key};
  spec.key_hint = hint(key);
  if (spec.description.empty()) spec.description = spec.model + " via own API key";
  if (!http::is_https_url(spec.base_url))
    return {{"error", "remote API base URL must use HTTPS with no credentials, query or fragment"}};
  if (spec.model.empty()) return {{"error", "model is required"}};
  // A key is only kept sealed, under a wallet's vault.
  if (!key.empty() && !keeps_credentials(uid, vault)) return kWalletOnly;
  if (!key.empty() && vault.size() != 32)
    return {{"error", "unlock your vault first (sign in again)"}};
  if (auto err = reg_.add(spec); !err.empty()) return {{"error", err}};

  if (!key.empty()) {
    const json slot = make_slot(key, vault, uid, spec.name);  // sealed only
    const auto cancelled = operation_cancel(uid);
    if (!save_connection(uid, spec.name, slot, body.value("remember", true), true, cancelled.get())) {
      reg_.remove(spec.name, uid);
      return {{"error", "couldn't save the API key on the Saga host"}};
    }
  }
  persist_user_agents(uid);
  return {{"ok", true}, {"name", spec.name}};
}

json Harness::remove_agent(const std::string& uid, const std::string& name, const secrets::Key& vault) {
  if (!reg_.remove(name, uid)) return {{"error", "not one of your agents"}};
  const std::string ring = keyring(uid, vault);
  std::string handle = name;
  std::transform(handle.begin(), handle.end(), handle.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  forget_connection(uid, handle, true);
  update_keys(opt_.keys_path, [&](json& keys) {
    if (!keys.contains(ring) || !keys[ring].is_object()) return;
    // Also any spelling an older Saga saved the key under ("MyAgent" for @myagent).
    for (auto it = keys[ring].begin(); it != keys[ring].end();) {
      std::string k = it.key();
      std::transform(k.begin(), k.end(), k.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      it = k == handle ? keys[ring].erase(it) : std::next(it);
    }
  });
  persist_user_agents(uid);
  return {{"ok", true}};
}

// Models worth suggesting per kind of agent; anything else can still be typed in.
json model_options(const std::string& kind) {
  if (kind == "claude-code") return {"opus", "sonnet", "haiku"};
  if (kind == "codex") return {"gpt-6.1-sol", "gpt-6-sol", "gpt-5.6-sol", "gpt-5.5"};
  if (kind == "grok-cli") return {"grok-4.7", "grok-4.7-build-fast", "grok-4.6", "grok-4.5"};
  return json::array();
}

json Harness::models_view(const std::string& uid) {
  seed_user(uid);
  json out = json::array();
  for (auto& r : reg_.roster(uid)) {
    const std::string name = r["name"];
    agents::Agent* a = reg_.find(name, uid);
    if (!a) continue;
    if (a->spec().locked) {  // shown as just "Saga": no model name, nothing to pick
      out.push_back({{"name", name}, {"primary", r.value("primary", false)}, {"locked", true}, {"options", json::array()}});
      continue;
    }
    out.push_back({{"name", name}, {"primary", r.value("primary", false)}, {"kind", a->spec().kind},
                   {"default", a->spec().model}, {"pick", model_pick(uid, name)},
                   {"options", model_options(a->spec().kind)}});
  }
  return out;
}

std::string Harness::model_pick(const std::string& uid, const std::string& agent) const {
  std::lock_guard lk(mu_);
  auto u = model_picks_.find(uid);
  if (u == model_picks_.end()) return "";
  auto it = u->second.find(agent);
  return it == u->second.end() ? "" : it->second;
}

// The user's model for one agent, kept on Walrus with their other settings (u:<uid>:settings).
json Harness::set_model(const std::string& uid, const std::string& agent, const std::string& model) {
  seed_user(uid);
  const agents::Agent* target = reg_.find(agent, uid);
  if (!target) return {{"error", "no agent @" + agent}};
  if (target->spec().locked) return {{"error", "@" + agent + "'s model can't be changed"}};
  // It becomes a CLI argument, so only the characters model ids actually use, and never a flag.
  if (model.size() > 80 || model.starts_with("-") || !std::all_of(model.begin(), model.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '.' || c == '-' || c == '_' || c == ':' || c == '/' || c == '@';
      }))
    return {{"error", "that isn't a model id"}};
  json picks;
  {
    std::lock_guard lk(mu_);
    if (model.empty()) model_picks_[uid].erase(agent);
    else model_picks_[uid][agent] = model;
    picks = model_picks_[uid];
  }
  store_.put(ns_user(uid, "settings"), "models",
             memwal::encode_record("models", {{"ts", std::time(nullptr)}, {"models", picks}}));
  return {{"ok", true}, {"agent", agent}, {"model", model}};
}

void Harness::persist_user_agents(const std::string& uid) {
  json list = json::array();
  for (auto* a : reg_.visible(uid)) {
    if (a->spec().owner != uid) continue;
    list.push_back({{"name", a->name()}, {"kind", "openai"}, {"base_url", a->spec().base_url},
                    {"model", a->spec().model}, {"description", a->spec().description}});
  }
  store_.put(ns_user(uid, "settings"), "agents",
             memwal::encode_record("agents", {{"ts", std::time(nullptr)}, {"agents", list}}));
}

// ---- GitHub: the user's own repos, worked on in their chat workspace --------------------------
// The token is sealed with the user's vault key like every other credential. A chat's repo is a
// normal clone inside that chat's workspace on branch saga/<chat>. Everything inside the workspace
// is the agents' to change — files, .git/config, hooks — so nothing Saga trusts lives there: the
// record of which repo a chat works on sits next to the workspace, out of the sandbox's view, and
// the token only ever meets git in a fresh repository (see github_open_pr).
namespace {
std::string repo_dir_name(const std::string& full_name) {
  std::string n = full_name.substr(full_name.find('/') + 1), out;
  for (char c : n)
    if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.') out += c;
  return out.empty() || out[0] == '.' ? "repo" : out;
}

bool valid_full_name(const std::string& s) {
  static const std::regex re(R"(^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$)");
  return std::regex_match(s, re);
}

bool valid_branch(const std::string& s) {
  static const std::regex re(R"(^[A-Za-z0-9._][A-Za-z0-9._/-]{0,199}$)");
  return std::regex_match(s, re) && s.find("..") == std::string::npos;
}

// workspaces/<uid>/<session> → workspaces/<uid>/.repo-<session>.json (only the session dir is mounted).
fs::path marker_path(const std::string& workspace) {
  const fs::path ws(workspace);
  return ws.parent_path() / (".repo-" + ws.filename().string() + ".json");
}

json read_marker(const std::string& workspace) {
  std::ifstream in(marker_path(workspace));
  auto j = json::parse(in, nullptr, false);
  if (!j.is_object()) return json();
  const std::string full = j.value("full_name", "");
  const std::string session = fs::path(workspace).filename().string();
  if (!valid_full_name(full) || j.value("dir", "") != repo_dir_name(full) || j.value("branch", "") != "saga/" + session ||
      !valid_branch(j.value("base", "")))
    return json();
  return j;
}
}  // namespace

std::string Harness::github_token(const std::string& uid, const secrets::Key& vault) {
  const json slot = account_keys().value(kCreds, json::object()).value(keyring(uid, vault), json::object())
                        .value("github", json::object());
  return open_slot(slot.value("secret", json()), vault, uid, "github");
}

proc::Result Harness::git(const std::string& uid, const std::string& workspace, const secrets::Key& vault,
                          const std::vector<std::string>& args, const std::string& token, int timeout_s) {
  std::vector<std::string> argv = {"git"};
  argv.insert(argv.end(), args.begin(), args.end());
  return git_argv(uid, workspace, vault, argv, token, timeout_s);
}

proc::Result Harness::git_argv(const std::string& uid, const std::string& workspace, const secrets::Key& vault,
                               const std::vector<std::string>& argv, const std::string& token, int timeout_s) {
  memwal::SecretScope sensitive(token);
  if (!token.empty()) sensitive.add(crypto::b64_encode("x-access-token:" + token));
  proc::Options o;
  o.timeout_s = timeout_s;
  o.merge_stderr = true;
  std::map<std::string, std::string> env = token.empty() ? std::map<std::string, std::string>{}
                                                        : github::git_env(token);
  env["GIT_TERMINAL_PROMPT"] = "0";
  env["GIT_CONFIG_GLOBAL"] = "/dev/null";  // in a sandbox, ~/.gitconfig is the agents' to write
  if (auto sb = sandbox_for(uid, workspace, vault, "git")) {
    for (auto& [k, v] : env) sb->env[k] = v;
    auto result = sandbox::run(*sb, argv, o);
    result.out = memwal::redact_secrets(result.out);
    result.err = memwal::redact_secrets(result.err);
    return result;
  }
  o.cwd = workspace;
  o.env = env;
  return proc::run(argv, o);
}

std::string Harness::repo_context(const Turn& t) {
  const json m = read_marker(t.workspace);
  if (m.is_null()) return "";
  const std::string root = opt_.user_accounts ? std::string(sandbox::kWork) : t.workspace;
  return "\n## Repository\nThis chat is working on the GitHub repo " + m.value("full_name", "") + ", cloned at " + root +
         "/" + m.value("dir", "") + " on branch `" + m.value("branch", "") + "` (base `" + m.value("base", "") +
         "`). When the current request needs repository work, run repository commands in that directory, "
         "not the shared workspace root. When asked to change code, make changes there and commit them with "
         "clear messages (`git add` / `git commit`). Having an attached repository does not require inspecting "
         "or changing it to answer a question about recalled past work. Do not push or "
         "change branches — the user opens the pull request from Saga.\n";
}

json Harness::github_status(const std::string& uid, const secrets::Key& vault) {
  const std::string ring = keyring(uid, vault);
  const json slot = account_keys().value(kCreds, json::object()).value(ring, json::object())
                        .value("github", json::object());
  auto who = json::parse(open_slot(slot.value("who", json()), vault, uid, "github"), nullptr, false);
  std::string token = github_token(uid, vault);
  secrets::WipeString wipe{token};
  if (slot.contains("login") && vault.size() == 32 && !token.empty()) {
    // An older slot kept the GitHub username in the clear: seal it now that the key is here.
    who = {{"login", slot.value("login", "")}, {"id", slot.value("id", 0)}};
    update_keys(opt_.keys_path, [&](json& keys) {
      json& g = keys[kCreds][ring]["github"];
      g["who"] = make_slot(who.dump(), vault, uid, "github");
      g.erase("login");
      g.erase("id");
    });
  }
  json out = {{"connected", !slot.empty()},
              {"login", who.is_object() ? who.value("login", "") : slot.value("login", "")},  // older slots kept it plain
              {"unlocked", !token.empty()},
              {"device_available", !opt_.github_client_id.empty()},
              {"oauth_available", !opt_.github_client_id.empty() && !opt_.github_client_secret.empty()}};
  std::lock_guard lk(mu_);
  if (auto it = gh_device_.find(ring); it != gh_device_.end()) {
    out["device"] = {{"status", it->second->status}, {"url", it->second->url}, {"code", it->second->code},
                     {"error", it->second->error}};
  }
  return out;
}

json Harness::github_set_token(const std::string& uid, const std::string& token, const secrets::Key& vault,
                               const std::string& source, const std::atomic<bool>* cancelled, bool remember) {
  if (!keeps_credentials(uid, vault)) return kWalletOnly;
  if (vault.size() != 32) return {{"error", "unlock your vault first (sign in again)"}};
  const auto context = operation_cancel(uid);
  if (!cancelled) cancelled = context.get();
  std::string t = token.substr(0, 400);
  secrets::WipeString wipe{t};
  json me;
  try {
    me = github::user(t, cancelled);  // proves the token works before we keep it
  } catch (const std::exception& e) {
    return {{"error", std::string("GitHub rejected the token: ") + e.what()}};
  }
  // Who the token belongs to is sealed with it: nothing about the account sits on disk in the clear.
  const json who = {{"login", me.value("login", "")}, {"id", me.value("id", 0)}};
  const json slot = {{"secret", make_slot(t, vault, uid, "github")},
                     {"who", make_slot(who.dump(), vault, uid, "github")},
                     {"source", source == "oauth" ? "oauth" : "pat"}};
  if (context->load() || !save_connection(uid, "github", slot, remember, false, cancelled))
    return {{"error", "couldn't save the GitHub token on the Saga host"}};
  return {{"ok", true}, {"login", me.value("login", "")}};
}

std::string Harness::github_authorize_url(const std::string& redirect_uri, const std::string& state) const {
  if (opt_.github_client_id.empty() || opt_.github_client_secret.empty()) return "";
  return github::authorize_url(opt_.github_client_id, redirect_uri, state);
}

json Harness::github_oauth_finish(const std::string& uid, const std::string& code, const std::string& redirect_uri,
                                  const secrets::Key& vault, bool remember) {
  const auto cancelled = operation_cancel(uid);
  if (opt_.github_client_id.empty() || opt_.github_client_secret.empty())
    return {{"error", "GitHub sign-in isn't set up on this Saga server"}};
  json r;
  try {
    r = github::exchange_code(opt_.github_client_id, opt_.github_client_secret, code, redirect_uri);
  } catch (const std::exception& e) {
    return {{"error", std::string("couldn't reach GitHub: ") + e.what()}};
  }
  if (!r.contains("access_token")) return {{"error", "GitHub didn't approve the connection: " + r.value("error_description", r.value("error", "unknown error"))}};
  return github_set_token(uid, r.value("access_token", ""), vault, "oauth", cancelled.get(), remember);
}

json Harness::github_device(const std::string& uid, const secrets::Key& vault, bool remember) {
  const auto cancelled = operation_cancel(uid);
  if (!keeps_credentials(uid, vault)) return kWalletOnly;
  if (vault.size() != 32) return {{"error", "unlock your vault first (sign in again)"}};
  if (opt_.github_client_id.empty()) return {{"error", "GitHub sign-in isn't configured here — use a token"}};
  json start;
  try {
    start = github::device_start(opt_.github_client_id);
  } catch (const std::exception& e) {
    return {{"error", e.what()}};
  }
  auto st = std::make_shared<DeviceLogin>();
  st->url = start.value("verification_uri", "https://github.com/login/device");
  st->code = start.value("user_code", "");
  st->status = "waiting";
  {
    std::lock_guard lk(mu_);
    if (cancelled->load()) return {{"error", "GitHub sign-in was cancelled"}};
    if (auto it = gh_device_.find(keyring(uid, vault)); it != gh_device_.end()) it->second->cancel = true;
    gh_device_[keyring(uid, vault)] = st;
    // Poll until the user approves; the vault key lives only in this thread's memory meanwhile.
    if (!spawn_locked([this, uid, st, vault, remember, device = start.value("device_code", ""),
                       interval = start.value("interval", 5), expires = start.value("expires_in", 900)] {
      int wait = std::max(5, interval);
      for (int elapsed = 0; elapsed < expires; elapsed += wait) {
        if (st->cancel) return;
        for (int tick = 0; tick < wait * 10 && !st->cancel; ++tick)
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (st->cancel) return;
        const json r = github::device_poll(opt_.github_client_id, device, &st->cancel);
        if (st->cancel) return;
        const std::string err = r.value("error", "");
        if (err == "authorization_pending") continue;
        if (err == "slow_down") {
          wait += 5;
          continue;
        }
        const json res = err.empty() ? github_set_token(uid, r.value("access_token", ""), vault, "oauth", &st->cancel, remember)
                                     : json{{"error", r.value("error_description", err)}};
        std::lock_guard lk2(mu_);
        st->status = res.contains("error") ? "failed" : "done";
        st->error = res.value("error", "");
        return;
      }
      std::lock_guard lk2(mu_);
      st->status = "failed";
      st->error = "the code expired";
    })) {
      st->status = "failed";
      st->error = "the server is busy — try again shortly";
      return {{"error", st->error}};
    }
  }
  return {{"ok", true}, {"url", st->url}, {"code", st->code}};
}

json Harness::github_disconnect(const std::string& uid, const secrets::Key& vault) {
  const std::string ring = keyring(uid, vault);
  {
    std::lock_guard lk(mu_);
    if (auto it = gh_device_.find(ring); it != gh_device_.end()) it->second->cancel = true;
    gh_device_.erase(ring);
  }
  const json old = account_keys().value(kCreds, json::object()).value(ring, json::object())
                       .value("github", json::object());
  std::string token = open_slot(old.value("secret", json()), vault, uid, "github");
  secrets::WipeString wipe{token};
  cancel_active(uid);
  const bool oauth = old.value("source", "") == "oauth" || token.starts_with("gho_");
  const bool had = !old.empty();
  if (!forget_connection(uid, "github")) return {{"error", "couldn't delete the GitHub credential on the Saga host"}};
  const bool gone = !account_keys().value(kCreds, json::object()).value(ring, json::object()).contains("github");
  json out = {{"ok", gone}, {"deleted", had ? json::array({"github token"}) : json::array()}};
  if (had && oauth) {
    if (token.empty()) {
      out["revoked"] = false;
      out["revocation_error"] = "GitHub authorization is locked; revoke Saga in GitHub settings";
    } else if (!opt_.github_client_id.empty() && !opt_.github_client_secret.empty()) {
      try { github::revoke_grant(opt_.github_client_id, opt_.github_client_secret, token); out["revoked"] = true; }
      catch (const std::exception&) {
        out["revoked"] = false;
        out["revocation_error"] = "GitHub authorization could not be revoked; revoke Saga in GitHub settings";
      }
    } else {
      out["revoked"] = false;
      out["revocation_error"] = "Revoke Saga in GitHub settings; this server has no OAuth app secret";
    }
  }
  return out;
}

json Harness::github_repos(const std::string& uid, const secrets::Key& vault) {
  std::string token = github_token(uid, vault);
  secrets::WipeString wipe{token};
  if (token.empty()) return {{"error", "connect GitHub first"}};
  try {
    return {{"repos", github::repos(token)}};
  } catch (const std::exception& e) {
    return {{"error", e.what()}};
  }
}

json Harness::github_attach(const std::string& uid, const std::string& session, const std::string& full_name,
                             const secrets::Key& vault) {
  if (!valid_full_name(full_name)) return {{"error", "pick a repository"}};
  std::string token = github_token(uid, vault);
  secrets::WipeString wipe{token};
  if (token.empty()) return {{"error", "connect GitHub first"}};
  const std::string ws = workspace_for(uid, session);
  if (auto m = read_marker(ws); !m.is_null()) return {{"error", "this chat already works on " + m.value("full_name", "")}};
  json meta, me;
  try {
    meta = github::api(token, "GET", "/repos/" + full_name);
    me = github::user(token);
  } catch (const std::exception& e) {
    return {{"error", e.what()}};
  }
  if (!meta.value("permissions", json::object()).value("push", false))
    return {{"error", "this GitHub account cannot push to that repository"}};
  const std::string dir = repo_dir_name(full_name), base = meta.value("default_branch", "main");
  const std::string branch = "saga/" + session;
  auto run = [&](std::vector<std::string> args, bool auth, int timeout = 120) {
    return git(uid, ws, vault, args, auth ? token : "", timeout);
  };
  std::error_code ec;
  if (fs::exists(fs::path(ws) / dir / ".git", ec)) {
    // Already cloned here (chats attached before the repo record moved out of the workspace).
    if (run({"-C", dir, "checkout", branch}, false).exit_code != 0) run({"-C", dir, "checkout", "-b", branch}, false);
  } else {
    auto p = run({"clone", "--filter=blob:none", "https://github.com/" + full_name + ".git", dir}, true, 600);
    if (p.exit_code != 0) return {{"error", "clone failed: " + p.out.substr(0, 240)}};
    run({"-C", dir, "checkout", "-b", branch}, false);
  }
  run({"-C", dir, "config", "user.name", me.value("login", "saga")}, false);
  run({"-C", dir, "config", "user.email",
       std::to_string(me.value("id", 0)) + "+" + me.value("login", "saga") + "@users.noreply.github.com"},
      false);
  const json marker = {{"full_name", full_name}, {"dir", dir}, {"branch", branch}, {"base", base},
                       {"private", meta.value("private", false)}};
  std::ofstream(marker_path(ws)) << marker.dump(2);
  return {{"ok", true}, {"repo", marker}};
}

json Harness::github_repo(const std::string& uid, const std::string& session, const secrets::Key& vault) {
  const std::string ws = workspace_for(uid, session);
  json m = read_marker(ws);
  if (m.is_null()) return {{"repo", nullptr}};
  const std::string dir = m.value("dir", "");
  auto dirty = git(uid, ws, vault, {"-C", dir, "status", "--porcelain"});
  auto ahead = git(uid, ws, vault, {"-C", dir, "rev-list", "--count", "origin/" + m.value("base", "main") + "..HEAD"});
  int changed = 0;
  for (char c : dirty.out) changed += c == '\n';
  m["uncommitted"] = changed;
  try {
    m["commits"] = std::stoi(ahead.out);
  } catch (...) {
    m["commits"] = 0;
  }
  return {{"repo", m}};
}

json Harness::github_open_pr(const std::string& uid, const std::string& session, const std::string& title,
                              const secrets::Key& vault) {
  const std::string ws = workspace_for(uid, session);
  const json m = read_marker(ws);
  if (m.is_null()) return {{"error", "this chat has no repository"}};
  std::string token = github_token(uid, vault);
  secrets::WipeString wipe{token};
  if (token.empty()) return {{"error", "connect GitHub first"}};
  try {
    const json repo = github::api(token, "GET", "/repos/" + m.value("full_name", ""));
    if (!repo.value("permissions", json::object()).value("push", false))
      return {{"error", "this GitHub account can no longer push to that repository"}};
  } catch (const std::exception& e) { return {{"error", e.what()}}; }
  const std::string dir = m.value("dir", ""), branch = m.value("branch", ""), base = m.value("base", "main");
  const std::string full = m.value("full_name", ""), owner = full.substr(0, full.find('/'));
  const std::string t = title.empty() ? "Changes from Saga" : title.substr(0, 200);

  // Anything the agents left uncommitted goes into one last commit.
  if (!git(uid, ws, vault, {"-C", dir, "status", "--porcelain"}).out.empty()) {
    git(uid, ws, vault, {"-C", dir, "add", "-A"});
    git(uid, ws, vault, {"-C", dir, "commit", "-m", "Saga: " + t});
  }
  const auto log = git(uid, ws, vault, {"-C", dir, "log", "--oneline", "origin/" + base + "..refs/heads/" + branch});
  if (log.out.empty()) return {{"error", "no commits yet — ask an agent to make a change first"}};

  // The agents' clone is theirs: its config, hooks, filters or fsmonitor could run code, point git at
  // a proxy, or rewrite the remote while the token is in git's environment. So the push happens from
  // a fresh blob-less clone of GitHub, which fetches only the branch's new commits from the agents'
  // clone (with the token unset) and never reads its config.
  const bool sandboxed = opt_.user_accounts;
  fs::path scratch;
  if (!sandboxed) {
    std::string tmpl = (fs::temp_directory_path() / "saga-push-XXXXXX").string();
    if (!::mkdtemp(tmpl.data())) return {{"error", "push failed: no temporary directory"}};
    scratch = tmpl;
  }
  const std::string clean = sandboxed ? "/tmp/saga-push" : (scratch / "repo.git").string();
  const std::string src = (sandboxed ? std::string(sandbox::kWork) : ws) + "/" + dir;
  const char* script =
      "set -e\n"
      "git clone -q --bare --filter=blob:none \"$1\" \"$4\"\n"
      "env -u GIT_CONFIG_COUNT -u GIT_CONFIG_KEY_0 -u GIT_CONFIG_VALUE_0 \\\n"
      "  git -C \"$4\" fetch -q --no-tags \"$3\" \"+refs/heads/$2:refs/heads/$2\"\n"
      "git -C \"$4\" -c core.hooksPath=/dev/null push -q \"$1\" \"refs/heads/$2:refs/heads/$2\"\n";
  const auto push = git_argv(uid, ws, vault,
                             {"sh", "-c", script, "saga-push", "https://github.com/" + full + ".git", branch, src, clean},
                             token, 300);
  if (!scratch.empty()) {
    std::error_code ec;
    fs::remove_all(scratch, ec);
  }
  if (push.exit_code != 0) return {{"error", "push failed: " + push.out.substr(0, 240)}};
  try {
    json pr = github::find_pr(token, full, owner, branch);
    bool created = false;
    if (pr.is_null()) {
      std::string body = "Opened from a [Saga](https://github.com/MystenLabs/MemWal) chat — agents that remember, on Walrus.\n\n**Commits**\n";
      std::istringstream in(log.out);
      for (std::string line; std::getline(in, line);) body += "- " + line + "\n";
      pr = github::create_pr(token, full, branch, base, t, body);
      created = true;
    }
    return {{"ok", true}, {"url", pr.value("html_url", "")}, {"number", pr.value("number", 0)}, {"created", created}};
  } catch (const std::exception& e) {
    return {{"error", std::string("pushed, but the PR failed: ") + e.what()}};
  }
}

}  // namespace saga::harness

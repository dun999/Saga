#include "harness/harness.h"
#include "core/http.h"
#include "memwal/redact.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
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
json make_slot(const std::string& value, const secrets::Key& vault);
std::string open_slot(const json& slot, const secrets::Key& vault);
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
  for (auto& part : fs::path(rel))
    if (part == "..") return false;
  return true;
}

json memories_json(const std::vector<memwal::Memory>& ms) {
  json arr = json::array();
  for (auto& m : ms) arr.push_back({{"text", clip(m.text, 300)}, {"distance", m.distance}, {"blob_id", m.blob_id}});
  return arr;
}

bool is_capacity_error(const std::string& e) {
  static const std::regex re("usage limit|balance exhausted|402|429|rate.?limit|quota|not supported|"
                             "not found on PATH|not set|unauthori[sz]ed|401|connect to server|resolve host|limit reached|not connected",
                             std::regex::icase);
  return std::regex_search(e, re);
}

std::optional<json> parse_json_object(const std::string& text) {
  const auto l = text.find('{'), r = text.rfind('}');
  if (l == std::string::npos || r == std::string::npos || r < l) return std::nullopt;
  auto j = json::parse(text.substr(l, r - l + 1), nullptr, false);
  if (!j.is_object()) return std::nullopt;
  return j;
}

}  // namespace

json model_options(const std::string& kind);

// Restore runs on the host, outside the sandbox, into a directory agents control. Every step is
// opened relative to its parent with O_NOFOLLOW, so a symlink an agent planted (or swaps in mid-way)
// can't redirect the write, and a hard-linked file is refused rather than truncated.
bool write_in_workspace(const std::string& root, const std::string& rel, const std::string& content) {
  if (!safe_relative(rel)) return false;
  std::vector<std::string> parts;
  for (auto& part : fs::path(rel))
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

std::string ns_user(const std::string& uid, const char* what) { return "u:" + uid + ":" + what; }
std::string ns_lessons(const std::string& agent, const std::string& uid) {
  return ns_user(uid, "lessons") + ":" + agent;
}

// Injected into every agent's context: what Saga's memory is and how to use it.
std::string memory_protocol(const std::string& uid, const std::string& agent, bool can_run_shell,
                            const std::string& saga_bin) {
  std::string p =
      "\n## Memory protocol — Walrus mainnet\n"
      "Saga has no database. Every memory is SEAL-encrypted by the Walrus Memory (MemWal) relayer and stored as "
      "a blob on Walrus mainnet, owned by this deployment's Sui MemWalAccount; recall is semantic search over "
      "those blobs. The sections above were already recalled for you. Namespaces:\n"
      "- " + ns_user(uid, "facts") + " — durable facts & preferences about the user\n"
      "- " + ns_user(uid, "episodes") + " — summaries of past turns\n"
      "- " + ns_user(uid, "chat") + " — full chat transcripts\n"
      "- " + ns_user(uid, "checkpoints") + " — snapshots of files you change (restorable)\n"
      "- " + ns_lessons(agent, uid) + " — lessons learned about how you should work\n"
      "- " + ns_user(uid, "skills") + ", " + ns_user(uid, "learning") + ":prompts, " +
      ns_user(uid, "improvements") + " — how Saga improves for this user\n"
      "- task:<turn> — the blackboard shared with teammates this turn\n"
      "Transcripts, checkpoints and episodes are saved automatically; you never need to save your own output.\n"
      "Never put a secret in memory: no passwords, API keys, tokens, private keys, seed phrases or anything that "
      "grants access. Memory is recalled into future conversations, possibly by someone else using this identity. "
      "If the user shares one, use it only for the task at hand, don't repeat it back, don't #remember it, and "
      "tell them it won't be kept. Saga strips recognisable secrets before anything reaches Walrus, including "
      "unlabelled 64-character hex strings. A wallet address already stored as an identity is kept.\n"
      "To save a NEW durable fact the user told you (preference, goal, constraint, name), write it on its own "
      "line as:\n#remember <one self-contained fact, third person, e.g. \"User deploys to Fly.io\">\n"
      "Use it sparingly, only for things worth knowing in a future conversation. Never store secrets, keys or "
      "passwords.\n";
  if (can_run_shell && !saga_bin.empty())
    p += "You can also query memory on demand from the shell:\n"
         "  " + saga_bin + " mem recall \"<query>\" [--ns <namespace>] [--limit N]\n"
         "  " + saga_bin + " mem remember \"<text>\" [--ns <namespace>]\n"
         "(default namespace: " + ns_user(uid, "facts") + "). Use recall when the user refers to something from "
         "the past that is not in the sections above.\n";
  return p;
}

Harness::Harness(agents::Registry& reg, memwal::Store& store, Options opt)
    : reg_(reg), store_(store), opt_(std::move(opt)) {}

Harness::Learning& Harness::learning_for(const std::string& uid) {
  Learning* learning;
  {
    std::lock_guard lk(learning_mu_);
    auto& slot = learning_[uid];
    if (!slot) slot = std::make_unique<Learning>(store_, uid);
    learning = slot.get();
  }
  std::call_once(learning->loaded, [&] {
    if (store_.enabled())
      for (const char* suffix : {":prompts", ":scores"}) {
        try { store_.client()->restore(ns_user(uid, "learning") + suffix, 50); } catch (...) {}
      }
    learning->pool.load();
  });
  return *learning;
}

PromptPool& Harness::prompts(const std::string& uid) { return learning_for(uid).pool; }

Harness::~Harness() {
  // Background work can queue more of it (reflection → evolution), so drain until nothing is left.
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
                                 } catch (const std::exception& e) {
                                   std::fprintf(stderr, "[background] %s\n", e.what());
                                 } catch (...) {
                                   std::fprintf(stderr, "[background] unknown error\n");
                                 }
                                 done->store(true);
                               }),
                               done});
  return true;
}

bool Harness::take_operator_run(const agents::Agent& agent) {
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
      if (fs::is_directory(fs::symlink_status(it->path(), ec))) sandbox::scrub_home(it->path().string());
  }
  say("learning namespaces load privately for each user");
}

std::string Harness::build_context(Turn& t, const agents::Agent& agent, const std::string& instruction,
                                   const std::vector<memwal::Memory>& facts,
                                   const std::vector<memwal::Memory>& episodes,
                                   const std::vector<memwal::Memory>& skills, std::vector<memwal::Memory> lessons,
                                   const Emit& emit) {
  (void)instruction;
  // A lesson that keeps hurting stays on Walrus but stops being used.
  std::erase_if(lessons, [&](const memwal::Memory& m) { return prompts(t.uid).credit_of("lesson:" + m.blob_id).muted(); });
  if (lessons.size() > 4) lessons.resize(4);
  if (!lessons.empty() && emit)
    emit({{"type", "recall"}, {"ns", ns_lessons(agent.name(), t.uid)}, {"items", memories_json(lessons)}});

  const PromptVersion& pv = prompts(t.uid).get(t.prompt_version);
  auto note = [&](const std::string& id, const std::string& text) {
    if (std::none_of(t.in_context.begin(), t.in_context.end(), [&](auto& x) { return x.first == id; }))
      t.in_context.push_back({id, text});
  };
  for (auto& r : pv.rules) note(r.id, r.text);
  for (auto& m : lessons)
    if (!m.blob_id.empty()) note("lesson:" + m.blob_id, m.text);

  std::string c = pv.prompt + "\n\n";
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
      c += " @" + r["name"].get<std::string>() + " (" + r["description"].get<std::string>() + ");";
  c += "\nTo hand part of the work to a teammate, write a line on its own: `@name <precise instruction>`. "
       "Only do this when it clearly helps; otherwise finish the work yourself.\n";
  if (agent.can_edit_files())
    c += "Shared workspace (every teammate sees the same files): " +
         (opt_.user_accounts ? std::string(sandbox::kWork) : t.workspace) + "\n";
  else
    c += "You cannot edit files; put any code inline in fenced blocks.\n";

  auto section = [&](const char* title, const std::vector<memwal::Memory>& ms) {
    if (ms.empty()) return;
    c += "\n## " + std::string(title) + "\n";
    for (auto& m : ms) c += "- " + clip(m.text, 400) + "\n";
  };
  section("What Saga remembers about this user (Walrus Memory)", facts);
  section("Relevant past episodes", episodes);
  section(("Lessons learned for @" + agent.name()).c_str(), lessons);
  section("Skills that worked before", skills);
  c += t.history;
  c += repo_context(t);
  // Shell access to memory needs the Walrus delegate key, which never enters a user's sandbox.
  c += memory_protocol(t.uid, agent.name(), agent.can_edit_files() && !opt_.user_accounts, opt_.saga_bin);

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

void Harness::run_step(Turn& t, Step& s, const std::string& context, const Emit& emit) {
  agents::Agent* agent = reg_.find(s.agent, t.uid);
  const size_t idx = &s - t.steps.data();
  const auto sb = sandbox_for(t.uid, t.workspace, t.vault);
  const sandbox::Sandbox* sbp = sb ? &*sb : nullptr;
  auto run_on = [&](agents::Agent* a) {
    agents::Task task{s.instruction, context, sbp ? sandbox::kWork : t.workspace, t.cancel.get(),
                      opt_.agent_timeout_s, {}, sbp};
    if (!sbp) {
      task.env = {{"SAGA_UID", t.uid}, {"SAGA_BIN", opt_.saga_bin}};
      if (!opt_.mem_sock.empty()) task.env["SAGA_MEM_SOCK"] = opt_.mem_sock;
    }
    task.model = model_pick(t.uid, a->name());
    if (!a->spec().owner.empty())  // the user's own API agent: unseal its key for this call only
      task.api_key = api_key_for(t.uid, a->name(), t.vault);
    return a->run(task, [&](const agents::Event& e) {
      if (emit) emit({{"type", "agent"}, {"step", idx}, {"agent", a->name()}, {"kind", e.type}, {"text", clip(e.text, 4000)}});
    });
  };

  // Gate on availability, the user's own sign-in and the provider's usage windows, then record
  // what actually ran.
  auto attempt = [&](agents::Agent* a) {
    agents::Result res;
    std::string why = a ? a->unavailable_reason() : "unknown agent";
    if (why.empty() && sbp && !a->account(sbp).value("connected", false))
      why = "@" + a->name() + " is not connected — connect your account in Agents";
    if (why.empty()) a->exhausted(sbp, &why);
    if (!why.empty()) {
      res.error = why;
      return res;
    }
    if (a && !take_operator_run(*a)) {
      res.error = "this Saga's daily budget for built-in agents is used up";
      return res;
    }
    res = run_on(a);
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
  std::vector<memwal::Memory> hits;
};

std::shared_ptr<Harness::PendingRecall> Harness::recall_async(std::string query, std::string ns,
                                                             memwal::RecallOptions opt) {
  auto r = std::make_shared<PendingRecall>();
  auto f = std::async(std::launch::async, [this, r, query = std::move(query), ns = std::move(ns), opt] {
    std::vector<memwal::Memory> hits;
    try {
      hits = store_.recall(query, ns, opt);
    } catch (...) {
    }
    std::lock_guard lk(r->mu);
    r->hits = std::move(hits);
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
  t->id = crypto::uuid4();
  t->uid = uid;
  t->session = session;
  t->message = message;
  t->workspace = workspace_for(uid, session);
  fs::create_directories(t->workspace);
  t->prompt_version = prompts(uid).choose().v;
  t->started = std::time(nullptr);
  // Implicit feedback: the next message often says how the last answer went ("no, that's wrong", "thanks").
  if (auto prev = last_turn(uid, session); prev && prev->done)
    if (const int sig = followup_signal(message); sig != 0)
      rate_later(prev, sig, "(implicit: the user's next message was \"" + clip(message, 200) + "\")");
  {
    std::lock_guard lk(mu_);
    prune_turns();
    turns_[t->id] = t;
  }
  // Follow-ups ("make it shorter", "no, the other one") only make sense next to what came before.
  t->history = session_history(uid, session);
  {
    std::lock_guard lk(mu_);
    session_turns_[uid + "/" + session].push_back(t->id);
  }
  if (emit) emit({{"type", "turn"}, {"turn_id", t->id}, {"prompt_version", t->prompt_version}, {"workspace", t->workspace}});
  trace("turn started");

  // Recall (parallel) — this is where memory does its work, and every answer waits for it. The reads
  // start together, and each agent's lessons are fetched as soon as it is known to be needed (a handoff's
  // while the previous agent is still working), so they overlap instead of queueing one after another.
  auto facts_r = recall_async(message, ns_user(uid, "facts"), {.limit = 10, .max_distance = 0.75, .recency_weight = 0.2});
  auto episodes_r = recall_async(message, ns_user(uid, "episodes"), {.limit = 3, .max_distance = 0.7});
  auto skills_r = recall_async(message, ns_user(uid, "skills"), {.limit = 2, .max_distance = 0.55});
  std::map<std::string, std::shared_ptr<PendingRecall>> lessons_r;
  auto want_lessons = [&](const std::string& agent, const std::string& instruction) {
    if (!lessons_r.contains(agent))
      lessons_r[agent] = recall_async(instruction, ns_lessons(agent, uid), {.limit = 6, .max_distance = 0.7});
  };
  auto await = [](const std::shared_ptr<PendingRecall>& r) {
    std::unique_lock lk(r->mu);
    r->cv.wait(lk, [&] { return r->done; });
    return r->hits;
  };
  // Learn from what the user just said (relayer-side fact extraction → one blob per fact).
  store_.analyze(ns_user(uid, "facts"), message);

  // Route: split @mentions into an ordered plan; agents can extend it with their own @handoffs.
  trace("recalls started");
  seed_user(uid);
  trace("user settings ready");
  const auto names = reg_.names(uid);
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

  for (auto& [seg, by] : queue) want_lessons(seg.agent, seg.instruction);
  const auto facts = await(facts_r), episodes = await(episodes_r), skills = await(skills_r);
  trace("facts/episodes/skills recalled");
  for (auto* ms : {&facts, &episodes, &skills})
    for (auto& m : *ms) t->recalled.push_back(m.text);
  if (emit) {
    if (!facts.empty()) emit({{"type", "recall"}, {"ns", ns_user(uid, "facts")}, {"items", memories_json(facts)}});
    if (!episodes.empty()) emit({{"type", "recall"}, {"ns", ns_user(uid, "episodes")}, {"items", memories_json(episodes)}});
    if (!skills.empty()) emit({{"type", "recall"}, {"ns", ns_user(uid, "skills")}, {"items", memories_json(skills)}});
  }

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

    agents::Agent* a = reg_.find(s.agent, uid);
    want_lessons(s.agent, s.instruction);
    auto lessons = await(lessons_r[s.agent]);  // usually already fetched while the previous agent worked
    trace("@" + s.agent + " lessons recalled");
    const std::string ctx = build_context(*t, a ? *a : *reg_.primary(), s.instruction, facts, episodes, skills,
                                          std::move(lessons), emit);
    const Snapshot before = snapshot(t->workspace);
    trace("@" + s.agent + " running");
    run_step(*t, s, ctx, emit);
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

    // Shared blackboard on Walrus: any teammate (now or in a later session) can recall it.
    store_.put("task:" + t->id, "blackboard",
               "@" + s.agent + " (" + (s.error.empty() ? "done" : "failed") + ") " + clip(s.instruction, 200) +
                   " → " + clip(s.error.empty() ? s.output : s.error, 800),
               t->id, uid);

    for (auto& h : router::find_handoffs(s.output, names)) {
      const bool dup = std::any_of(queue.begin(), queue.end(), [&](auto& q) {
        return q.first.agent == h.agent && q.first.instruction == h.instruction;
      });
      if (!dup && h.agent != s.agent) {
        queue.push_back({h, s.agent});
        want_lessons(h.agent, h.instruction);
      }
    }
  }

  // Episode memory: what happened, compactly, for future continuity.
  std::string ep = "Episode " + today() + ": user asked \"" + clip(message, 240) + "\". ";
  for (auto& s : t->steps)
    ep += "@" + s.agent + (s.fallback ? " (fallback)" : "") + (s.error.empty() ? " did: " : " failed: ") +
          clip(s.error.empty() ? s.output : s.error, 220) + " ";
  store_.put(ns_user(uid, "episodes"), "episode", ep);

  // Implicit feedback (Reflexion): a hard failure is a learning signal even without a thumbs-down.
  const bool failed = std::any_of(t->steps.begin(), t->steps.end(),
                                  [](auto& s) { return !s.error.empty() && !is_capacity_error(s.error); });
  if (failed && !t->cancel->load()) {
    std::lock_guard lk(mu_);
    if (!spawn_locked([this, t] { reflect(*t, -1, "(automatic: an agent step failed)"); }))
      std::fprintf(stderr, "[background] dropped a reflection: the server is busy\n");
  }

  const std::string final_text = t->steps.empty() ? "" : t->steps.back().output;

  // Transcript: the conversation itself lives on Walrus, so history survives any restart or machine.
  json steps = json::array();
  for (auto& s : t->steps)
    steps.push_back({{"agent", s.agent}, {"instruction", clip(s.instruction, 400)}, {"requested_by", s.requested_by},
                     {"fallback", s.fallback}, {"ok", s.error.empty()},
                     {"output", clip(s.error.empty() ? s.output : s.error, 6000)}});
  store_.put(ns_user(uid, "chat"), "chat",
             memwal::encode_record("chat", {{"session", session}, {"turn", t->id}, {"ts", std::time(nullptr)},
                                            {"user", clip(message, 4000)}, {"steps", steps},
                                            {"prompt_version", t->prompt_version}}),
             t->id);

  t->done = true;
  if (emit) emit({{"type", "done"}, {"turn_id", t->id}, {"final", clip(final_text, 20000)}});
  return t->id;
}

json Harness::reflect(const Turn& t, int rating, const std::string& comment) {
  agents::Agent* brain = reg_.brain();
  if (!brain) return {{"error", "no brain configured"}};

  std::string trace = "USER MESSAGE: " + clip(t.message, 1500) + "\n\nMEMORIES USED:\n";
  for (auto& m : t.recalled) trace += "- " + clip(m, 200) + "\n";
  trace += "\nSTEPS:\n";
  for (auto& s : t.steps)
    trace += "@" + s.agent + " ← \"" + clip(s.instruction, 300) + "\" (" + std::to_string(int(s.seconds)) + "s" +
             (s.fallback ? ", fallback" : "") + ")\n" +
             (s.error.empty() ? clip(s.output, 1800) : "ERROR: " + clip(s.error, 400)) + "\n\n";
  if (!t.in_context.empty()) {
    trace += "RULES AND LESSONS IN THE AGENTS' CONTEXT:\n";
    for (size_t i = 0; i < t.in_context.size(); ++i)
      trace += "[r" + std::to_string(i + 1) + "] " + clip(t.in_context[i].second, 240) + "\n";
    trace += "\n";
  }
  trace += "USER RATING: " + std::string(rating > 0 ? "👍 good" : "👎 bad") + "\nUSER COMMENT: " +
           (comment.empty() ? "(none)" : comment) + "\n";

  const auto sb = sandbox_for(t.uid, "", t.vault);
  auto r = brain->complete(
      "You are the reflection module of Saga, a multi-agent assistant harness (Reflexion-style verbal "
      "reinforcement). From one turn's trace and the user's rating, extract durable, specific lessons that will "
      "change future behaviour. Never restate the task; write reusable guidance. Reply with JSON only:\n"
      "{\"lessons\":[{\"agent\":\"<agent name>\",\"lesson\":\"...\"}],"
      "\"skill\":null or {\"name\":\"...\",\"when\":\"...\",\"how\":\"numbered steps incl. which @agents\"},"
      "\"critique\":\"what the system prompt should do differently, or empty if the turn was good\","
      "\"credit\":{\"r1\":\"helpful\" or \"harmful\"}}\n"
      "In credit, name only listed rules and lessons that clearly helped or hurt this turn; omit the rest.\n"
      "Only emit a skill for a successful multi-step procedure worth reusing. At most 3 lessons.",
      trace, sb ? &*sb : nullptr);
  if (!r.ok) return {{"error", r.error}};
  auto j = parse_json_object(r.text);
  if (!j) return {{"error", "reflection was not JSON"}, {"raw", clip(r.text, 400)}};

  json out = {{"lessons", json::array()}, {"skill", nullptr}, {"critique", ""}, {"credit", json::array()}};
  if (auto cr = j->value("credit", json::object()); cr.is_object())
    for (auto& [label, verdict] : cr.items()) {
      const size_t i = label.size() > 1 ? std::strtoul(label.c_str() + 1, nullptr, 10) : 0;
      if (i == 0 || i > t.in_context.size() || !verdict.is_string()) continue;
      const bool helpful = verdict.get<std::string>() == "helpful";
      prompts(t.uid).credit(t.in_context[i - 1].first, helpful);
      out["credit"].push_back({{"text", clip(t.in_context[i - 1].second, 160)}, {"helpful", helpful}});
    }
  for (auto& l : j->value("lessons", json::array())) {
    std::string agent = l.value("agent", reg_.primary()->name());
    if (agent.starts_with("@")) agent.erase(0, 1);
    if (!reg_.find(agent, t.uid)) agent = reg_.primary()->name();
    const std::string lesson = l.value("lesson", "");
    if (lesson.empty()) continue;
    store_.put(ns_lessons(agent, t.uid), "lesson", "Lesson for @" + agent + " (" + today() + "): " + lesson, t.id, t.uid);
    out["lessons"].push_back({{"agent", agent}, {"lesson", lesson}});
  }
  if (rating > 0 && j->contains("skill") && (*j)["skill"].is_object()) {
    const json& sk = (*j)["skill"];
    const std::string text = "Skill \"" + sk.value("name", "unnamed") + "\" — use when: " + sk.value("when", "") +
                             ". How: " + sk.value("how", "");
    store_.put(ns_user(t.uid, "skills"), "skill", text, t.id, t.uid);
    out["skill"] = sk;
  }
  const std::string critique = j->value("critique", "");
  if (rating < 0 && !critique.empty()) {
    prompts(t.uid).add_critique(critique);
    out["critique"] = critique;
    if (static_cast<int>(prompts(t.uid).pending_critiques()) >= opt_.evolve_every) {
      evolve_in_background(t.uid, t.vault);
      out["evolving"] = true;
    }
  }
  // The improvement itself is part of the record: what the harness learned, from which turn.
  store_.put(ns_user(t.uid, "improvements"), "improvement",
             memwal::encode_record("improvement", {{"ts", std::time(nullptr)}, {"uid", t.uid}, {"turn", t.id},
                                                   {"rating", rating}, {"comment", clip(comment, 300)}, {"result", out}}),
             t.id, t.uid);
  return out;
}

json Harness::feedback(const std::string& uid, const std::string& turn_id, int rating, const std::string& comment) {
  if (comment.size() > 4096) return {{"error", "comment must be at most 4096 bytes"}};
  std::shared_ptr<Turn> t;
  {
    std::lock_guard lk(mu_);
    auto it = turns_.find(turn_id);
    if (it == turns_.end() || it->second->uid != uid) return {{"error", "unknown turn (feedback is only accepted in the session that ran it)"}};
    t = it->second;
    if (t->user_rated) return {{"error", "already rated"}};
  }
  // What users say about answers is itself a preference worth remembering ("shorter please").
  if (!comment.empty()) store_.analyze(ns_user(t->uid, "facts"), "Feedback from the user about an answer: " + comment);
  return rate(t, rating, comment, false);
}

json Harness::rate(const std::shared_ptr<Turn>& t, int rating, const std::string& comment, bool implicit) {
  {
    std::lock_guard lk(mu_);
    if (t->user_rated || (implicit && t->rating != 0)) return {{"error", "already rated"}};
    t->rating = rating;
    t->user_rated = !implicit;
  }
  prompts(t->uid).score(t->prompt_version, rating, implicit);
  // Every rated turn becomes a replay case: a new prompt version has to handle it at least as well.
  std::string memory, answer;
  for (size_t i = 0; i < t->recalled.size() && i < 8; ++i) memory += "- " + clip(t->recalled[i], 300) + "\n";
  if (!t->steps.empty() && t->steps.back().error.empty()) answer = t->steps.back().output;
  store_.put(ns_user(t->uid, "cases"), "case",
             memwal::encode_record("case", {{"ts", std::time(nullptr)}, {"message", clip(t->message, 1500)},
                                            {"memory", memory}, {"answer", clip(answer, 2500)}, {"rating", rating},
                                            {"comment", clip(comment, 300)}, {"prompt_version", t->prompt_version}}));
  json out = reflect(*t, rating, comment);
  out["prompt_version"] = t->prompt_version;
  out["implicit"] = implicit;
  return out;
}

void Harness::rate_later(const std::shared_ptr<Turn>& t, int rating, const std::string& why) {
  std::lock_guard lk(mu_);
  if (!spawn_locked([this, t, rating, why] { rate(t, rating, why, true); }))
    std::fprintf(stderr, "[background] dropped a rating: the server is busy\n");
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

std::shared_ptr<Turn> Harness::last_turn(const std::string& uid, const std::string& session) {
  std::lock_guard lk(mu_);
  auto it = session_turns_.find(uid + "/" + session);
  if (it == session_turns_.end() || it->second.empty()) return nullptr;
  auto t = turns_.find(it->second.back());
  return t == turns_.end() ? nullptr : t->second;
}

std::string Harness::session_history(const std::string& uid, const std::string& session) {
  constexpr size_t kTurns = 4;
  std::vector<std::pair<std::string, std::string>> ex;  // user message, final answer
  {
    std::lock_guard lk(mu_);
    if (auto it = session_turns_.find(uid + "/" + session); it != session_turns_.end())
      for (auto& id : it->second)
        if (auto t = turns_.find(id); t != turns_.end() && t->second->done && !t->second->steps.empty())
          ex.push_back({t->second->message, t->second->steps.back().agent + ": " +
                                                (t->second->steps.back().error.empty() ? t->second->steps.back().output
                                                                                       : "(failed)")});
  }
  if (ex.empty()) {  // a chat reopened after a restart: its transcript is on Walrus
    for (auto& r : chat_transcript(uid, session)["turns"]) {
      const json steps = r.value("steps", json::array());
      if (!steps.empty()) ex.push_back({r.value("user", ""), steps.back().value("agent", "") + ": " + steps.back().value("output", "")});
    }
  }
  if (ex.empty()) return "";
  std::string h = "\n## This conversation so far\n";
  for (size_t i = ex.size() > kTurns ? ex.size() - kTurns : 0; i < ex.size(); ++i)
    h += "User: " + clip(ex[i].first, 600) + "\n@" + clip(ex[i].second, 1200) + "\n";
  return h;
}

std::vector<ReplayCase> Harness::replay_cases(const std::string& uid) {
  // Bad turns are what a new version should fix; good ones guard against breaking what worked.
  std::vector<ReplayCase> bad, good;
  for (auto& r : recall_records(ns_user(uid, "cases"), "case", "rated turn replay case", 20)) {
    ReplayCase c{r.value("message", ""), r.value("memory", ""), r.value("answer", ""), r.value("comment", ""),
                 r.value("rating", 0)};
    if (c.message.empty()) continue;
    (c.rating < 0 ? bad : good).push_back(std::move(c));
  }
  if (bad.size() > 3) bad.resize(3);
  for (auto& c : good)
    if (bad.size() < 5) bad.push_back(std::move(c));
  return bad;
}

json Harness::evolve_now(const std::string& uid, const std::vector<std::string>& critiques) {
  agents::Agent* brain = reg_.brain();
  if (!brain) return {{"error", "no brain configured"}};
  for (auto& c : critiques) prompts(uid).add_critique(c);
  const auto cases = replay_cases(uid);
  const auto sb = sandbox_for(uid, "", {});
  json r = prompts(uid).evolve(*brain, cases, sb ? &*sb : nullptr);
  if (!r.contains("error"))
    store_.put(ns_user(uid, "improvements"), "improvement",
               memwal::encode_record("improvement", {{"ts", std::time(nullptr)}, {"uid", uid}, {"rating", 0},
                                                     {"result", {{"evolved", r}}}}),
               "", uid);
  r["replay_cases"] = cases.size();
  return r;
}

void Harness::evolve_in_background(const std::string& uid, const secrets::Key& vault) {
  Learning& learning = learning_for(uid);
  if (learning.evolving.exchange(true)) return;
  std::lock_guard lk(mu_);
  if (!spawn_locked([this, uid, vault, &learning] {
    struct Done {
      std::atomic<bool>& flag;
      ~Done() { flag = false; }
    } done{learning.evolving};
    const auto cases = replay_cases(uid);
    json r = {{"error", "no brain configured"}};
    if (agents::Agent* brain = reg_.brain()) {
      const auto sb = sandbox_for(uid, "", vault);
      r = learning.pool.evolve(*brain, cases, sb ? &*sb : nullptr);
    }
    if (!r.contains("error"))
      store_.put(ns_user(uid, "improvements"), "improvement",
                 memwal::encode_record("improvement", {{"ts", std::time(nullptr)}, {"uid", uid}, {"rating", 0},
                                                       {"result", {{"evolved", r}}}}), "", uid);
  }))
    learning.evolving = false;
}

bool Harness::cancel(const std::string& uid, const std::string& turn_id) {
  std::lock_guard lk(mu_);
  auto it = turns_.find(turn_id);
  if (it == turns_.end() || it->second->uid != uid) return false;
  it->second->cancel->store(true);
  return true;
}

json Harness::memory_view(const std::string& uid, const std::string& query) {
  const std::string q = query.empty() ? "what matters about this user and how Saga should behave" : query;
  json lessons = json::array();
  for (auto* a : reg_.visible(uid))
    for (auto& m : store_.recall(q, ns_lessons(a->name(), uid), {.limit = 5}))
      lessons.push_back({{"agent", a->name()}, {"text", m.text}, {"blob_id", m.blob_id}, {"distance", m.distance}});
  return {
      {"facts", memories_json(store_.recall(q, ns_user(uid, "facts"), {.limit = 20}))},
      {"episodes", memories_json(store_.recall(q, ns_user(uid, "episodes"), {.limit = 8, .recent = true}))},
      {"lessons", lessons},
      {"skills", memories_json(store_.recall(q, ns_user(uid, "skills"), {.limit = 8}))},
      {"improvements", [&] {
         json arr = json::array();
         // Improvements quote the user's own comments, so each user sees only the ones their turns caused.
         for (auto& r : recall_records(ns_user(uid, "improvements"), "improvement", "harness improvement lesson critique", 30))
           if (r.value("uid", "") == uid && arr.size() < 15) arr.push_back(r);
         return arr;
       }()},
      {"prompts", prompts(uid).summary()},
  };
}

json Harness::memory_stats(const std::string& uid) {
  long blobs = 0, bytes = 0;
  if (auto* c = store_.enabled() ? store_.client() : nullptr)
    for (const char* k : {"facts", "episodes", "chat", "checkpoints", "settings", "cases"}) {
      try {
        const json s = c->stats(ns_user(uid, k));
        blobs += s.value("memory_count", 0L);
        bytes += s.value("storage_bytes", 0L);
      } catch (const std::exception&) {  // a namespace that was never written has no stats
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

std::string Harness::workspace_for(const std::string& uid, const std::string& session) const {
  const auto p = fs::absolute(fs::path(opt_.workspaces_dir) / uid / session);
  fs::create_directories(p);
  return p.string();
}

// `#remember <fact>` lines in any agent's output become user facts on Walrus.
void Harness::apply_directives(Turn& t, const Step& s, const Emit& emit) {
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
    store_.put(ns_user(t.uid, "facts"), "fact", clip(fact, 600));
    if (emit) emit({{"type", "remember"}, {"agent", s.agent}, {"text", clip(fact, 600)}});
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

json Harness::chat_history(const std::string& uid) {
  std::map<std::string, json> sessions;
  for (auto& r : recall_records(ns_user(uid, "chat"), "chat", "conversation with the user", 100)) {
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
  for (auto& [k, v] : sessions) arr.push_back(v);
  std::sort(arr.begin(), arr.end(), [](const json& a, const json& b) { return a["updated"] > b["updated"]; });
  return arr;
}

json Harness::chat_transcript(const std::string& uid, const std::string& session) {
  json turns = json::array();
  for (auto& r : recall_records(ns_user(uid, "chat"), "chat", "conversation with the user", 100))
    if (r.value("session", "") == session) turns.push_back(r);
  std::sort(turns.begin(), turns.end(), [](const json& a, const json& b) { return a["ts"] < b["ts"]; });
  return {{"session", session}, {"turns", turns}};
}

json Harness::checkpoints(const std::string& uid, const std::string& session) {
  json arr = json::array();
  for (auto& r : recall_records(ns_user(uid, "checkpoints"), "checkpoint", "workspace file checkpoint", 100)) {
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
  auto recs = recall_records(ns_user(uid, "checkpoints"), "checkpoint", "workspace file checkpoint", 100);
  std::sort(recs.begin(), recs.end(), [](const json& a, const json& b) { return a.value("ts", 0L) < b.value("ts", 0L); });
  std::map<std::string, std::string> latest;
  for (auto& r : recs) {
    if (r.value("session", "") != session) continue;
    for (auto& f : r.value("files", json::array()))
      if (f.contains("content") && safe_relative(f.value("path", ""))) latest[f["path"]] = f["content"];
  }
  const fs::path root = workspace_for(uid, session);
  json restored = json::array(), skipped = json::array();
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
    std::fprintf(stderr, "[keys] could not save %s: %s\n", path.c_str(), e.what());
    return false;
  }
}
// A secret slot in the keys file: {"sealed": …} under the user's vault key, or {"plain": …} only
// for local single-user runs without wallet sign-in (no vault key exists there).
json make_slot(const std::string& value, const secrets::Key& vault) {
  if (vault.size() == 32) return {{"sealed", secrets::seal(vault, value)}};
  return {{"plain", value}};
}
std::string open_slot(const json& slot, const secrets::Key& vault) {
  if (!slot.is_object()) return slot.is_string() ? slot.get<std::string>() : "";
  if (slot.contains("plain")) return slot.value("plain", "");
  if (vault.size() != 32 || !slot.contains("sealed")) return "";
  try {
    return secrets::open(vault, slot.value("sealed", ""));
  } catch (...) {
    return "";  // sealed under a different vault key
  }
}
std::string hint(const std::string& key) { return key.size() > 4 ? key.substr(key.size() - 4) : ""; }
}  // namespace

void Harness::seed_user(const std::string& uid) {
  {
    std::lock_guard lk(mu_);
    if (seeded_.contains(uid)) return;
    seeded_.insert(uid);
  }
  // If the relayer can't be reached, try again on the user's next request instead of leaving them
  // without their agents and model picks until a restart.
  bool failed = false;
  struct Retry {
    Harness* h;
    const std::string& uid;
    bool& failed;
    ~Retry() {
      if (!failed) return;
      std::lock_guard lk(h->mu_);
      h->seeded_.erase(uid);
    }
  } retry{this, uid, failed};
  // Today's runs per agent, rebuilt from the Walrus transcripts (idempotent, since seeding can repeat).
  auto chats = recall_records(ns_user(uid, "chat"), "chat", "conversation with the user", 100, &failed);
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
  if (auto picks = recall_records(ns_user(uid, "settings"), "models", "user model picks settings", 5, &failed);
      !picks.empty()) {
    // Name the object: before C++23 a range-for over a temporary's items() iterates freed memory.
    const json models = picks.front().value("models", json::object());
    std::lock_guard lk(mu_);
    for (auto& [agent, model] : models.items())
      if (model.is_string()) model_picks_[uid][agent] = model.get<std::string>();
  }
  // The user's own API agents.
  auto recs = recall_records(ns_user(uid, "settings"), "agents", "user api agents settings", 5, &failed);
  if (recs.empty()) return;
  for (auto& a : recs.front().value("agents", json::array())) {
    if (!a.is_object() || !a.contains("name") || !a["name"].is_string()) continue;
    agents::Spec spec = agents::spec_from_json(a);
    spec.kind = "openai";
    spec.owner = uid;
    spec.public_only = true;
    reg_.add(spec);
  }
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
// its session proves the owner and its signature derives the vault key, which stays in the browser, so
// the server only ever keeps sealed copies. A username is guest mode — anyone can type it — so it
// gets an empty keyring nothing is ever saved to. '~' never appears in a uid.
std::string Harness::keyring(const std::string& uid, const secrets::Key&) const {
  return is_wallet(uid) ? uid : uid + "~guest";
}

namespace {
const json kWalletOnly = {{"error", "Sign in with a wallet to connect accounts. Guest usernames can't keep credentials."}};
}

std::optional<sandbox::Sandbox> Harness::sandbox_for(const std::string& uid, const std::string& workspace,
                                                     const secrets::Key& vault) {
  if (!opt_.user_accounts || uid.empty()) return std::nullopt;
  const std::string ring = keyring(uid, vault);
  sandbox::Sandbox sb;
  sb.home = fs::absolute(fs::path(opt_.homes_dir) / ring).string();
  fs::create_directories(fs::path(sb.home) / ".codex");
  fs::permissions(sb.home, fs::perms::owner_all, fs::perm_options::replace);
  sb.workspace = workspace;
  sb.vault = vault;
  sb.runner = opt_.saga_bin;
  const json cred = read_keys(opt_.keys_path).value(kCreds, json::object()).value(ring, json::object())
                        .value("claude", json::object());
  const std::string value = open_slot(cred.value("secret", json()), vault);
  if (!value.empty() && cred.value("kind", "") == "oauth_token") sb.env["CLAUDE_CODE_OAUTH_TOKEN"] = value;
  if (!value.empty() && cred.value("kind", "") == "api_key") sb.env["ANTHROPIC_API_KEY"] = value;
  return sb;
}

json Harness::agents_view(const std::string& uid, const secrets::Key& vault) {
  seed_user(uid);
  const std::string ring = keyring(uid, vault);
  const json api_keys = read_keys(opt_.keys_path).value(ring, json::object());
  const auto sb = sandbox_for(uid, "", vault);
  const sandbox::Sandbox* sbp = sb ? &*sb : nullptr;
  json out = json::array();
  for (auto& r : reg_.roster(uid)) {
    const std::string name = r["name"];
    agents::Agent* a = reg_.find(name, uid);
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
      const std::string key = open_slot(api_keys.value(name, json()), vault);
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

json Harness::connect_agent(const std::string& uid, const std::string& name, const secrets::Key& vault) {
  agents::Agent* a = reg_.find(name);
  if (!a) return {{"error", "unknown agent"}};
  if (opt_.user_accounts && !is_wallet(uid)) return kWalletOnly;
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
  const auto sb = sandbox_for(uid, "", vault);
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
      a->invalidate(&sb);
      std::lock_guard lk2(mu_);
      st->status = p.exit_code == 0 ? "done" : "failed";
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
                             const std::string& value, const secrets::Key& vault) {
  if (!opt_.user_accounts) return {{"error", "this Saga runs agents on the operator's own accounts"}};
  if (!is_wallet(uid)) return kWalletOnly;
  if (vault.size() != 32) return {{"error", "unlock your vault first (sign in again)"}};
  agents::Agent* a = reg_.find(name);
  if (!a) return {{"error", "unknown agent"}};
  const std::string v = value.substr(0, 4096);
  const auto sb = sandbox_for(uid, "", vault);
  if (a->spec().kind == "claude-code") {
    // Tokens from `claude setup-token` start sk-ant-oat…, API keys sk-ant-api….
    if (kind == "oauth_token" && !v.starts_with("sk-ant-oat")) return {{"error", "that doesn't look like a token from `claude setup-token` (sk-ant-oat…)"}};
    if (kind == "api_key" && !v.starts_with("sk-ant-")) return {{"error", "that doesn't look like an Anthropic API key (sk-ant-…)"}};
    if (kind != "oauth_token" && kind != "api_key") return {{"error", "unknown credential type"}};
    const json slot = {{"kind", kind}, {"secret", make_slot(v, vault)}};
    if (!update_keys(opt_.keys_path, [&](json& keys) { keys[kCreds][keyring(uid, vault)]["claude"] = slot; }))
      return {{"error", "couldn't save the credential on the Saga host"}};
    a->invalidate(sb ? &*sb : nullptr);
    return {{"ok", true}};
  }
  if (a->spec().kind == "codex" && kind == "api_key") {
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
  // Disconnect deletes the credential outright (sealed or not).
  const std::string ring = keyring(uid, vault);
  const auto sb = sandbox_for(uid, "", vault);
  json deleted = json::array();
  if (a->spec().kind == "claude-code") {
    update_keys(opt_.keys_path, [&](json& keys) {
      if (keys.contains(kCreds) && keys[kCreds].contains(ring) && keys[kCreds][ring].contains("claude")) {
        keys[kCreds][ring].erase("claude");
        deleted.push_back("claude token / API key");
      }
    });
  } else {
    const std::string rel = a->spec().kind == "codex" ? ".codex/auth.json" : ".grok/auth.json";
    if (secrets::erase_file(sb->home, rel)) deleted.push_back(rel);
  }
  a->invalidate(&*sb);
  {
    std::lock_guard lk(mu_);
    device_.erase(ring + "/" + a->name());
  }
  const bool gone = a->spec().kind == "claude-code"
                        ? !read_keys(opt_.keys_path).value(kCreds, json::object()).value(ring, json::object()).contains("claude")
                        : !sandbox::has_login(*sb, a->spec().kind == "codex" ? ".codex/auth.json" : ".grok/auth.json");
  return {{"ok", gone}, {"deleted", deleted}};
}

json Harness::vault_status(const std::string& uid, const secrets::Key& vault) {
  if (vault.size() != 32) return {{"state", "missing"}};
  if (!is_wallet(uid)) return {{"state", "guest"}};  // guests keep no credentials
  const std::string id = secrets::key_id(vault);
  std::string known;
  update_keys(opt_.keys_path, [&](json& keys) {
    known = keys.value("#vault", json::object()).value(uid, "");
    if (known.empty()) keys["#vault"][uid] = known = id;  // first key for this user becomes their vault
  });
  return {{"state", known == id ? "ok" : "mismatch"}};
}

// The user's secrets were sealed under a key this browser can't reproduce: drop them and adopt this key.
// Only a wallet can do this: its session proves the owner. A guest username has nothing to reset.
json Harness::vault_reset(const std::string& uid, const secrets::Key& vault) {
  if (vault.size() != 32) return {{"error", "no vault key"}};
  if (!is_wallet(uid)) return {{"error", "only a wallet's vault can be reset"}};
  if (!update_keys(opt_.keys_path, [&](json& keys) {
        if (keys.contains(kCreds)) keys[kCreds].erase(uid);
        if (keys.contains(uid) && keys[uid].is_object())
          for (auto it = keys[uid].begin(); it != keys[uid].end();)
            it = it->is_object() && it->contains("sealed") ? keys[uid].erase(it) : std::next(it);
        keys["#vault"][uid] = secrets::key_id(vault);
      }))
    return {{"error", "couldn't update the vault on the Saga host"}};
  if (const auto sb = sandbox_for(uid, "", vault))
    for (auto& rel : sandbox::kLoginFiles) secrets::erase_file(sb->home, rel);
  for (auto* a : reg_.visible(uid)) a->invalidate(nullptr);
  return {{"ok", true}};
}

// The key for one of the user's own API agents, from their keyring. A local operator-mode Saga used
// to keep these under the bare uid in the clear; that spelling still works there.
std::string Harness::api_key_for(const std::string& uid, const std::string& agent, const secrets::Key& vault) {
  const json keys = read_keys(opt_.keys_path);
  std::string k = open_slot(keys.value(keyring(uid, vault), json::object()).value(agent, json()), vault);
  if (k.empty() && !opt_.user_accounts) {
    const json legacy = keys.value(uid, json::object()).value(agent, json());
    if (legacy.is_object() && legacy.contains("plain")) k = legacy.value("plain", "");
  }
  return k;
}

json Harness::probe_agent(const std::string& uid, const std::string& name, const secrets::Key& vault) {
  agents::Agent* a = reg_.find(name);
  if (!a) return {{"error", "unknown agent"}};
  const auto sb = sandbox_for(uid, "", vault);
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
  const std::string key = body.value("api_key", "");
  spec.key_hint = hint(key);
  if (spec.description.empty()) spec.description = spec.model + " via own API key";
  if (!http::is_https_url(spec.base_url))
    return {{"error", "remote API base URL must use HTTPS with no credentials, query or fragment"}};
  if (spec.model.empty()) return {{"error", "model is required"}};
  // A key is only kept sealed, under a wallet's vault.
  if (!key.empty() && !is_wallet(uid)) return kWalletOnly;
  if (!key.empty() && vault.size() != 32)
    return {{"error", "unlock your vault first (sign in again)"}};
  if (auto err = reg_.add(spec); !err.empty()) return {{"error", err}};

  if (!key.empty()) {
    const json slot = make_slot(key, vault);  // sealed only: its last 4 characters are shown from the opened key
    if (!update_keys(opt_.keys_path, [&](json& keys) { keys[keyring(uid, vault)][spec.name] = slot; })) {
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
  if (kind == "codex") return {"gpt-5.5"};
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
  const json slot = read_keys(opt_.keys_path).value(kCreds, json::object()).value(keyring(uid, vault), json::object())
                        .value("github", json::object());
  return open_slot(slot.value("secret", json()), vault);
}

proc::Result Harness::git(const std::string& uid, const std::string& workspace, const secrets::Key& vault,
                          const std::vector<std::string>& args, const std::string& token, int timeout_s) {
  std::vector<std::string> argv = {"git"};
  argv.insert(argv.end(), args.begin(), args.end());
  return git_argv(uid, workspace, vault, argv, token, timeout_s);
}

proc::Result Harness::git_argv(const std::string& uid, const std::string& workspace, const secrets::Key& vault,
                               const std::vector<std::string>& argv, const std::string& token, int timeout_s) {
  proc::Options o;
  o.timeout_s = timeout_s;
  o.merge_stderr = true;
  std::map<std::string, std::string> env = token.empty() ? std::map<std::string, std::string>{}
                                                        : github::git_env(token);
  env["GIT_TERMINAL_PROMPT"] = "0";
  env["GIT_CONFIG_GLOBAL"] = "/dev/null";  // in a sandbox, ~/.gitconfig is the agents' to write
  if (auto sb = sandbox_for(uid, workspace, vault)) {
    for (auto& [k, v] : env) sb->env[k] = v;
    return sandbox::run(*sb, argv, o);
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
         "`). Make changes there and commit them with clear messages (`git add` / `git commit`). Do not push or "
         "change branches — the user opens the pull request from Saga.\n";
}

json Harness::github_status(const std::string& uid, const secrets::Key& vault) {
  const std::string ring = keyring(uid, vault);
  const json slot = read_keys(opt_.keys_path).value(kCreds, json::object()).value(ring, json::object())
                        .value("github", json::object());
  auto who = json::parse(open_slot(slot.value("who", json()), vault), nullptr, false);
  if (slot.contains("login") && vault.size() == 32 && !github_token(uid, vault).empty()) {
    // An older slot kept the GitHub username in the clear: seal it now that the key is here.
    who = {{"login", slot.value("login", "")}, {"id", slot.value("id", 0)}};
    update_keys(opt_.keys_path, [&](json& keys) {
      json& g = keys[kCreds][ring]["github"];
      g["who"] = make_slot(who.dump(), vault);
      g.erase("login");
      g.erase("id");
    });
  }
  json out = {{"connected", !slot.empty()},
              {"login", who.is_object() ? who.value("login", "") : slot.value("login", "")},  // older slots kept it plain
              {"unlocked", !github_token(uid, vault).empty()},
              {"device_available", !opt_.github_client_id.empty()},
              {"oauth_available", !opt_.github_client_id.empty() && !opt_.github_client_secret.empty()}};
  std::lock_guard lk(mu_);
  if (auto it = gh_device_.find(ring); it != gh_device_.end()) {
    out["device"] = {{"status", it->second->status}, {"url", it->second->url}, {"code", it->second->code},
                     {"error", it->second->error}};
  }
  return out;
}

json Harness::github_set_token(const std::string& uid, const std::string& token, const secrets::Key& vault) {
  if (!is_wallet(uid)) return kWalletOnly;
  if (vault.size() != 32) return {{"error", "unlock your vault first (sign in again)"}};
  const std::string t = token.substr(0, 400);
  json me;
  try {
    me = github::user(t);  // proves the token works before we keep it
  } catch (const std::exception& e) {
    return {{"error", std::string("GitHub rejected the token: ") + e.what()}};
  }
  // Who the token belongs to is sealed with it: nothing about the account sits on disk in the clear.
  const json who = {{"login", me.value("login", "")}, {"id", me.value("id", 0)}};
  const json slot = {{"secret", make_slot(t, vault)}, {"who", make_slot(who.dump(), vault)}};
  if (!update_keys(opt_.keys_path, [&](json& keys) { keys[kCreds][keyring(uid, vault)]["github"] = slot; }))
    return {{"error", "couldn't save the GitHub token on the Saga host"}};
  return {{"ok", true}, {"login", me.value("login", "")}};
}

std::string Harness::github_authorize_url(const std::string& redirect_uri, const std::string& state) const {
  if (opt_.github_client_id.empty() || opt_.github_client_secret.empty()) return "";
  return github::authorize_url(opt_.github_client_id, redirect_uri, state);
}

json Harness::github_oauth_finish(const std::string& uid, const std::string& code, const std::string& redirect_uri,
                                  const secrets::Key& vault) {
  if (opt_.github_client_id.empty() || opt_.github_client_secret.empty())
    return {{"error", "GitHub sign-in isn't set up on this Saga server"}};
  json r;
  try {
    r = github::exchange_code(opt_.github_client_id, opt_.github_client_secret, code, redirect_uri);
  } catch (const std::exception& e) {
    return {{"error", std::string("couldn't reach GitHub: ") + e.what()}};
  }
  if (!r.contains("access_token")) return {{"error", "GitHub didn't approve the connection: " + r.value("error_description", r.value("error", "unknown error"))}};
  return github_set_token(uid, r.value("access_token", ""), vault);
}

json Harness::github_device(const std::string& uid, const secrets::Key& vault) {
  if (!is_wallet(uid)) return kWalletOnly;
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
    gh_device_[keyring(uid, vault)] = st;
    // Poll until the user approves; the vault key lives only in this thread's memory meanwhile.
    if (!spawn_locked([this, uid, st, vault, device = start.value("device_code", ""),
                       interval = start.value("interval", 5), expires = start.value("expires_in", 900)] {
      int wait = std::max(5, interval);
      for (int elapsed = 0; elapsed < expires; elapsed += wait) {
        std::this_thread::sleep_for(std::chrono::seconds(wait));
        const json r = github::device_poll(opt_.github_client_id, device);
        const std::string err = r.value("error", "");
        if (err == "authorization_pending") continue;
        if (err == "slow_down") {
          wait += 5;
          continue;
        }
        const json res = err.empty() ? github_set_token(uid, r.value("access_token", ""), vault)
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
  bool had = false;
  update_keys(opt_.keys_path, [&](json& keys) {
    had = keys.contains(kCreds) && keys[kCreds].contains(ring) && keys[kCreds][ring].contains("github");
    if (had) keys[kCreds][ring].erase("github");
  });
  {
    std::lock_guard lk(mu_);
    gh_device_.erase(ring);
  }
  const bool gone = !read_keys(opt_.keys_path).value(kCreds, json::object()).value(ring, json::object()).contains("github");
  return {{"ok", gone}, {"deleted", had ? json::array({"github token"}) : json::array()}};
}

json Harness::github_repos(const std::string& uid, const secrets::Key& vault) {
  const std::string token = github_token(uid, vault);
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
  const std::string token = github_token(uid, vault);
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
  const std::string token = github_token(uid, vault);
  if (token.empty()) return {{"error", "connect GitHub first"}};
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
    // Shipping the work is the clearest "this was good" a user gives.
    if (auto last = last_turn(uid, session); created && last && last->done)
      rate_later(last, 1, "(implicit: the user opened a pull request from this work)");
    return {{"ok", true}, {"url", pr.value("html_url", "")}, {"number", pr.value("number", 0)}, {"created", created}};
  } catch (const std::exception& e) {
    return {{"error", std::string("pushed, but the PR failed: ") + e.what()}};
  }
}

}  // namespace saga::harness

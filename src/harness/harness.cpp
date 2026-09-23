#include "harness/harness.h"
#include "memwal/redact.h"

#include <algorithm>
#include <cctype>
#include <chrono>
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
void write_keys(const std::string& path, const json& j);
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

constexpr const char* kSkillsNs = "harness:skills";
constexpr const char* kImprovementsNs = "harness:improvements";
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
    if (!it->is_regular_file() || it->file_size(ec) > 1'000'000) continue;
    std::ifstream in(it->path(), std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    snap[fs::relative(it->path(), root).string()] = crypto::sha256_hex(ss.str());
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

// Quota / auth failures mean "this backend can't serve right now", not "the task is bad".
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
std::string ns_user(const std::string& uid, const char* what) { return "u:" + uid + ":" + what; }
std::string ns_lessons(const std::string& agent) { return "agent:" + agent + ":lessons"; }

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
      "- " + ns_lessons(agent) + " — lessons learned about how you should work\n"
      "- harness:skills, harness:prompts, harness:improvements — how Saga improves itself\n"
      "- task:<turn> — the blackboard shared with teammates this turn\n"
      "Transcripts, checkpoints and episodes are saved automatically; you never need to save your own output.\n"
      "Never put a secret in memory: no passwords, API keys, tokens, private keys, seed phrases or anything that "
      "grants access. Memory is recalled into future conversations, possibly by someone else using this identity. "
      "If the user shares one, use it only for the task at hand, don't repeat it back, don't #remember it, and "
      "tell them it won't be kept. Saga also strips recognisable secrets before anything reaches Walrus.\n"
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
    : reg_(reg), store_(store), opt_(std::move(opt)), prompts_(store) {}

Harness::~Harness() {
  // Background work can queue more of it (reflection → evolution), so drain until nothing is left.
  for (;;) {
    std::vector<std::thread> bg;
    {
      std::lock_guard lk(mu_);
      bg.swap(background_);
    }
    if (bg.empty()) break;
    for (auto& t : bg)
      if (t.joinable()) t.join();
  }
}

void Harness::boot(const Emit& log) {
  auto say = [&](const std::string& m) {
    if (log) log({{"type", "log"}, {"text", m}});
  };
  if (store_.enabled()) {
    // The relayer's vector index is a cache; Walrus is the source of truth. Rebuild anything missing
    // for the namespaces every turn depends on.
    std::vector<std::string> hot = {"harness:prompts", "harness:scores", kSkillsNs};
    for (auto* a : reg_.all()) hot.push_back(ns_lessons(a->name()));
    std::vector<std::future<void>> jobs;
    for (auto& ns : hot) {
      jobs.push_back(std::async(std::launch::async, [&, ns] {
        try {
          auto r = store_.client()->restore(ns, 50);
          if (r.value("restored", 0) > 0) say("restored " + std::to_string(r.value("restored", 0)) + " from Walrus → " + ns);
        } catch (const std::exception& e) {
          say("restore " + ns + " skipped: " + clip(e.what(), 120));
        }
      }));
    }
    for (auto& j : jobs) j.get();
  }
  prompts_.load();
  const auto s = prompts_.summary();
  say("prompt population: " + std::to_string(s["versions"].size()) + " version(s)");
}

std::string Harness::build_context(Turn& t, const agents::Agent& agent, const std::string& instruction,
                                   const std::vector<memwal::Memory>& facts,
                                   const std::vector<memwal::Memory>& episodes,
                                   const std::vector<memwal::Memory>& skills, const Emit& emit) {
  auto lessons = store_.recall(instruction, ns_lessons(agent.name()), {.limit = 6, .max_distance = 0.7});
  // A lesson that keeps hurting stays on Walrus but stops being used.
  std::erase_if(lessons, [&](const memwal::Memory& m) { return prompts_.credit_of("lesson:" + m.blob_id).muted(); });
  if (lessons.size() > 4) lessons.resize(4);
  if (!lessons.empty() && emit)
    emit({{"type", "recall"}, {"ns", ns_lessons(agent.name())}, {"items", memories_json(lessons)}});

  const PromptVersion& pv = prompts_.get(t.prompt_version);
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
      task.api_key = open_slot(read_keys(opt_.keys_path).value(t.uid, json::object()).value(a->name(), json()), t.vault);
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

std::string Harness::chat(const std::string& uid, const std::string& session, const std::string& message,
                          const Emit& emit, const secrets::Key& vault) {
  auto t = std::make_shared<Turn>();
  t->vault = vault;
  t->id = crypto::uuid4();
  t->uid = uid;
  t->session = session;
  t->message = message;
  t->workspace = workspace_for(uid, session);
  fs::create_directories(t->workspace);
  t->prompt_version = prompts_.choose().v;
  // Implicit feedback: the next message often says how the last answer went ("no, that's wrong", "thanks").
  if (auto prev = last_turn(uid, session); prev && prev->done)
    if (const int sig = followup_signal(message); sig != 0)
      rate_later(prev, sig, "(implicit: the user's next message was \"" + clip(message, 200) + "\")");
  {
    std::lock_guard lk(mu_);
    turns_[t->id] = t;
  }
  // Follow-ups ("make it shorter", "no, the other one") only make sense next to what came before.
  t->history = session_history(uid, session);
  {
    std::lock_guard lk(mu_);
    session_turns_[uid + "/" + session].push_back(t->id);
  }
  if (emit) emit({{"type", "turn"}, {"turn_id", t->id}, {"prompt_version", t->prompt_version}, {"workspace", t->workspace}});

  // Recall (parallel) — this is where memory does its work.
  auto facts_f = std::async(std::launch::async, [&] {
    return store_.recall(message, ns_user(uid, "facts"), {.limit = 10, .max_distance = 0.75, .recency_weight = 0.2});
  });
  auto episodes_f = std::async(std::launch::async, [&] {
    return store_.recall(message, ns_user(uid, "episodes"), {.limit = 3, .max_distance = 0.7});
  });
  auto skills_f = std::async(std::launch::async, [&] {
    return store_.recall(message, kSkillsNs, {.limit = 2, .max_distance = 0.55});
  });
  const auto facts = facts_f.get(), episodes = episodes_f.get(), skills = skills_f.get();
  for (auto* ms : {&facts, &episodes, &skills})
    for (auto& m : *ms) t->recalled.push_back(m.text);
  if (emit) {
    if (!facts.empty()) emit({{"type", "recall"}, {"ns", ns_user(uid, "facts")}, {"items", memories_json(facts)}});
    if (!episodes.empty()) emit({{"type", "recall"}, {"ns", ns_user(uid, "episodes")}, {"items", memories_json(episodes)}});
    if (!skills.empty()) emit({{"type", "recall"}, {"ns", kSkillsNs}, {"items", memories_json(skills)}});
  }

  // Learn from what the user just said (relayer-side fact extraction → one blob per fact).
  store_.analyze(ns_user(uid, "facts"), message);

  // Route: split @mentions into an ordered plan; agents can extend it with their own @handoffs.
  seed_user(uid);
  const auto names = reg_.names(uid);
  std::vector<router::Segment> plan = router::split_mentions(message, names);
  if (plan.empty()) plan.push_back({"", message});
  std::vector<std::pair<router::Segment, std::string>> queue;  // segment, requested_by
  for (auto& seg : plan) queue.push_back({seg, "user"});

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
    const std::string ctx = build_context(*t, a ? *a : *reg_.primary(), s.instruction, facts, episodes, skills, emit);
    const Snapshot before = snapshot(t->workspace);
    run_step(*t, s, ctx, emit);

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
                   " → " + clip(s.error.empty() ? s.output : s.error, 800));

    for (auto& h : router::find_handoffs(s.output, names)) {
      const bool dup = std::any_of(queue.begin(), queue.end(), [&](auto& q) {
        return q.first.agent == h.agent && q.first.instruction == h.instruction;
      });
      if (!dup && h.agent != s.agent) queue.push_back({h, s.agent});
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
    background_.emplace_back([this, t] { reflect(*t, -1, "(automatic: an agent step failed)"); });
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
      prompts_.credit(t.in_context[i - 1].first, helpful);
      out["credit"].push_back({{"text", clip(t.in_context[i - 1].second, 160)}, {"helpful", helpful}});
    }
  for (auto& l : j->value("lessons", json::array())) {
    std::string agent = l.value("agent", reg_.primary()->name());
    if (agent.starts_with("@")) agent.erase(0, 1);
    if (!reg_.find(agent, t.uid)) agent = reg_.primary()->name();
    const std::string lesson = l.value("lesson", "");
    if (lesson.empty()) continue;
    store_.put(ns_lessons(agent), "lesson", "Lesson for @" + agent + " (" + today() + "): " + lesson);
    out["lessons"].push_back({{"agent", agent}, {"lesson", lesson}});
  }
  if (rating > 0 && j->contains("skill") && (*j)["skill"].is_object()) {
    const json& sk = (*j)["skill"];
    const std::string text = "Skill \"" + sk.value("name", "unnamed") + "\" — use when: " + sk.value("when", "") +
                             ". How: " + sk.value("how", "");
    store_.put(kSkillsNs, "skill", text);
    out["skill"] = sk;
  }
  const std::string critique = j->value("critique", "");
  if (rating < 0 && !critique.empty()) {
    prompts_.add_critique(critique);
    out["critique"] = critique;
    if (static_cast<int>(prompts_.pending_critiques()) >= opt_.evolve_every) {
      evolve_in_background(t.uid, t.vault);
      out["evolving"] = true;
    }
  }
  // The improvement itself is part of the record: what the harness learned, from which turn.
  store_.put(kImprovementsNs, "improvement",
             memwal::encode_record("improvement", {{"ts", std::time(nullptr)}, {"turn", t.id}, {"rating", rating},
                                                   {"comment", clip(comment, 300)}, {"result", out}}));
  return out;
}

json Harness::feedback(const std::string& turn_id, int rating, const std::string& comment) {
  std::shared_ptr<Turn> t;
  {
    std::lock_guard lk(mu_);
    auto it = turns_.find(turn_id);
    if (it == turns_.end()) return {{"error", "unknown turn (feedback is only accepted in the session that ran it)"}};
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
  prompts_.score(t->prompt_version, rating, implicit);
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
  background_.emplace_back([this, t, rating, why] { rate(t, rating, why, true); });
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
  for (auto& c : critiques) prompts_.add_critique(c);
  const auto cases = replay_cases(uid);
  const auto sb = sandbox_for(uid, "", {});
  json r = prompts_.evolve(*brain, cases, sb ? &*sb : nullptr);
  if (!r.contains("error"))
    store_.put(kImprovementsNs, "improvement",
               memwal::encode_record("improvement", {{"ts", std::time(nullptr)}, {"rating", 0}, {"result", {{"evolved", r}}}}));
  r["replay_cases"] = cases.size();
  return r;
}

void Harness::evolve_in_background(const std::string& uid, const secrets::Key& vault) {
  if (evolving_.exchange(true)) return;  // one evolution at a time; critiques keep queueing
  std::lock_guard lk(mu_);
  background_.emplace_back([this, uid, vault] {
    json r = {{"error", "no brain configured"}};
    if (agents::Agent* brain = reg_.brain()) {
      const auto sb = sandbox_for(uid, "", vault);
      r = prompts_.evolve(*brain, replay_cases(uid), sb ? &*sb : nullptr);
    }
    if (!r.contains("error"))
      store_.put(kImprovementsNs, "improvement",
                 memwal::encode_record("improvement", {{"ts", std::time(nullptr)}, {"rating", 0},
                                                       {"result", {{"evolved", r}}}}));
    evolving_ = false;
  });
}

bool Harness::cancel(const std::string& turn_id) {
  std::lock_guard lk(mu_);
  auto it = turns_.find(turn_id);
  if (it == turns_.end()) return false;
  it->second->cancel->store(true);
  return true;
}

json Harness::memory_view(const std::string& uid, const std::string& query) {
  const std::string q = query.empty() ? "what matters about this user and how Saga should behave" : query;
  json lessons = json::array();
  for (auto* a : reg_.visible(uid))
    for (auto& m : store_.recall(q, ns_lessons(a->name()), {.limit = 5}))
      lessons.push_back({{"agent", a->name()}, {"text", m.text}, {"blob_id", m.blob_id}, {"distance", m.distance}});
  return {
      {"facts", memories_json(store_.recall(q, ns_user(uid, "facts"), {.limit = 20}))},
      {"episodes", memories_json(store_.recall(q, ns_user(uid, "episodes"), {.limit = 8, .recent = true}))},
      {"lessons", lessons},
      {"skills", memories_json(store_.recall(q, kSkillsNs, {.limit = 8}))},
      {"improvements", [&] {
         json arr = json::array();
         for (auto& r : recall_records(kImprovementsNs, "improvement", "harness improvement lesson critique", 15))
           arr.push_back(r);
         return arr;
       }()},
      {"prompts", prompts_.summary()},
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
                                          int limit) {
  std::vector<json> out;
  for (auto& m : store_.recall(query, ns, {.limit = limit, .recent = true})) {
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
  json restored = json::array();
  for (auto& [path, content] : latest) {
    const fs::path dst = root / path;
    fs::create_directories(dst.parent_path());
    std::ofstream(dst, std::ios::binary) << content;
    restored.push_back(path);
  }
  return {{"session", session}, {"workspace", root.string()}, {"restored", restored}};
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
void write_keys(const std::string& path, const json& j) {
  fs::create_directories(fs::path(path).parent_path());
  const std::string tmp = path + ".tmp";
  { std::ofstream(tmp) << j.dump(2); }
  fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
  fs::rename(tmp, path);
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
  // Today's runs per agent, rebuilt from the Walrus transcripts.
  auto chats = recall_records(ns_user(uid, "chat"), "chat", "conversation with the user", 100);
  const std::time_t now = std::time(nullptr);
  std::tm tm{};
  gmtime_r(&now, &tm);
  tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
  const long midnight = static_cast<long>(timegm(&tm));
  {
    std::lock_guard lk(mu_);
    auto& u = usage_[uid];
    for (auto& c : chats) {
      if (c.value("ts", 0L) < midnight) continue;
      for (auto& st : c.value("steps", json::array())) {
        auto& e = u[st.value("agent", "")];
        e.day = today();
        e.runs++;
      }
    }
  }
  // The user's model picks.
  if (auto picks = recall_records(ns_user(uid, "settings"), "models", "user model picks settings", 5); !picks.empty()) {
    // Name the object: before C++23 a range-for over a temporary's items() iterates freed memory.
    const json models = picks.front().value("models", json::object());
    std::lock_guard lk(mu_);
    for (auto& [agent, model] : models.items())
      if (model.is_string()) model_picks_[uid][agent] = model.get<std::string>();
  }
  // The user's own API agents.
  auto recs = recall_records(ns_user(uid, "settings"), "agents", "user api agents settings", 5);
  if (recs.empty()) return;
  const json keys = read_keys(opt_.keys_path).value(uid, json::object());
  for (auto& a : recs.front().value("agents", json::array())) {
    agents::Spec spec = agents::spec_from_json(a);
    spec.kind = "openai";
    spec.owner = uid;
    const json slot = keys.value(spec.name, json());
    spec.key_hint = slot.is_object() ? slot.value("hint", "") : "";
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

std::string strip_ansi(const std::string& s) {
  static const std::regex ansi("\x1B\\[[0-9;?]*[A-Za-z]");
  return std::regex_replace(s, ansi, "");
}
}  // namespace

std::optional<sandbox::Sandbox> Harness::sandbox_for(const std::string& uid, const std::string& workspace,
                                                     const secrets::Key& vault) {
  if (!opt_.user_accounts || uid.empty()) return std::nullopt;
  sandbox::Sandbox sb;
  sb.home = fs::absolute(fs::path(opt_.homes_dir) / uid).string();
  fs::create_directories(fs::path(sb.home) / ".codex");
  fs::permissions(sb.home, fs::perms::owner_all, fs::perm_options::replace);
  sb.workspace = workspace;
  sb.vault = vault;
  const json cred = read_keys(opt_.keys_path).value(kCreds, json::object()).value(uid, json::object())
                        .value("claude", json::object());
  const std::string value = open_slot(cred.value("secret", json()), vault);
  if (!value.empty() && cred.value("kind", "") == "oauth_token") sb.env["CLAUDE_CODE_OAUTH_TOKEN"] = value;
  if (!value.empty() && cred.value("kind", "") == "api_key") sb.env["ANTHROPIC_API_KEY"] = value;
  return sb;
}

json Harness::agents_view(const std::string& uid, const secrets::Key& vault) {
  seed_user(uid);
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
      if (auto d = device_.find(uid + "/" + name); d != device_.end() && d->second->status == "waiting")
        r["device"] = {{"url", d->second->url}, {"code", d->second->code}};
    }
    out.push_back(r);
  }
  return out;
}

json Harness::connect_agent(const std::string& uid, const std::string& name, const secrets::Key& vault) {
  agents::Agent* a = reg_.find(name);
  if (!a) return {{"error", "unknown agent"}};
  if (opt_.user_accounts && vault.size() != 32) return {{"error", "unlock your vault first (sign in again)"}};

  if (!opt_.user_accounts) {
    // Operator mode: the provider's own browser sign-in on the Saga host.
    if (a->login_argv().empty()) return {{"error", "this agent has no sign-in flow"}};
    std::string cmd;
    for (auto& p : a->login_argv()) cmd += (cmd.empty() ? "" : " ") + p;
    std::lock_guard lk(mu_);
    if (connecting_.contains(a->name())) return {{"ok", true}, {"command", cmd}, {"already", true}};
    connecting_.insert(a->name());
    background_.emplace_back([this, a] {
      proc::Options o;
      o.timeout_s = 600;
      proc::run(a->login_argv(), o);
      a->invalidate(nullptr);
      std::lock_guard lk2(mu_);
      connecting_.erase(a->name());
    });
    return {{"ok", true}, {"command", cmd}};
  }

  // User mode: device-code sign-in inside the user's sandbox, so the login lands in their home.
  if (a->device_login_argv().empty()) return {{"error", "@" + name + " connects with a token or API key"}};
  const std::string key = uid + "/" + a->name();
  auto st = std::make_shared<DeviceLogin>();
  {
    std::lock_guard lk(mu_);
    if (auto it = device_.find(key); it != device_.end() && it->second->status == "waiting")
      return {{"ok", true}, {"url", it->second->url}, {"code", it->second->code}};
    device_[key] = st;
  }
  const auto sb = sandbox_for(uid, "", vault);
  auto ready = std::make_shared<std::promise<void>>();
  auto fut = ready->get_future();
  {
    std::lock_guard lk(mu_);
    background_.emplace_back([this, a, st, sb = *sb, ready] {
      static const std::regex url_re(R"(https://[^\s]+)"), code_re(R"(\b[A-Z0-9]{4}-[A-Z0-9]{4,6}\b)");
      bool signalled = false;
      proc::Options o;
      o.timeout_s = 900;  // device codes expire in 15 minutes
      o.merge_stderr = true;
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
        p = proc::run(sandbox::wrap(sb, a->device_login_argv()), o);
      }
      a->invalidate(&sb);
      std::lock_guard lk2(mu_);
      st->status = p.exit_code == 0 ? "done" : "failed";
      if (p.exit_code != 0) st->error = p.timed_out ? "sign-in timed out" : strip_ansi(p.out).substr(0, 240);
      if (!signalled) ready->set_value();
    });
  }
  // Hand the URL + code to the browser as soon as the CLI prints them; the CLI keeps waiting.
  fut.wait_for(std::chrono::seconds(25));
  std::lock_guard lk(mu_);
  if (st->status == "waiting") return {{"ok", true}, {"url", st->url}, {"code", st->code}};
  return {{"error", st->error.empty() ? "@" + name + " did not start a sign-in" : st->error}};
}

json Harness::connect_status(const std::string& uid, const std::string& name) {
  std::lock_guard lk(mu_);
  auto it = device_.find(uid + "/" + name);
  if (it == device_.end()) return {{"status", "none"}};
  return {{"status", it->second->status}, {"error", it->second->error}};
}

json Harness::set_credential(const std::string& uid, const std::string& name, const std::string& kind,
                             const std::string& value, const secrets::Key& vault) {
  if (!opt_.user_accounts) return {{"error", "this Saga runs agents on the operator's own accounts"}};
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
    json keys = read_keys(opt_.keys_path);
    keys[kCreds][uid]["claude"] = {{"kind", kind}, {"secret", make_slot(v, vault)}, {"hint", hint(v)}};
    write_keys(opt_.keys_path, keys);
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
      p = proc::run(sandbox::wrap(*sb, {"codex", "login", "--with-api-key"}), o);
    }
    a->invalidate(&*sb);
    if (p.exit_code != 0) return {{"error", "codex rejected the key: " + strip_ansi(p.out).substr(0, 200)}};
    return {{"ok", true}};
  }
  return {{"error", "@" + name + " doesn't take a " + kind}};
}

json Harness::disconnect_agent(const std::string& uid, const std::string& name) {
  if (!opt_.user_accounts) return {{"error", "operator accounts are managed on the Saga host"}};
  agents::Agent* a = reg_.find(name);
  if (!a) return {{"error", "unknown agent"}};
  const auto sb = sandbox_for(uid, "", {});
  // Disconnect deletes the credential outright (sealed or not); nothing needs the vault key for that.
  json deleted = json::array();
  if (a->spec().kind == "claude-code") {
    json keys = read_keys(opt_.keys_path);
    if (keys.contains(kCreds) && keys[kCreds].contains(uid) && keys[kCreds][uid].contains("claude")) {
      keys[kCreds][uid].erase("claude");
      deleted.push_back("claude token / API key");
    }
    write_keys(opt_.keys_path, keys);
  } else {
    const std::string rel = a->spec().kind == "codex" ? ".codex/auth.json" : ".grok/auth.json";
    if (secrets::erase_file((fs::path(sb->home) / rel).string())) deleted.push_back(rel);
  }
  a->invalidate(&*sb);
  {
    std::lock_guard lk(mu_);
    device_.erase(uid + "/" + a->name());
  }
  const bool gone = a->spec().kind == "claude-code"
                        ? !read_keys(opt_.keys_path).value(kCreds, json::object()).value(uid, json::object()).contains("claude")
                        : !sandbox::has_login(*sb, a->spec().kind == "codex" ? ".codex/auth.json" : ".grok/auth.json");
  return {{"ok", gone}, {"deleted", deleted}};
}

json Harness::vault_status(const std::string& uid, const secrets::Key& vault) {
  if (vault.size() != 32) return {{"state", "missing"}};
  json keys = read_keys(opt_.keys_path);
  const std::string id = secrets::key_id(vault), known = keys.value("#vault", json::object()).value(uid, "");
  if (known.empty()) {  // first key for this user becomes their vault
    keys["#vault"][uid] = id;
    write_keys(opt_.keys_path, keys);
    return {{"state", "ok"}};
  }
  return {{"state", known == id ? "ok" : "mismatch"}};
}

// The user's secrets were sealed under a key this browser can't reproduce: drop them and adopt this key.
json Harness::vault_reset(const std::string& uid, const secrets::Key& vault) {
  if (vault.size() != 32) return {{"error", "no vault key"}};
  json keys = read_keys(opt_.keys_path);
  if (keys.contains(kCreds)) keys[kCreds].erase(uid);
  if (keys.contains(uid))
    for (auto& [name, slot] : keys[uid].items())
      if (slot.is_object() && slot.contains("sealed")) slot = json{{"hint", slot.value("hint", "")}};
  keys["#vault"][uid] = secrets::key_id(vault);
  write_keys(opt_.keys_path, keys);
  if (const auto sb = sandbox_for(uid, "", vault))
    for (auto& rel : sandbox::kLoginFiles) secrets::erase_file((fs::path(sb->home) / rel).string());
  for (auto* a : reg_.visible(uid)) a->invalidate(nullptr);
  return {{"ok", true}};
}

json Harness::probe_agent(const std::string& uid, const std::string& name, const secrets::Key& vault) {
  agents::Agent* a = reg_.find(name);
  if (!a) return {{"error", "unknown agent"}};
  const auto sb = sandbox_for(uid, "", vault);
  const sandbox::Sandbox* sbp = sb ? &*sb : nullptr;
  if (!a->probe_usage(sbp)) return {{"error", "@" + name + " did not report usage windows"}};
  return {{"ok", true}, {"account", a->account(sbp)}};
}

json Harness::add_agent(const std::string& uid, const json& body, const secrets::Key& vault) {
  seed_user(uid);
  agents::Spec spec;
  spec.kind = "openai";
  spec.owner = uid;
  spec.name = body.value("name", "");
  spec.base_url = body.value("base_url", "");
  while (!spec.base_url.empty() && spec.base_url.back() == '/') spec.base_url.pop_back();
  spec.model = body.value("model", "");
  spec.description = body.value("description", "");
  const std::string key = body.value("api_key", "");
  spec.key_hint = hint(key);
  if (spec.description.empty()) spec.description = spec.model + " via own API key";
  if (!spec.base_url.starts_with("http://") && !spec.base_url.starts_with("https://"))
    return {{"error", "base URL must start with http:// or https://"}};
  if (spec.model.empty()) return {{"error", "model is required"}};
  if (auto err = reg_.add(spec); !err.empty()) return {{"error", err}};

  json keys = read_keys(opt_.keys_path);
  if (!key.empty()) {
    json slot = make_slot(key, vault);
    slot["hint"] = spec.key_hint;
    keys[uid][spec.name] = slot;
  }
  write_keys(opt_.keys_path, keys);
  persist_user_agents(uid);
  return {{"ok", true}, {"name", spec.name}};
}

json Harness::remove_agent(const std::string& uid, const std::string& name) {
  if (!reg_.remove(name, uid)) return {{"error", "not one of your agents"}};
  json keys = read_keys(opt_.keys_path);
  if (keys.contains(uid)) keys[uid].erase(name);
  write_keys(opt_.keys_path, keys);
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
  // It becomes a CLI argument, so only the characters model ids actually use.
  if (model.size() > 80 || !std::all_of(model.begin(), model.end(), [](unsigned char c) {
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
// normal clone inside that chat's workspace on branch saga/<chat>; `.saga-repo.json` beside it says
// which repo it is. Git gets the token per command via GIT_CONFIG_* env — never in .git/config, so
// the agents working in the repo can commit but cannot push.
namespace {
constexpr const char* kRepoMarker = ".saga-repo.json";

json read_marker(const std::string& workspace) {
  std::ifstream in(fs::path(workspace) / kRepoMarker);
  auto j = json::parse(in, nullptr, false);
  return j.is_object() ? j : json();
}

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
}  // namespace

std::string Harness::github_token(const std::string& uid, const secrets::Key& vault) {
  const json slot = read_keys(opt_.keys_path).value(kCreds, json::object()).value(uid, json::object())
                        .value("github", json::object());
  return open_slot(slot.value("secret", json()), vault);
}

proc::Result Harness::git(const std::string& uid, const std::string& workspace, const secrets::Key& vault,
                          const std::vector<std::string>& args, const std::string& token, int timeout_s) {
  std::vector<std::string> argv = {"git"};
  argv.insert(argv.end(), args.begin(), args.end());
  proc::Options o;
  o.timeout_s = timeout_s;
  o.merge_stderr = true;
  const std::map<std::string, std::string> auth = token.empty() ? std::map<std::string, std::string>{}
                                                                : github::git_env(token);
  if (auto sb = sandbox_for(uid, workspace, vault)) {
    for (auto& [k, v] : auth) sb->env[k] = v;
    sb->env["GIT_TERMINAL_PROMPT"] = "0";
    return proc::run(sandbox::wrap(*sb, argv), o);
  }
  o.cwd = workspace;
  o.env = auth;
  o.env["GIT_TERMINAL_PROMPT"] = "0";
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
  const json slot = read_keys(opt_.keys_path).value(kCreds, json::object()).value(uid, json::object())
                        .value("github", json::object());
  json out = {{"connected", !slot.empty()},
              {"login", slot.value("login", "")},
              {"unlocked", !github_token(uid, vault).empty()},
              {"device_available", !opt_.github_client_id.empty()},
              {"oauth_available", !opt_.github_client_id.empty() && !opt_.github_client_secret.empty()}};
  std::lock_guard lk(mu_);
  if (auto it = gh_device_.find(uid); it != gh_device_.end()) {
    out["device"] = {{"status", it->second->status}, {"url", it->second->url}, {"code", it->second->code},
                     {"error", it->second->error}};
  }
  return out;
}

json Harness::github_set_token(const std::string& uid, const std::string& token, const secrets::Key& vault) {
  if (opt_.user_accounts && vault.size() != 32) return {{"error", "unlock your vault first (sign in again)"}};
  const std::string t = token.substr(0, 400);
  json me;
  try {
    me = github::user(t);  // proves the token works before we keep it
  } catch (const std::exception& e) {
    return {{"error", std::string("GitHub rejected the token: ") + e.what()}};
  }
  json keys = read_keys(opt_.keys_path);
  keys[kCreds][uid]["github"] = {{"secret", make_slot(t, vault)},
                                 {"login", me.value("login", "")},
                                 {"id", me.value("id", 0)},
                                 {"hint", hint(t)}};
  write_keys(opt_.keys_path, keys);
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
    gh_device_[uid] = st;
    // Poll until the user approves; the vault key lives only in this thread's memory meanwhile.
    background_.emplace_back([this, uid, st, vault, device = start.value("device_code", ""),
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
    });
  }
  return {{"ok", true}, {"url", st->url}, {"code", st->code}};
}

json Harness::github_disconnect(const std::string& uid) {
  json keys = read_keys(opt_.keys_path);
  bool had = keys.contains(kCreds) && keys[kCreds].contains(uid) && keys[kCreds][uid].contains("github");
  if (had) keys[kCreds][uid].erase("github");
  write_keys(opt_.keys_path, keys);
  {
    std::lock_guard lk(mu_);
    gh_device_.erase(uid);
  }
  const bool gone = !read_keys(opt_.keys_path).value(kCreds, json::object()).value(uid, json::object()).contains("github");
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
  auto p = run({"clone", "--filter=blob:none", "https://github.com/" + full_name + ".git", dir}, true, 600);
  if (p.exit_code != 0) return {{"error", "clone failed: " + p.out.substr(0, 240)}};
  run({"-C", dir, "checkout", "-b", branch}, false);
  run({"-C", dir, "config", "user.name", me.value("login", "saga")}, false);
  run({"-C", dir, "config", "user.email",
       std::to_string(me.value("id", 0)) + "+" + me.value("login", "saga") + "@users.noreply.github.com"},
      false);
  const json marker = {{"full_name", full_name}, {"dir", dir}, {"branch", branch}, {"base", base},
                       {"private", meta.value("private", false)}};
  std::ofstream(fs::path(ws) / kRepoMarker) << marker.dump(2);
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
  const auto log = git(uid, ws, vault, {"-C", dir, "log", "--oneline", "origin/" + base + "..HEAD"});
  if (log.out.empty()) return {{"error", "no commits yet — ask an agent to make a change first"}};
  const auto push = git(uid, ws, vault, {"-C", dir, "push", "-u", "origin", branch}, token, 300);
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

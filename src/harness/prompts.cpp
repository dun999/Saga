#include "harness/prompts.h"

#include <algorithm>
#include <cctype>
#include <future>

namespace saga::harness {

using json = nlohmann::json;

const char* kSeedPrompt =
    "You are Saga, a personal assistant that remembers. Everything you know about the user comes from "
    "their Walrus Memory, shown below under 'What Saga remembers'. Use it naturally and specifically: "
    "greet returning users with continuity, apply their stated preferences without being asked again, and "
    "never claim you cannot remember when the memory section has the answer. If memories conflict, prefer "
    "the most recent. Be concise and concrete. When you build something, say where the files are.";

namespace {
constexpr const char* kPromptNs = "harness:prompts";
constexpr const char* kScoreNs = "harness:scores";
constexpr size_t kMaxRules = 20;
constexpr size_t kMaxRuleChars = 240;

double beta_sample(std::mt19937& rng, double a, double b) {
  std::gamma_distribution<double> ga(a, 1.0), gb(b, 1.0);
  const double x = ga(rng), y = gb(rng);
  return x / (x + y);
}

std::optional<json> json_in(const std::string& text) {
  const auto l = text.find('{'), e = text.rfind('}');
  if (l == std::string::npos || e == std::string::npos || e < l) return std::nullopt;
  auto j = json::parse(text.substr(l, e - l + 1), nullptr, false);
  if (!j.is_object()) return std::nullopt;
  return j;
}

std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}
}  // namespace

std::string render_prompt(const std::string& base, const std::vector<Rule>& rules) {
  if (rules.empty()) return base;
  std::string p = base + "\n\nPlaybook (rules learned from feedback):\n";
  for (auto& r : rules) p += "- " + r.text + "\n";
  return p;
}

std::vector<Rule> apply_ops(std::vector<Rule> rules, const json& ops, int& next_id) {
  if (!ops.is_array()) return rules;
  for (auto& op : ops) {
    if (!op.is_object()) continue;
    const std::string kind = op.value("op", ""), id = op.value("id", "");
    std::string text = op.value("text", "");
    if (text.size() > kMaxRuleChars) text.resize(kMaxRuleChars);
    auto it = std::find_if(rules.begin(), rules.end(), [&](const Rule& r) { return r.id == id; });
    if (kind == "add" && !text.empty() && rules.size() < kMaxRules)
      rules.push_back({"b" + std::to_string(next_id++), text});
    else if (kind == "edit" && it != rules.end() && !text.empty())
      it->text = text;
    else if (kind == "remove" && it != rules.end())
      rules.erase(it);
  }
  return rules;
}

int followup_signal(const std::string& next_message) {
  const std::string m = lower(next_message.substr(0, 80));
  auto starts = [&](const char* p) {
    const std::string s = p;
    // Whole-word prefix: "no," is a correction, "now" is not.
    return m.starts_with(s) && (m.size() == s.size() || !std::isalnum(static_cast<unsigned char>(m[s.size()])));
  };
  for (const char* p : {"no worries", "no problem", "no rush", "no need"})  // polite, not a correction
    if (starts(p)) return 0;
  for (const char* p : {"no", "nope", "wrong", "that's wrong", "thats wrong", "that is wrong", "that's not",
                        "not what i", "not quite", "doesn't work", "does not work", "didn't work", "it doesn't",
                        "still broken", "still not", "still doesn't", "you forgot", "you missed", "incorrect",
                        "try again", "that's incorrect", "this is wrong", "it broke", "why did you"})
    if (starts(p)) return -1;
  for (const char* p : {"thanks", "thank you", "thx", "perfect", "great", "awesome", "that worked", "it works",
                        "works", "nice", "love it", "exactly", "amazing"})
    if (starts(p)) return 1;
  return 0;
}

void PromptPool::load() {
  std::map<int, PromptVersion> found;
  for (auto& m : store_.recall("Saga system prompt version", kPromptNs, {.limit = 50, .recent = true})) {
    if (auto j = memwal::decode_record(m.text, "prompt")) {
      PromptVersion p;
      p.v = j->value("v", 0);
      p.parent = j->value("parent", -1);
      p.why = j->value("why", "");
      p.status = j->value("status", "live");
      p.eval = j->value("eval", json());
      // Older versions stored one full prompt; it becomes the base with an empty playbook.
      p.base = j->value("base", j->value("prompt", ""));
      for (auto& r : j->value("rules", json::array()))
        p.rules.push_back({r.value("id", ""), r.value("text", "")});
      p.prompt = render_prompt(p.base, p.rules);
      if (!p.base.empty()) found.emplace(p.v, p);
    }
  }
  std::map<std::string, Credit> credit;
  // Rolling window of the most recent ratings: a non-stationary bandit, which suits a
  // harness whose users and models drift. Credit tags share the namespace.
  for (auto& m : store_.recall("Saga prompt score rating", kScoreNs, {.limit = 200, .recent = true})) {
    if (auto j = memwal::decode_record(m.text, "score")) {
      auto it = found.find(j->value("v", -1));
      if (it != found.end()) (j->value("r", 0) > 0 ? it->second.wins : it->second.losses)++;
    } else if (auto c = memwal::decode_record(m.text, "credit")) {
      auto& cr = credit[c->value("id", "")];
      (c->value("helpful", false) ? cr.helpful : cr.harmful)++;
    }
  }
  const bool fresh = found.empty();
  if (fresh) {
    PromptVersion seed;
    seed.base = seed.prompt = kSeedPrompt;
    seed.why = "seed";
    found.emplace(0, seed);
  }
  {
    std::lock_guard lk(mu_);
    versions_ = std::move(found);
    credit_ = std::move(credit);
  }
  if (fresh) persist(get(0));
}

void PromptPool::persist(const PromptVersion& p) {
  json rules = json::array();
  for (auto& r : p.rules) rules.push_back({{"id", r.id}, {"text", r.text}});
  store_.put(kPromptNs, "prompt",
             memwal::encode_record("prompt", {{"v", p.v}, {"parent", p.parent}, {"base", p.base}, {"rules", rules},
                                              {"why", p.why}, {"status", p.status}, {"eval", p.eval}}));
}

const PromptVersion& PromptPool::choose() {
  std::lock_guard lk(mu_);
  const PromptVersion* pick = &versions_.begin()->second;
  double top = -1;
  for (auto& [v, p] : versions_) {
    if (p.status != "live") continue;
    const double s = beta_sample(rng_, 1.0 + p.wins, 1.0 + p.losses);
    if (s > top) top = s, pick = &p;
  }
  return *pick;
}

const PromptVersion& PromptPool::get(int v) {
  std::lock_guard lk(mu_);
  auto it = versions_.find(v);
  return it == versions_.end() ? versions_.begin()->second : it->second;
}

const PromptVersion& PromptPool::best() {
  std::lock_guard lk(mu_);
  const PromptVersion* b = &versions_.begin()->second;
  double top = -1;
  for (auto& [v, p] : versions_) {
    if (p.status != "live") continue;
    const double mean = (1.0 + p.wins) / (2.0 + p.wins + p.losses);  // posterior mean
    if (mean > top || (mean == top && v > b->v)) top = mean, b = &p;
  }
  return *b;
}

void PromptPool::score(int v, int rating, bool implicit) {
  {
    std::lock_guard lk(mu_);
    auto it = versions_.find(v);
    if (it == versions_.end()) return;
    (rating > 0 ? it->second.wins : it->second.losses)++;
  }
  store_.put(kScoreNs, "score",
             memwal::encode_record("score", {{"v", v}, {"r", rating > 0 ? 1 : -1}, {"src", implicit ? "implicit" : "user"}}));
}

void PromptPool::credit(const std::string& id, bool helpful) {
  if (id.empty()) return;
  {
    std::lock_guard lk(mu_);
    auto& c = credit_[id];
    (helpful ? c.helpful : c.harmful)++;
  }
  store_.put(kScoreNs, "credit", memwal::encode_record("credit", {{"id", id}, {"helpful", helpful}}));
}

Credit PromptPool::credit_of(const std::string& id) const {
  std::lock_guard lk(mu_);
  auto it = credit_.find(id);
  return it == credit_.end() ? Credit{} : it->second;
}

void PromptPool::add_critique(const std::string& c) {
  std::lock_guard lk(mu_);
  if (!c.empty()) critiques_.push_back(c);
}

size_t PromptPool::pending_critiques() const {
  std::lock_guard lk(mu_);
  return critiques_.size();
}

json PromptPool::evolve(agents::Agent& brain, const std::vector<ReplayCase>& cases, const sandbox::Sandbox* sb) {
  const PromptVersion parent = best();
  std::vector<std::string> crit;
  int next_v, next_rule = 1;
  {
    std::lock_guard lk(mu_);
    crit.swap(critiques_);
    next_v = versions_.rbegin()->first + 1;
    for (auto& [v, p] : versions_)
      for (auto& r : p.rules)
        if (r.id.size() > 1) next_rule = std::max(next_rule, std::atoi(r.id.c_str() + 1) + 1);
  }
  if (crit.empty()) return {{"error", "no critiques queued"}};
  auto requeue = [&] {
    std::lock_guard lk(mu_);
    critiques_.insert(critiques_.begin(), crit.begin(), crit.end());
  };

  // Rules that keep hurting are dropped before the brain sees the playbook.
  std::vector<Rule> kept;
  std::string dropped;
  for (auto& r : parent.rules)
    if (credit_of(r.id).muted()) dropped += "[" + r.id + "] " + r.text + "\n";
    else kept.push_back(r);

  std::string prompt = "BASE PROMPT (fixed):\n<<<\n" + parent.base + "\n>>>\n\nPLAYBOOK (v" +
                       std::to_string(parent.v) + "):\n";
  if (kept.empty()) prompt += "(empty)\n";
  for (auto& r : kept) {
    const Credit c = credit_of(r.id);
    prompt += "[" + r.id + "] " + r.text + "  (helped " + std::to_string(c.helpful) + ", hurt " +
              std::to_string(c.harmful) + ")\n";
  }
  if (!dropped.empty()) prompt += "\nALREADY REMOVED (hurt more than they helped):\n" + dropped;
  prompt += "\nCRITIQUES OF RECENT TURNS THAT WENT BADLY:\n";
  for (auto& c : crit) prompt += "- " + c + "\n";
  prompt +=
      "\nPropose at most 3 small edits to the playbook so these failures stop, keeping every rule that works. "
      "Each rule is one concrete, general instruction under 200 characters, never about a single task. "
      "Reply with JSON only: {\"ops\":[{\"op\":\"add\",\"text\":\"...\"},{\"op\":\"edit\",\"id\":\"b2\","
      "\"text\":\"...\"},{\"op\":\"remove\",\"id\":\"b3\"}],\"why\":\"one sentence\"}";
  auto r = brain.complete(
      "You curate the playbook of an AI assistant harness from evidence (agentic context engineering). "
      "You make small, targeted edits grounded in the critiques; you never rewrite the whole list.",
      prompt, sb);
  if (!r.ok) {
    requeue();
    return {{"error", r.error}};
  }
  auto j = json_in(r.text);
  if (!j) {
    requeue();
    return {{"error", "brain returned no JSON ops"}};
  }

  PromptVersion child;
  child.v = next_v;
  child.parent = parent.v;
  child.base = parent.base;
  child.rules = apply_ops(kept, j->value("ops", json::array()), next_rule);
  child.why = j->value("why", "");
  child.prompt = render_prompt(child.base, child.rules);
  if (child.prompt == parent.prompt) return {{"error", "no change proposed"}};

  // The gate: replay rated turns under both versions; the child must not lose. The playbook is shared
  // by every user, so an edit nobody could test never goes live.
  if (cases.empty()) {
    requeue();
    return {{"error", "no rated turns to replay yet"}};
  }
  child.eval = replay(brain, parent, child, cases, sb);
  if (!child.eval.value("judged", false)) {  // couldn't verify: try again after the next critique
    requeue();
    return {{"error", "replay judge failed"}};
  }
  if (child.eval.value("losses", 0) > child.eval.value("wins", 0)) child.status = "rejected";
  {
    std::lock_guard lk(mu_);
    versions_[child.v] = child;
  }
  persist(child);
  return {{"version", child.v}, {"parent", parent.v}, {"why", child.why}, {"status", child.status}, {"eval", child.eval}};
}

json PromptPool::replay(agents::Agent& brain, const PromptVersion& parent, const PromptVersion& child,
                        const std::vector<ReplayCase>& cases, const sandbox::Sandbox* sb) {
  auto answer = [&](const PromptVersion& p, const ReplayCase& c) {
    const std::string sys = p.prompt + (c.memory.empty() ? "" : "\n\n## What Saga remembers about this user\n" + c.memory);
    auto r = brain.complete(sys, c.message, sb);
    return r.ok ? r.text : std::string();
  };
  std::vector<std::future<std::string>> old_f, new_f;
  for (auto& c : cases) {
    old_f.push_back(std::async(std::launch::async, answer, std::cref(parent), std::cref(c)));
    new_f.push_back(std::async(std::launch::async, answer, std::cref(child), std::cref(c)));
  }
  // Blind pairwise judging, with the order shuffled per case so position bias can't pick a side.
  std::vector<bool> child_first;
  std::string prompt;
  for (size_t i = 0; i < cases.size(); ++i) {
    const std::string a = old_f[i].get(), b = new_f[i].get();
    bool flip;
    {
      std::lock_guard lk(mu_);
      flip = rng_() & 1;
    }
    child_first.push_back(flip);
    const auto& c = cases[i];
    prompt += "### Case " + std::to_string(i + 1) + "\nUSER: " + c.message.substr(0, 1500) + "\n";
    if (c.rating < 0)
      prompt += "(An earlier answer to this was rated bad" + (c.comment.empty() ? "" : ": " + c.comment) + ")\n";
    prompt += "ANSWER 1:\n" + (flip ? b : a).substr(0, 2500) + "\nANSWER 2:\n" + (flip ? a : b).substr(0, 2500) + "\n\n";
  }
  prompt += "For each case, which answer serves this user better? Reply with JSON only: "
            "{\"verdicts\":[\"1\"|\"2\"|\"tie\", ...]} in case order.";
  auto r = brain.complete(
      "You are an impartial judge comparing two assistant answers to the same message. Prefer answers that "
      "use what is known about the user, avoid the problem the user complained about, and are correct and "
      "concise. Ignore length and style unless the user asked for it. An empty answer always loses.",
      prompt, sb);
  int wins = 0, losses = 0, ties = 0;
  auto j = r.ok ? json_in(r.text) : std::nullopt;
  const json verdicts = j ? j->value("verdicts", json::array()) : json::array();
  for (size_t i = 0; i < cases.size(); ++i) {
    const std::string v = i < verdicts.size() && verdicts[i].is_string() ? verdicts[i].get<std::string>() : "tie";
    if (v == "tie") ++ties;
    else if ((v == "1") == child_first[i]) ++wins;
    else ++losses;
  }
  return {{"wins", wins}, {"losses", losses}, {"ties", ties}, {"cases", cases.size()}, {"judged", j.has_value()}};
}

json PromptPool::summary() const {
  std::lock_guard lk(mu_);
  json arr = json::array();
  for (auto& [v, p] : versions_) {
    json rules = json::array();
    for (auto& r : p.rules) {
      auto it = credit_.find(r.id);
      const Credit c = it == credit_.end() ? Credit{} : it->second;
      rules.push_back({{"id", r.id}, {"text", r.text}, {"helpful", c.helpful}, {"harmful", c.harmful}});
    }
    arr.push_back({{"v", v}, {"parent", p.parent}, {"why", p.why}, {"wins", p.wins}, {"losses", p.losses},
                   {"status", p.status}, {"eval", p.eval}, {"rules", rules}, {"prompt", p.prompt}});
  }
  return {{"versions", arr}, {"pending_critiques", critiques_.size()}};
}

}  // namespace saga::harness

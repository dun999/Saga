#include "harness/prompts.h"

#include <algorithm>

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

double beta_sample(std::mt19937& rng, double a, double b) {
  std::gamma_distribution<double> ga(a, 1.0), gb(b, 1.0);
  const double x = ga(rng), y = gb(rng);
  return x / (x + y);
}
}  // namespace

void PromptPool::load() {
  std::map<int, PromptVersion> found;
  for (auto& m : store_.recall("Saga system prompt version", kPromptNs, {.limit = 50, .recent = true})) {
    if (auto j = memwal::decode_record(m.text, "prompt")) {
      PromptVersion p;
      p.v = j->value("v", 0);
      p.parent = j->value("parent", -1);
      p.prompt = j->value("prompt", "");
      p.why = j->value("why", "");
      if (!p.prompt.empty()) found.emplace(p.v, p);
    }
  }
  // Rolling window of the most recent ratings: a non-stationary bandit, which suits a
  // harness whose users and models drift.
  for (auto& m : store_.recall("Saga prompt score rating", kScoreNs, {.limit = 100, .recent = true})) {
    if (auto j = memwal::decode_record(m.text, "score")) {
      auto it = found.find(j->value("v", -1));
      if (it == found.end()) continue;
      (j->value("r", 0) > 0 ? it->second.wins : it->second.losses)++;
    }
  }
  std::lock_guard lk(mu_);
  if (found.empty()) {
    PromptVersion seed{0, -1, kSeedPrompt, "seed", 0, 0};
    found.emplace(0, seed);
    store_.put(kPromptNs, "prompt", memwal::encode_record("prompt", {{"v", 0}, {"parent", -1},
                                                                     {"prompt", seed.prompt}, {"why", "seed"}}));
  }
  versions_ = std::move(found);
}

const PromptVersion& PromptPool::choose() {
  std::lock_guard lk(mu_);
  const PromptVersion* pick = &versions_.begin()->second;
  double top = -1;
  for (auto& [v, p] : versions_) {
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
    const double mean = (1.0 + p.wins) / (2.0 + p.wins + p.losses);  // posterior mean
    if (mean > top || (mean == top && v > b->v)) top = mean, b = &p;
  }
  return *b;
}

void PromptPool::score(int v, int rating) {
  {
    std::lock_guard lk(mu_);
    auto it = versions_.find(v);
    if (it == versions_.end()) return;
    (rating > 0 ? it->second.wins : it->second.losses)++;
  }
  store_.put(kScoreNs, "score", memwal::encode_record("score", {{"v", v}, {"r", rating > 0 ? 1 : -1}}));
}

void PromptPool::add_critique(const std::string& c) {
  std::lock_guard lk(mu_);
  if (!c.empty()) critiques_.push_back(c);
}

size_t PromptPool::pending_critiques() const {
  std::lock_guard lk(mu_);
  return critiques_.size();
}

int PromptPool::evolve(agents::Agent& brain, std::string* log, const sandbox::Sandbox* sb) {
  PromptVersion parent = best();
  std::vector<std::string> crit;
  int next_v;
  {
    std::lock_guard lk(mu_);
    crit.swap(critiques_);
    next_v = versions_.rbegin()->first + 1;
  }
  if (crit.empty()) return -1;

  std::string prompt = "CURRENT SYSTEM PROMPT (v" + std::to_string(parent.v) + "):\n<<<\n" + parent.prompt +
                       "\n>>>\n\nCRITIQUES OF TURNS USERS RATED BADLY:\n";
  for (auto& c : crit) prompt += "- " + c + "\n";
  prompt +=
      "\nRewrite the system prompt so these failures stop happening, keeping everything that works. "
      "Stay under 1200 characters. Reply with JSON only: {\"prompt\": \"...\", \"why\": \"one sentence\"}";
  auto r = brain.complete(
      "You optimise the system prompt of an AI assistant harness from evidence (reflective prompt "
      "evolution). You make targeted, minimal edits grounded in the critiques.",
      prompt, sb);
  if (!r.ok) {
    if (log) *log = r.error;
    std::lock_guard lk(mu_);
    critiques_.insert(critiques_.end(), crit.begin(), crit.end());
    return -1;
  }
  const auto l = r.text.find('{'), e = r.text.rfind('}');
  auto j = l == std::string::npos ? json() : json::parse(r.text.substr(l, e - l + 1), nullptr, false);
  if (!j.is_object() || !j.contains("prompt")) {
    if (log) *log = "brain returned no JSON prompt";
    return -1;
  }
  PromptVersion child{next_v, parent.v, j["prompt"].get<std::string>(), j.value("why", ""), 0, 0};
  {
    std::lock_guard lk(mu_);
    versions_[child.v] = child;
  }
  store_.put(kPromptNs, "prompt",
             memwal::encode_record("prompt", {{"v", child.v}, {"parent", child.parent},
                                              {"prompt", child.prompt}, {"why", child.why}}));
  if (log) *log = child.why;
  return child.v;
}

json PromptPool::summary() const {
  std::lock_guard lk(mu_);
  json arr = json::array();
  for (auto& [v, p] : versions_)
    arr.push_back({{"v", v}, {"parent", p.parent}, {"why", p.why}, {"wins", p.wins}, {"losses", p.losses},
                   {"prompt", p.prompt}});
  return {{"versions", arr}, {"pending_critiques", critiques_.size()}};
}

}  // namespace saga::harness

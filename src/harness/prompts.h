#pragma once
// Evolving system prompt, persisted only in Walrus Memory. Three ideas, each from a paper:
//
//  1. Playbook, not rewrites (ACE, Zhang et al. 2025). A version is a fixed base prompt plus a list
//     of short rules. Evolution proposes small add/edit/remove ops on that list, so what worked
//     before can't be silently lost the way it is when a whole prompt is rewritten each time.
//  2. Credit per rule. After a rated turn, reflection says which rules (and which per-agent lessons)
//     helped or hurt. A rule or lesson that keeps hurting is dropped automatically.
//  3. Test before trusting (Darwin Gödel Machine, Zhang et al. 2025; GEPA, Agrawal et al. 2025).
//     A proposed child is replayed against the user's own rated past turns next to its parent, and a
//     judge picks the better answer blind. Only a child that doesn't lose goes live; after that,
//     Thompson sampling over live ratings decides how much traffic each live version gets.
#include <map>
#include <mutex>
#include <random>
#include <string>
#include <vector>

#include "agents/agent.h"
#include "memwal/store.h"

namespace saga::harness {

struct Rule {
  std::string id, text;  // id "b<n>", stable across versions
};

struct PromptVersion {
  int v = 0;
  int parent = -1;
  std::string base;         // fixed part (the seed prompt, or a legacy full rewrite)
  std::vector<Rule> rules;  // the playbook
  std::string why;
  std::string status = "live";          // live | rejected (lost its replay)
  nlohmann::json eval = nullptr;        // {wins, losses, ties, cases} of the child vs its parent
  int wins = 0, losses = 0;             // live ratings (Thompson sampling)
  std::string prompt;                   // base + playbook, rendered
};

struct Credit {
  int helpful = 0, harmful = 0;
  bool muted() const { return harmful >= 2 && harmful > helpful; }  // keeps hurting → drop it
};

// A rated past turn, replayed to test a new prompt before it goes live.
struct ReplayCase {
  std::string message, memory, answer, comment;
  int rating = 0;
};

extern const char* kSeedPrompt;

std::string render_prompt(const std::string& base, const std::vector<Rule>& rules);
// Applies [{"op":"add"|"edit"|"remove","id":..,"text":..}]; new rules get ids from next_id.
std::vector<Rule> apply_ops(std::vector<Rule> rules, const nlohmann::json& ops, int& next_id);
// Reads the user's next message as feedback on the previous answer: -1 correction, +1 thanks, 0 neither.
int followup_signal(const std::string& next_message);

class PromptPool {
 public:
  explicit PromptPool(memwal::Store& store, std::string scope = "harness")
      : store_(store), scope_(std::move(scope)) {}

  void load();                        // pull versions, scores and credit from Walrus
  const PromptVersion& choose();      // Thompson sample over live versions
  const PromptVersion& get(int v);
  const PromptVersion& best();
  void score(int v, int rating, bool implicit = false);  // +1 / -1, persisted as a SAGA:score record
  void credit(const std::string& id, bool helpful);      // rule "b3" or "lesson:<blob>"
  Credit credit_of(const std::string& id) const;
  void add_critique(const std::string& c);
  size_t pending_critiques() const;
  // Propose a child of best() from queued critiques, replay it against `cases`, keep it live only if
  // it doesn't lose. Returns {version, why, status, eval} or {error}.
  nlohmann::json evolve(agents::Agent& brain, const std::vector<ReplayCase>& cases,
                        const sandbox::Sandbox* sb = nullptr);
  nlohmann::json summary() const;

 private:
  nlohmann::json replay(agents::Agent& brain, const PromptVersion& parent, const PromptVersion& child,
                        const std::vector<ReplayCase>& cases, const sandbox::Sandbox* sb);
  void persist(const PromptVersion& p);

  memwal::Store& store_;
  const std::string scope_;
  mutable std::mutex mu_;
  std::map<int, PromptVersion> versions_;
  std::map<std::string, Credit> credit_;
  std::vector<std::string> critiques_;
  std::mt19937 rng_{std::random_device{}()};
};

}  // namespace saga::harness

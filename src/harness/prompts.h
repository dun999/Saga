#pragma once
// Evolving system-prompt population, persisted only in Walrus Memory.
//
// GEPA-style (Agrawal et al. 2025): when enough negative feedback accumulates, the brain reads the
// critiques of failed turns and proposes a mutated child of the best prompt. Which version serves a
// turn is chosen by Thompson sampling over thumbs-up/down tallies, so a bad mutation loses traffic
// on its own and good ones take over — the harness optimises itself around fixed model weights
// (Meta-Harness, Lee et al. 2026; Continual Harness, Karten et al. 2026).
#include <map>
#include <mutex>
#include <random>
#include <string>
#include <vector>

#include "agents/agent.h"
#include "memwal/store.h"

namespace saga::harness {

struct PromptVersion {
  int v = 0;
  int parent = -1;
  std::string prompt;
  std::string why;
  int wins = 0, losses = 0;
};

extern const char* kSeedPrompt;

class PromptPool {
 public:
  explicit PromptPool(memwal::Store& store) : store_(store) {}

  void load();                        // pull versions + scores from Walrus
  const PromptVersion& choose();      // Thompson sample
  const PromptVersion& get(int v);
  const PromptVersion& best();
  void score(int v, int rating);      // rating: +1 / -1, persisted as a SAGA:score record
  void add_critique(const std::string& c);
  size_t pending_critiques() const;
  // Mutate best() from accumulated critiques. Returns the new version or -1.
  int evolve(agents::Agent& brain, std::string* log = nullptr, const sandbox::Sandbox* sb = nullptr);
  nlohmann::json summary() const;

 private:
  memwal::Store& store_;
  mutable std::mutex mu_;
  std::map<int, PromptVersion> versions_;
  std::vector<std::string> critiques_;
  std::mt19937 rng_{std::random_device{}()};
};

}  // namespace saga::harness

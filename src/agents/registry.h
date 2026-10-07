#pragma once
#include <map>
#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>

#include "agents/agent.h"

namespace saga::agents {

// Agents configured in saga.json (shared) plus agents users add with their own API key (owned).
// Handles are lower-case '@' names; an owned agent is only visible to its owner.
class Registry {
 public:
  static Registry load(const std::string& path = "saga.json");
  Registry() = default;
  Registry(Registry&& o) noexcept;

  Agent* find(const std::string& name, const std::string& uid = "") const;
  std::vector<Agent*> all() const;                        // shared agents
  std::vector<Agent*> visible(const std::string& uid) const;  // shared + uid's own
  std::vector<std::string> names(const std::string& uid = "") const;
  Agent* primary() const { return find(primary_); }
  json roster(const std::string& uid = "") const;  // for UI + prompts

  // Owned agents. Names of shared agents are reserved.
  std::string add(const Spec& spec);  // "" on success, else error
  bool remove(const std::string& name, const std::string& uid);

 private:
  static std::string key(const std::string& name, const std::string& owner) {
    return owner.empty() ? name : owner + "/" + name;
  }
  mutable std::shared_mutex mu_;
  std::map<std::string, std::unique_ptr<Agent>> agents_;
  // Removed or replaced agents. find() hands out raw pointers that a running turn may still hold, so
  // an agent is never destroyed while the process lives (a few bytes per removal).
  std::vector<std::unique_ptr<Agent>> retired_;
  std::vector<std::string> order_;  // shared agents, config order
  std::string primary_;
};

}  // namespace saga::agents

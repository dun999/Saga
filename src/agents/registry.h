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
  Agent* brain() const { return find(brain_); }
  bool is_internal(const Agent* a) const { return a == brain() && a != primary(); }
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
  std::vector<std::string> order_;  // shared agents, config order
  std::string primary_, brain_;
};

}  // namespace saga::agents

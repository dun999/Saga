#include "agents/registry.h"

#include <algorithm>
#include <fstream>
#include <mutex>

namespace saga::agents {
namespace {

const char* kDefaults = R"({
  "primary": "claude",
  "brain": "claude-brain",
  "agents": [
    {"name": "claude", "kind": "claude-code", "description": "Claude Code: generalist, frontend, refactors, writing"},
    {"name": "codex",  "kind": "codex", "model": "gpt-6.1-sol", "effort": "high", "description": "OpenAI Codex CLI: backend services, scripts, tests"},
    {"name": "grok",   "kind": "grok-cli", "description": "Grok Build CLI: fast iteration, reviews, research"},
    {"name": "claude-brain", "kind": "claude-code", "model": "sonnet", "description": "internal: reflection and prompt evolution"}
  ]
})";

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  return s;
}

}  // namespace

Registry::Registry(Registry&& o) noexcept
    : agents_(std::move(o.agents_)), retired_(std::move(o.retired_)), order_(std::move(o.order_)),
      primary_(std::move(o.primary_)), brain_(std::move(o.brain_)) {}

Registry Registry::load(const std::string& path) {
  json cfg;
  if (std::ifstream in(path); in) cfg = json::parse(in, nullptr, true, /*ignore_comments=*/true);
  if (!cfg.is_object()) cfg = json::parse(kDefaults);

  Registry r;
  for (auto& a : cfg.value("agents", json::array())) {
    Spec s = spec_from_json(a);
    s.name = lower(s.name);
    s.owner.clear();
    r.order_.push_back(s.name);
    r.agents_[s.name] = make_agent(s);
  }
  r.primary_ = lower(cfg.value("primary", r.order_.empty() ? "" : r.order_.front()));
  r.brain_ = lower(cfg.value("brain", r.primary_));
  if (!r.find(r.primary_)) throw std::runtime_error("primary agent '" + r.primary_ + "' is not configured");
  if (!r.find(r.brain_)) throw std::runtime_error("brain agent '" + r.brain_ + "' is not configured");
  return r;
}

Agent* Registry::find(const std::string& name, const std::string& uid) const {
  std::shared_lock lk(mu_);
  const std::string n = lower(name);
  if (!uid.empty())
    if (auto it = agents_.find(key(n, uid)); it != agents_.end()) return it->second.get();
  auto it = agents_.find(n);
  return it == agents_.end() ? nullptr : it->second.get();
}

std::vector<Agent*> Registry::all() const {
  std::shared_lock lk(mu_);
  std::vector<Agent*> out;
  for (auto& n : order_) out.push_back(agents_.at(n).get());
  return out;
}

std::vector<Agent*> Registry::visible(const std::string& uid) const {
  std::vector<Agent*> out = all();
  if (uid.empty()) return out;
  std::shared_lock lk(mu_);
  const std::string prefix = uid + "/";
  for (auto& [k, a] : agents_)
    if (k.starts_with(prefix)) out.push_back(a.get());
  return out;
}

std::vector<std::string> Registry::names(const std::string& uid) const {
  std::vector<std::string> out;
  for (auto* a : visible(uid))
    if (!is_internal(a)) out.push_back(a->name());
  return out;
}

json Registry::roster(const std::string& uid) const {
  json arr = json::array();
  for (auto* a : visible(uid)) {
    if (is_internal(a)) continue;
    arr.push_back({{"name", a->name()},
                   {"kind", a->spec().kind},
                   {"model", a->spec().locked ? "" : a->spec().model},
                   {"locked", a->spec().locked},
                   {"description", a->spec().description},
                   {"edits_files", a->can_edit_files()},
                   {"primary", a->name() == primary_},
                   {"custom", !a->spec().owner.empty()},
                   {"base_url", a->spec().owner.empty() ? "" : a->spec().base_url},
                   {"unavailable", a->unavailable_reason()}});
  }
  return arr;
}

std::string Registry::add(const Spec& spec) {
  Spec s = spec;
  s.name = lower(s.name);
  if (s.owner.empty()) return "owned agents need an owner";
  // Every call site, including agents restored from memory. Operator agents never come through here.
  s.public_only = true;
  if (s.name.empty() || s.name.size() > 24 ||
      !std::all_of(s.name.begin(), s.name.end(), [](char c) { return std::isalnum((unsigned char)c) || c == '-' || c == '_'; }))
    return "name must be 1–24 letters, digits, - or _";
  std::unique_lock lk(mu_);
  if (agents_.contains(s.name)) return "@" + s.name + " is a built-in agent";
  auto& slot = agents_[key(s.name, s.owner)];
  if (slot) retired_.push_back(std::move(slot));
  slot = make_agent(s);
  return "";
}

bool Registry::remove(const std::string& name, const std::string& uid) {
  std::unique_lock lk(mu_);
  auto it = agents_.find(key(lower(name), uid));
  if (it == agents_.end()) return false;
  retired_.push_back(std::move(it->second));
  agents_.erase(it);
  return true;
}

}  // namespace saga::agents

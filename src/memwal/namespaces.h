#pragma once
#include <optional>
#include <string>

namespace saga::memwal {

inline std::string user_namespace(const std::string& uid, const std::string& kind) {
  return "u:" + uid + ":" + kind;
}
inline std::string shared_namespace(const std::string& uid) { return user_namespace(uid, "shared"); }
inline std::optional<std::string> shared_uid(const std::string& ns) {
  if (!ns.starts_with("u:") || !ns.ends_with(":shared") || ns.size() <= 9) return std::nullopt;
  return ns.substr(2, ns.size() - 9);
}
inline bool legacy_knowledge(const std::string& uid, const std::string& ns) {
  const std::string prefix = user_namespace(uid, "");
  if (!ns.starts_with(prefix)) return false;
  const auto suffix = ns.substr(prefix.size());
  return suffix == "facts" || suffix == "episodes" || suffix == "skills" ||
         (suffix.starts_with("lessons:") && suffix.size() > 8);
}
inline std::optional<std::string> knowledge_uid(const std::string& ns) {
  if (auto uid = shared_uid(ns)) return uid;
  if (!ns.starts_with("u:")) return std::nullopt;
  const auto end = ns.find(':', 2);
  if (end == std::string::npos || end == 2) return std::nullopt;
  const auto uid = ns.substr(2, end - 2);
  return legacy_knowledge(uid, ns) ? std::optional(uid) : std::nullopt;
}
inline bool content_namespace(const std::string& uid, const std::string& ns) {
  return ns == shared_namespace(uid) || legacy_knowledge(uid, ns) ||
         ns == user_namespace(uid, "chat") || ns == user_namespace(uid, "checkpoints");
}

}  // namespace saga::memwal

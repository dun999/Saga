#pragma once
// Tiny .env loader: KEY=VALUE lines, # comments, optional quotes. Never overrides real env.
#include <cstdlib>
#include <fstream>
#include <string>

namespace saga::env {

inline void load_dotenv(const std::string& path = ".env") {
  std::ifstream in(path);
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    if (line.starts_with("export ")) line = line.substr(7);
    const auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    std::string k = line.substr(0, eq), v = line.substr(eq + 1);
    while (!k.empty() && k.back() == ' ') k.pop_back();
    while (!v.empty() && (v.back() == '\r' || v.back() == ' ')) v.pop_back();
    if (v.size() >= 2 && (v.front() == '"' || v.front() == '\'') && v.back() == v.front())
      v = v.substr(1, v.size() - 2);
    setenv(k.c_str(), v.c_str(), /*overwrite=*/0);
  }
}

inline std::string get(const char* k, const std::string& def = "") {
  const char* v = std::getenv(k);
  return v && *v ? v : def;
}

}  // namespace saga::env

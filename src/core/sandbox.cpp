#include "core/sandbox.h"

#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <map>
#include <mutex>
#include <sstream>

#include "core/proc.h"
#include "core/secrets.h"

namespace saga::sandbox {
namespace fs = std::filesystem;
namespace {

std::mutex mu;
std::vector<std::string> hidden;

// Absolute, symlink-free path of a command on PATH (agent CLIs are single standalone binaries).
std::string resolve(const std::string& cmd) {
  if (cmd.find('/') != std::string::npos) return fs::weakly_canonical(cmd).string();
  const char* path = std::getenv("PATH");
  std::stringstream ss(path ? path : "");
  for (std::string dir; std::getline(ss, dir, ':');) {
    std::error_code ec;
    const fs::path p = fs::path(dir) / cmd;
    if (!dir.empty() && fs::exists(p, ec) && access(p.c_str(), X_OK) == 0) return fs::canonical(p, ec).string();
  }
  return "";
}

}  // namespace

const std::vector<std::string> kLoginFiles = {".codex/auth.json", ".grok/auth.json"};

namespace {
std::mutex lease_mu;
std::map<std::string, int> leases;  // home -> active leases
}  // namespace

// Without the user's key nothing is unsealed: their CLIs simply see no login.
Lease::Lease(const Sandbox* sb) {
  if (!sb || sb->vault.size() != 32) return;
  home_ = sb->home;
  key_ = sb->vault;
  std::lock_guard lk(lease_mu);
  if (leases[home_]++ == 0) {
    for (auto& rel : kLoginFiles) {
      try {
        secrets::unseal_file(key_, home_, rel);
      } catch (...) {  // sealed under another key (vault mismatch): leave it sealed
      }
    }
  }
}

Lease::~Lease() {
  if (home_.empty()) return;
  std::lock_guard lk(lease_mu);
  if (--leases[home_] == 0) {
    for (auto& rel : kLoginFiles) {
      try {
        secrets::seal_file(key_, home_, rel);
      } catch (...) {
      }
    }
    leases.erase(home_);
  }
}

bool has_login(const Sandbox& sb, const std::string& rel) {
  std::error_code ec;
  const fs::path p = fs::path(sb.home) / rel;
  return (fs::exists(p, ec) && fs::file_size(p, ec) > 2) || fs::exists(p.string() + ".sealed", ec);
}

bool available() { return proc::on_path("bwrap"); }

void set_hidden(std::vector<std::string> paths) {
  std::lock_guard lk(mu);
  hidden.clear();
  for (auto& p : paths) {
    std::error_code ec;
    if (p.empty() || !fs::exists(p, ec)) continue;
    const std::string c = fs::canonical(p, ec).string();
    if (!ec && c != "/") hidden.push_back(c);
  }
}

std::vector<std::string> wrap(const Sandbox& sb, const std::vector<std::string>& argv) {
  if (argv.empty()) return argv;
  const std::string bin = resolve(argv[0]);
  const std::string name = fs::path(argv[0]).filename().string();
  std::vector<std::string> a = {resolve("bwrap"), "--ro-bind", "/",      "/",      "--dev",  "/dev", "--proc",
                                "/proc",      "--tmpfs",   "/tmp",   "--tmpfs", "/run/user", "--die-with-parent",
                                "--unshare-pid", "--unshare-ipc", "--new-session"};
  {
    std::lock_guard lk(mu);
    for (auto& h : hidden) a.insert(a.end(), {"--tmpfs", h});
  }
  a.insert(a.end(), {"--tmpfs", "/mnt", "--dir", "/mnt/bin", "--dir", kHome, "--dir", kWork});
  if (!bin.empty()) a.insert(a.end(), {"--ro-bind", bin, "/mnt/bin/" + name});
  a.insert(a.end(), {"--bind", sb.home, kHome});
  if (!sb.workspace.empty()) a.insert(a.end(), {"--bind", sb.workspace, kWork});
  a.insert(a.end(), {"--chdir", sb.workspace.empty() ? kHome : kWork});
  a.push_back("--");
  a.push_back("/mnt/bin/" + name);
  a.insert(a.end(), argv.begin() + 1, argv.end());
  return a;
}

std::map<std::string, std::string> environment(const Sandbox& sb) {
  std::map<std::string, std::string> env = {{"PATH", "/mnt/bin:/usr/local/bin:/usr/bin:/bin"},
                                            {"HOME", kHome},
                                            {"CODEX_HOME", std::string(kHome) + "/.codex"},
                                            {"LANG", "C.UTF-8"},
                                            {"TERM", "dumb"}};
  for (auto& [k, v] : sb.env) env[k] = v;
  return env;
}

proc::Result run(const Sandbox& sb, const std::vector<std::string>& argv, proc::Options o) {
  o.cwd.clear();  // bwrap --chdir sets it
  o.env = environment(sb);
  o.inherit_env = false;  // bwrap passes exactly this on; nothing of the server's
  return proc::run(wrap(sb, argv), o);
}

}  // namespace saga::sandbox

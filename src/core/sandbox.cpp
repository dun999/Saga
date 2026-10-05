#include "core/sandbox.h"
#include "core/proxy.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <fcntl.h>

#include <chrono>
#include <thread>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <mutex>
#include <sstream>
#include <fstream>
#include <set>
#include <sodium.h>

#include "core/proc.h"
#include "core/secrets.h"
#include "memwal/redact.h"

namespace saga::sandbox {
namespace fs = std::filesystem;
namespace {

std::mutex mu;
std::vector<std::string> hidden;
std::string cgroup_root;

void control(const fs::path& file, const std::string& value) {
  const int fd = ::open(file.c_str(), O_WRONLY | O_CLOEXEC);
  const bool ok = fd >= 0 && ::write(fd, value.data(), value.size()) == static_cast<ssize_t>(value.size());
  if (fd >= 0) ::close(fd);
  if (!ok) throw std::runtime_error("cannot apply agent limits at " + file.string());
}
class ResourceGroup {
 public:
  fs::path path;
  ResourceGroup() {
    std::string root;
    { std::lock_guard lk(mu); root = cgroup_root; }
    if (root.empty()) return;  // local operator/library mode only
    path = fs::path(root) / ("job-" + crypto::random_hex(8));
    fs::create_directory(path);
    try {
      control(path / "memory.max", "2147483648");
      control(path / "memory.swap.max", "0");
      control(path / "memory.oom.group", "1");
      control(path / "pids.max", "64");
      control(path / "cpu.max", "200000 100000");
    } catch (...) { fs::remove(path); throw; }
  }
  ~ResourceGroup() {
    if (path.empty()) return;
    try { control(path / "cgroup.kill", "1"); } catch (...) {}
    // cgroup.kill completes asynchronously. Give the kernel a bounded window to reap descendants.
    for (int i = 0; i < 50; ++i) {
      std::error_code ec;
      if (fs::remove(path, ec) || !fs::exists(path, ec)) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }
};

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

Sandbox::~Sandbox() {
  secrets::clear(vault);
  for (auto& [_, value] : env)
    if (!value.empty()) sodium_memzero(value.data(), value.size());
}

namespace {
std::mutex lease_mu;
struct HomeUse {
  int count = 0;
  secrets::Key key;  // the key its logins were unsealed with, if any
  std::set<std::string> files;
  std::set<std::string> revoked;
};
std::map<std::string, HomeUse> leases;  // home -> calls running in it
struct LoginStorage {
  bool remember = true;  // existing stored connections retain their previous choice
  std::map<std::string, std::string> sealed;
};
std::map<std::string, LoginStorage> login_storage;
}  // namespace

// The agent home is scratch space. Between calls it keeps only the user's sealed provider logins and
// Saga's own small files (.saga: a call's context while it runs, cached usage numbers); everything a
// CLI leaves behind (session transcripts with the prompt and recalled memories, its own memory
// databases, logs, caches) is deleted. Nothing in it is followed: links are removed, not traversed.
void scrub_home(const std::string& home, bool provider_root) {
  std::error_code ec;
  const fs::path root(home);
  auto keep_only = [&](const fs::path& dir, auto&& keep) {
    for (auto it = fs::directory_iterator(dir, ec); !ec && it != fs::directory_iterator(); it.increment(ec))
      if (!keep(it->path().filename().string(), fs::symlink_status(it->path(), ec))) fs::remove_all(it->path(), ec);
  };
  keep_only(root, [&](const std::string& name, fs::file_status st) {
    if (!fs::is_directory(st)) return false;
    if (provider_root && (name == "claude" || name == "codex" || name == "grok" || name == "git" || name == "utility")) {
      scrub_home((root / name).string());
      return true;
    }
    if (name == ".codex" || name == ".grok") {
      keep_only(root / name, [](const std::string& n, fs::file_status s) { return n == "auth.json.sealed" && fs::is_regular_file(s); });
      return true;
    }
    if (name == ".saga") {  // a context file older than any call is one a crash left behind
      const auto stale = fs::file_time_type::clock::now() - std::chrono::hours(2);
      keep_only(root / name, [&](const std::string& n, fs::file_status s) {
        std::error_code e2;
        return fs::is_regular_file(s) && (!n.starts_with("ctx-") || fs::last_write_time(root / name / n, e2) > stale);
      });
      return true;
    }
    return false;
  });
}

// Every sandboxed call holds a lease on its home. With the user's key the logins are unsealed for the
// calls; when the last call ends they are sealed again and the home is scrubbed.
Lease::Lease(const Sandbox* sb) {
  if (!sb || sb->home.empty()) return;
  home_ = sb->home;
  sensitive_ = sb->sensitive ? sb->sensitive : std::make_shared<memwal::SecretScope>();
  for (const auto& [name, value] : sb->env)
    if (name.find("TOKEN") != std::string::npos || name.find("KEY") != std::string::npos ||
        name.find("SECRET") != std::string::npos || name.find("AUTH") != std::string::npos) sensitive_->add(value);
  std::lock_guard lk(lease_mu);
  HomeUse& use = leases[home_];
  ++use.count;
  if (use.key.empty() && sb->vault.size() == 32) use.key = sb->vault;
  for (auto& rel : sb->login_file.empty() ? std::vector<std::string>{} : std::vector<std::string>{sb->login_file}) {
    const bool first = use.files.insert(rel).second;
    if (use.key.empty() || use.revoked.contains(rel)) continue;
    if (first) try {
      const auto storage = login_storage.find(home_);
      if (storage != login_storage.end() && storage->second.sealed.contains(rel)) {
        std::string plain = secrets::open(use.key, storage->second.sealed.at(rel));
        secrets::WipeString wipe{plain};
        secrets::write_private_file(home_, rel, plain);
      } else secrets::unseal_file(use.key, home_, rel);
    } catch (...) {  // sealed under another key (vault mismatch): leave it sealed
    }
    if (auto plain = secrets::read_private_file(home_, rel)) {
      sensitive_->add_json(*plain);
      secrets::clear(*plain);
    }
  }
}

Lease::~Lease() {
  if (home_.empty()) return;
  std::lock_guard lk(lease_mu);
  HomeUse& use = leases[home_];
  if (--use.count > 0) return;
  for (auto& rel : use.files) {
    try {
      if (use.revoked.contains(rel)) secrets::erase_file(home_, rel);
      else if (!use.key.empty()) {
        auto storage = login_storage.find(home_);
        if (storage != login_storage.end() && !storage->second.remember) {
          auto plain = secrets::read_private_file(home_, rel);
          if (plain) {
            secrets::WipeString wipe{*plain};
            storage->second.sealed[rel] = secrets::seal(use.key, *plain);
          }
          secrets::erase_file(home_, rel);
        } else {
          secrets::seal_file(use.key, home_, rel);
          if (storage != login_storage.end()) storage->second.sealed.erase(rel);
        }
      } else secrets::erase_file(home_, rel);
    } catch (...) {
      secrets::erase_file(home_, rel);  // never leave plaintext behind after a failed seal
    }
  }
  scrub_home(home_);
  secrets::clear(use.key);
  leases.erase(home_);
}

bool has_login(const Sandbox& sb, const std::string& rel) {
  std::lock_guard lk(lease_mu);
  if (auto it = login_storage.find(sb.home); it != login_storage.end() && it->second.sealed.contains(rel)) return true;
  auto plain = secrets::read_private_file(sb.home, rel);
  if (plain) { const bool present = plain->size() > 2; secrets::clear(*plain); if (present) return true; }
  return secrets::read_private_file(sb.home, rel + ".sealed").has_value();
}

bool forget_login(const Sandbox& sb, const std::string& rel) {
  std::lock_guard lk(lease_mu);
  if (auto it = leases.find(sb.home); it != leases.end()) it->second.revoked.insert(rel);
  bool had = false;
  if (auto it = login_storage.find(sb.home); it != login_storage.end()) had = it->second.sealed.erase(rel) > 0;
  return secrets::erase_file(sb.home, rel) || had;
}

void remember_login(const Sandbox& sb, bool remember) {
  std::lock_guard lk(lease_mu);
  auto& storage = login_storage[sb.home];
  storage.remember = remember;
  if (!remember) {
    if (auto sealed = secrets::read_private_file(sb.home, sb.login_file + ".sealed"))
      storage.sealed[sb.login_file] = *sealed;
    // Keep any live worker's plaintext until it exits; its lease will remove it.
    if (!leases.contains(sb.home)) secrets::erase_file(sb.home, sb.login_file);
  }
}

void end_session(const std::string& home_root) {
  std::lock_guard lk(lease_mu);
  for (auto it = login_storage.begin(); it != login_storage.end();) {
    if (!it->first.starts_with(home_root + "/") || it->second.remember) { ++it; continue; }
    if (auto live = leases.find(it->first); live != leases.end())
      for (const auto& rel : live->second.files) live->second.revoked.insert(rel);
    for (const auto& rel : kLoginFiles) secrets::erase_file(it->first, rel);
    it = login_storage.erase(it);
  }
}

bool available() { return proc::on_path("bwrap"); }

void verify(const std::string& runner) {
  std::string pattern = (fs::temp_directory_path() / "saga-check-XXXXXX").string();
  if (!::mkdtemp(pattern.data())) throw std::runtime_error("cannot check agent sandbox");
  try {
    fs::create_directory(fs::path(pattern) / "home");
    fs::create_directory(fs::path(pattern) / "work");
    Sandbox sb{pattern + "/home", pattern + "/work", {}, {}, runner};
    proc::Options options; options.timeout_s = 10;
    const auto result = run(sb, {"/bin/true"}, options);
    if (result.exit_code != 0 || result.timed_out || result.output_limited)
      throw std::runtime_error("agent sandbox is unavailable: " + result.err);
  } catch (...) { fs::remove_all(pattern); throw; }
  fs::remove_all(pattern);
}

void set_cgroup_root(const std::string& path) {
  if (path.empty()) return;
  if (!fs::exists(path)) {
    struct statfs parent{};
    if (::statfs(fs::path(path).parent_path().c_str(), &parent) != 0 || parent.f_type != 0x63677270)
      throw std::runtime_error("--agent-cgroups must be inside a delegated cgroup v2 subtree");
    fs::create_directory(path);
  }
  const auto root = fs::canonical(path);
  struct statfs st{};
  if (::statfs(root.c_str(), &st) != 0 || st.f_type != 0x63677270)
    throw std::runtime_error("--agent-cgroups must be a delegated cgroup v2 subtree");
  std::ifstream processes(root / "cgroup.procs");
  std::string pid;
  if (processes >> pid) throw std::runtime_error("--agent-cgroups needs an empty subtree, separate from the Saga server");
  // systemd delegates a unit's cgroup with nothing enabled below it (an empty cgroup.subtree_control);
  // the delegatee turns on what its children use. Until the parent does, the subtree has no cpu,
  // memory or pids controllers to enable.
  auto available = [&] {
    std::ifstream in(root / "cgroup.controllers");
    std::set<std::string> have;
    for (std::string c; in >> c;) have.insert(c);
    return have.contains("cpu") && have.contains("memory") && have.contains("pids");
  };
  if (!available()) control(root.parent_path() / "cgroup.subtree_control", "+cpu +memory +pids");
  control(root / "cgroup.subtree_control", "+cpu +memory +pids");
  // Bound aggregate demand too: creating more wallets must not multiply the host's resource budget.
  control(root / "memory.max", "4294967296");
  control(root / "memory.swap.max", "0");
  control(root / "pids.max", "256");
  control(root / "cpu.max", "200000 100000");
  { std::lock_guard lk(mu); cgroup_root = root.string(); }
  ResourceGroup probe;  // fail at startup if per-call limits cannot actually be applied
  proc::Options options;
  options.inherit_env = false; options.timeout_s = 2;
  options.cgroup_procs = (probe.path / "cgroup.procs").string();
  if (proc::run({"/bin/true"}, options).exit_code != 0)
    throw std::runtime_error("agent cgroups need delegation that allows process migration from the Saga server");
}

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
  std::vector<std::string> a = {resolve("bwrap"), "--die-with-parent", "--unshare-user", "--disable-userns",
                              "--unshare-pid", "--unshare-ipc", "--unshare-net", "--unshare-uts",
                              "--cap-drop", "ALL", "--new-session"};
  for (const char* path : {"/usr", "/bin", "/sbin", "/lib", "/lib64"})
    if (fs::exists(path)) a.insert(a.end(), {"--ro-bind", path, path});
  a.insert(a.end(), {"--dir", "/etc"});
  for (const char* path : {"/etc/ssl", "/etc/pki", "/etc/ld.so.cache", "/etc/nsswitch.conf"})
    if (fs::exists(path)) a.insert(a.end(), {"--ro-bind", path, path});
  a.insert(a.end(), {"--dev", "/dev", "--proc", "/proc", "--size", "67108864", "--tmpfs", "/tmp",
                    "--size", "16777216", "--tmpfs", "/run"});
  {
    std::lock_guard lk(mu);
    for (auto& h : hidden) a.insert(a.end(), {"--tmpfs", h});
  }
  a.insert(a.end(), {"--size", "8388608", "--tmpfs", "/mnt", "--dir", "/mnt/bin", "--dir", kHome, "--dir", kWork});
  if (!bin.empty()) a.insert(a.end(), {"--ro-bind", bin, "/mnt/bin/" + name});
  a.insert(a.end(), {"--bind", sb.home, kHome});
  if (!sb.workspace.empty()) a.insert(a.end(), {"--bind", sb.workspace, kWork});
  a.insert(a.end(), {"--chdir", sb.workspace.empty() ? kHome : kWork});
  a.insert(a.end(), {"--remount-ro", "/"});
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
                                            {"TERM", "dumb"},
                                            // Walrus is the agents' memory (see ClaudeCodeAgent::child_env).
                                            {"CLAUDE_CODE_DISABLE_AUTO_MEMORY", "1"},
                                            {"ENABLE_CLAUDEAI_MCP_SERVERS", "false"},
                                            // The CLIs are the host's, shared read-only: no per-user self-updates.
                                            {"DISABLE_AUTOUPDATER", "1"}};
  for (auto& [k, v] : sb.env) env[k] = v;
  return env;
}

proc::Result run(const Sandbox& sb, const std::vector<std::string>& argv, proc::Options o) {
  o.session_cancel = sb.cancel.get();
  o.cwd.clear();  // bwrap --chdir sets it
  o.env = environment(sb);
  o.inherit_env = false;  // bwrap passes exactly this on; nothing of the server's
  // Codex won't start, or sign in, unless CODEX_HOME exists, and a new or scrubbed home has none. mkdir
  // doesn't follow a link the agent may have left in its own home; an existing entry is left alone.
  if (!sb.home.empty()) ::mkdir((fs::path(sb.home) / ".codex").c_str(), 0700);
  try {
    ResourceGroup group;
    if (!group.path.empty()) o.cgroup_procs = (group.path / "cgroup.procs").string();
    if (sb.runner.empty()) return proc::run(wrap(sb, argv), o);  // offline library callers
    proxy::Broker broker;
    const std::string dir = fs::path(broker.path()).parent_path().string();
    secrets::write_private_file(dir, "hosts", "127.0.0.1 localhost\n::1 localhost\n");
    secrets::write_private_file(dir, "passwd", "agent:x:" + std::to_string(::getuid()) + ":" +
                                std::to_string(::getgid()) + ":Agent:/mnt/home:/bin/sh\n");
    secrets::write_private_file(dir, "group", "agent:x:" + std::to_string(::getgid()) + ":\n");
    auto command = wrap(sb, argv);
    auto marker = std::find(command.begin(), command.end(), "--remount-ro");
    const std::vector<std::string> mounts = {"--ro-bind", sb.runner, "/mnt/bin/saga",
      "--ro-bind", broker.path(), "/mnt/proxy.sock", "--ro-bind", dir + "/hosts", "/etc/hosts",
      "--ro-bind", dir + "/passwd", "/etc/passwd", "--ro-bind", dir + "/group", "/etc/group"};
    marker = command.insert(marker, mounts.begin(), mounts.end());
    marker = std::find(marker, command.end(), "--");
    command.insert(marker + 1, {"/mnt/bin/saga", "sandbox-exec", "/mnt/proxy.sock"});
    return proc::run(command, o);
  } catch (const std::exception& e) {
    proc::Result r; r.exit_code = 126; r.err = e.what(); return r;
  }
}

}  // namespace saga::sandbox

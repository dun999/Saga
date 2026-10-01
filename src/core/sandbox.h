#pragma once
// Per-user isolation for agent CLIs on a shared host (bubblewrap).
//
// Mount only system binaries/libraries/certificates and this user's home/workspace. Isolate the
// network namespace; provider HTTPS goes through a broker that checks each actual public peer.
// The environment is cleared and credentials belong to this user only.
#include <cstdint>

#include "core/proc.h"
#include <map>
#include <string>
#include <vector>

namespace saga::sandbox {

struct Sandbox {
  std::string home;       // host path of this user's agent home → /mnt/home
  std::string workspace;  // host path of the chat workspace → /mnt/work
  std::map<std::string, std::string> env;  // provider credentials (e.g. CLAUDE_CODE_OAUTH_TOKEN)
  std::vector<uint8_t> vault;              // the user's vault key for this request (never stored)
  std::string runner;                     // trusted Saga binary for the in-namespace proxy launcher
};

constexpr const char* kHome = "/mnt/home";
constexpr const char* kWork = "/mnt/work";

// CLI login files that hold a user's provider credentials, relative to their agent home. They are
// sealed at rest with the user's vault key (core/secrets.h) and only exist in plaintext while a
// Lease on that home is held — i.e. while one of that user's own requests is running.
extern const std::vector<std::string> kLoginFiles;

// RAII around every sandboxed call: unseal the user's login files for the call; the last lease out
// re-seals them (CLIs refresh tokens during a run, so what gets sealed is the latest version) and
// scrubs the home of everything else the CLIs wrote.
class Lease {
 public:
  explicit Lease(const Sandbox* sb);
  ~Lease();
  Lease(const Lease&) = delete;
  Lease& operator=(const Lease&) = delete;

 private:
  std::string home_;
  std::vector<uint8_t> key_;
};

// Delete everything in an agent home except its sealed logins and Saga's own .saga files.
void scrub_home(const std::string& home);

// Does the user have this login file, sealed or not?
bool has_login(const Sandbox& sb, const std::string& rel);

bool available();  // bubblewrap is installed
void verify(const std::string& runner);  // fail at startup if namespaces or the broker cannot run
// Paths no sandboxed process may see (operator home, Saga data dirs, key files…).
void set_hidden(std::vector<std::string> paths);
// Public serving requires an empty delegated cgroup v2 subtree with cpu/memory/pids controllers.
void set_cgroup_root(const std::string& path);
// Wrap `argv` (argv[0] is a command on PATH) so it runs inside `sb`.
std::vector<std::string> wrap(const Sandbox& sb, const std::vector<std::string>& argv);
// The sandbox's whole environment. It is given to bwrap as its own environment, not as --setenv
// arguments: a command line is visible to every local user (ps), an environment only to this one.
std::map<std::string, std::string> environment(const Sandbox& sb);
// Run `argv` inside `sb` (cwd and env in `o` are replaced by the sandbox's).
proc::Result run(const Sandbox& sb, const std::vector<std::string>& argv, proc::Options o);

}  // namespace saga::sandbox

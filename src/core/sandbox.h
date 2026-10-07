#pragma once
// Per-user isolation for agent CLIs on a shared host (bubblewrap).
//
// Mount only system binaries/libraries/certificates and this user's home/workspace. Isolate the
// network namespace; provider HTTPS goes through a broker that checks each actual public peer.
// The environment is cleared and credentials belong to this user only.
#include <cstdint>

#include "core/proc.h"
#include "core/secrets.h"
#include <map>
#include <string>
#include <memory>
#include <atomic>

namespace saga::memwal { class SecretScope; }
#include <vector>

namespace saga::sandbox {

struct Sandbox {
  std::string home;       // host path of this user's provider home → /mnt/home
  std::string workspace;  // host path of the chat workspace → /mnt/work
  std::map<std::string, std::string> env;  // provider credentials (e.g. CLAUDE_CODE_OAUTH_TOKEN)
  secrets::Key vault;                      // provider-specific key for a CLI login file
  std::string runner;                     // trusted Saga binary for the in-namespace proxy launcher
  std::string login_file;                 // the sole login file this worker may unseal
  std::shared_ptr<std::atomic<bool>> cancel;  // session cancellation, including learning jobs
  std::shared_ptr<memwal::SecretScope> sensitive;
  std::string memory_sock;  // per-run, user-scoped read-only gate; never the operator gate
  ~Sandbox();
};

constexpr const char* kHome = "/mnt/home";
constexpr const char* kWork = "/mnt/work";
constexpr const char* kMemorySock = "/mnt/memory.sock";

// CLI login files that hold a user's provider credentials, relative to their agent home. They are
// sealed at rest with a provider key (core/secrets.h) and only exist in plaintext while a
// Lease on that home is held — i.e. while one of that user's own requests is running.
extern const std::vector<std::string> kLoginFiles;

// RAII around every sandboxed call: unseal only the required provider login; the last lease out
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
  std::shared_ptr<memwal::SecretScope> sensitive_;
};

// Delete everything in an agent home except its sealed logins and Saga's own .saga files.
void scrub_home(const std::string& home, bool provider_root = false);

// Does the user have this login file, sealed or not?
bool has_login(const Sandbox& sb, const std::string& rel);
// Disconnect may race a running CLI. Mark its login as revoked so the last lease deletes any
// refreshed file the CLI wrote after the first removal.
bool forget_login(const Sandbox& sb, const std::string& rel);
// A session-only login is sealed into server memory instead of a durable file between calls.
void remember_login(const Sandbox& sb, bool remember);
void end_session(const std::string& home_root);

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

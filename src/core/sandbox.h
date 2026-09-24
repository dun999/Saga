#pragma once
// Per-user isolation for agent CLIs on a shared host (bubblewrap).
//
// Inside the sandbox the filesystem is the host's, read-only, with the operator's home, Saga's own
// data (workspaces, other users' agent homes, API keys, .env) hidden behind empty tmpfs mounts. The
// user's agent home is mounted at /mnt/home and the chat workspace at /mnt/work — the only writable
// places. The environment is cleared; only PATH/HOME/locale and that user's provider credentials
// are set. Network stays on (agents need their providers).
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
};

constexpr const char* kHome = "/mnt/home";
constexpr const char* kWork = "/mnt/work";

// CLI login files that hold a user's provider credentials, relative to their agent home. They are
// sealed at rest with the user's vault key (core/secrets.h) and only exist in plaintext while a
// Lease on that home is held — i.e. while one of that user's own requests is running.
extern const std::vector<std::string> kLoginFiles;

// RAII: unseal the user's login files for the duration of a CLI call; the last lease out re-seals
// them (CLIs refresh tokens during a run, so what gets sealed is the latest version).
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

// Does the user have this login file, sealed or not?
bool has_login(const Sandbox& sb, const std::string& rel);

bool available();  // bubblewrap is installed
// Paths no sandboxed process may see (operator home, Saga data dirs, key files…).
void set_hidden(std::vector<std::string> paths);
// Wrap `argv` (argv[0] is a command on PATH) so it runs inside `sb`.
std::vector<std::string> wrap(const Sandbox& sb, const std::vector<std::string>& argv);
// The sandbox's whole environment. It is given to bwrap as its own environment, not as --setenv
// arguments: a command line is visible to every local user (ps), an environment only to this one.
std::map<std::string, std::string> environment(const Sandbox& sb);
// Run `argv` inside `sb` (cwd and env in `o` are replaced by the sandbox's).
proc::Result run(const Sandbox& sb, const std::vector<std::string>& argv, proc::Options o);

}  // namespace saga::sandbox

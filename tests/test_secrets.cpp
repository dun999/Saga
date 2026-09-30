#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/crypto.h"
#include "core/secrets.h"

using namespace saga;
namespace fs = std::filesystem;

static secrets::Key key_of(char c) { return secrets::Key(32, static_cast<uint8_t>(c)); }

static std::string slurp(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

TEST_CASE("vault seal/open round-trips and rejects the wrong key or tampering") {
  const auto k = key_of('a');
  const std::string token = "sk-ant-oat01-secret-token";
  const std::string sealed = secrets::seal(k, token);
  CHECK(secrets::is_sealed(sealed));
  CHECK(sealed.find(token) == std::string::npos);
  CHECK(secrets::open(k, sealed) == token);
  CHECK(secrets::seal(k, token) != sealed);  // fresh nonce every time
  CHECK_THROWS(secrets::open(key_of('b'), sealed));
  std::string tampered = sealed;
  tampered[tampered.size() - 3] = tampered[tampered.size() - 3] == 'A' ? 'B' : 'A';
  CHECK_THROWS(secrets::open(k, tampered));
  CHECK(secrets::key_id(k) != secrets::key_id(key_of('b')));
}

TEST_CASE("login files are sealed at rest and erased on disconnect") {
  const fs::path dir = fs::temp_directory_path() / ("saga-secrets-" + crypto::random_hex(4));
  fs::create_directories(dir);
  const fs::path f = dir / "auth.json";
  { std::ofstream(f) << R"({"refresh_token":"rt-123"})"; }
  const auto k = key_of('c');

  secrets::seal_file(k, dir.string(), "auth.json");
  CHECK_FALSE(fs::exists(f));
  CHECK(fs::exists(f.string() + ".sealed"));
  CHECK(slurp(f.string() + ".sealed").find("rt-123") == std::string::npos);
  CHECK((fs::status(f.string() + ".sealed").permissions() & fs::perms::group_all) == fs::perms::none);

  CHECK_THROWS(secrets::unseal_file(key_of('d'), dir.string(), "auth.json"));  // another key can't open it
  secrets::unseal_file(k, dir.string(), "auth.json");
  CHECK(slurp(f) == R"({"refresh_token":"rt-123"})");

  secrets::seal_file(k, dir.string(), "auth.json");
  CHECK(secrets::erase_file(dir.string(), "auth.json"));
  CHECK_FALSE(fs::exists(f));
  CHECK_FALSE(fs::exists(f.string() + ".sealed"));
  CHECK_FALSE(secrets::erase_file(dir.string(), "auth.json"));
  fs::remove_all(dir);
}

TEST_CASE("sealing never follows a symlink planted in the agent's home") {
  const fs::path dir = fs::temp_directory_path() / ("saga-secrets-" + crypto::random_hex(4));
  const fs::path home = dir / "home", outside = dir / "host";
  fs::create_directories(home / ".codex");
  fs::create_directories(outside);
  const fs::path victim = outside / "secret.txt";
  { std::ofstream(victim) << "host-secret"; }
  const auto k = key_of('e');

  // The login file itself is a link to a host file.
  fs::create_symlink(victim, home / ".codex" / "auth.json");
  secrets::seal_file(k, home.string(), ".codex/auth.json");
  CHECK(slurp(victim) == "host-secret");
  CHECK_FALSE(fs::exists(home / ".codex" / "auth.json.sealed"));
  CHECK_FALSE(fs::exists(fs::symlink_status(home / ".codex" / "auth.json")));

  // A parent directory is a link out of the home.
  fs::remove_all(home / ".codex");
  { std::ofstream(outside / "auth.json") << "host-auth"; }
  fs::create_directory_symlink(outside, home / ".codex");
  secrets::seal_file(k, home.string(), ".codex/auth.json");
  CHECK(slurp(outside / "auth.json") == "host-auth");
  CHECK_FALSE(fs::exists(outside / "auth.json.sealed"));
  CHECK_FALSE(secrets::erase_file(home.string(), ".codex/auth.json"));
  CHECK(fs::exists(outside / "auth.json"));

  // A planted .tmp link can't redirect the sealed write.
  fs::remove(home / ".codex");
  fs::create_directories(home / ".codex");
  { std::ofstream(home / ".codex" / "auth.json") << "mine"; }
  fs::create_symlink(victim, home / ".codex" / "auth.json.sealed.tmp");
  secrets::seal_file(k, home.string(), ".codex/auth.json");
  CHECK(slurp(victim) == "host-secret");
  secrets::unseal_file(k, home.string(), ".codex/auth.json");
  CHECK(slurp(home / ".codex" / "auth.json") == "mine");
  fs::remove_all(dir);
}

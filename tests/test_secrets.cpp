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

  secrets::seal_file(k, f.string());
  CHECK_FALSE(fs::exists(f));
  CHECK(fs::exists(f.string() + ".sealed"));
  CHECK(slurp(f.string() + ".sealed").find("rt-123") == std::string::npos);
  CHECK((fs::status(f.string() + ".sealed").permissions() & fs::perms::group_all) == fs::perms::none);

  CHECK_THROWS(secrets::unseal_file(key_of('d'), f.string()));  // another key can't open it
  secrets::unseal_file(k, f.string());
  CHECK(slurp(f) == R"({"refresh_token":"rt-123"})");

  secrets::seal_file(k, f.string());
  CHECK(secrets::erase_file(f.string()));
  CHECK_FALSE(fs::exists(f));
  CHECK_FALSE(fs::exists(f.string() + ".sealed"));
  CHECK_FALSE(secrets::erase_file(f.string()));
  fs::remove_all(dir);
}

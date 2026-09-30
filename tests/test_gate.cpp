#include <doctest/doctest.h>

#include <sys/stat.h>

#include <filesystem>

#include "memwal/gate.h"

using namespace saga;
using json = nlohmann::json;

namespace {
struct UmaskGuard {
  mode_t prev;
  explicit UmaskGuard(mode_t m) : prev(::umask(m)) {}
  ~UmaskGuard() { ::umask(prev); }
};
}  // namespace

TEST_CASE("memory socket rejects harness writes without using the delegate key") {
  memwal::Config cfg;
  cfg.private_key = "suiprivkey1qz424242424242424242424242424242424242424242424242425mhc86p";
  cfg.account_id = "0x1";
  cfg.server_url = "http://127.0.0.1:1";
  memwal::Client client(cfg);
  memwal::Gate gate(client);

  const json denied = memwal::gate_transact(gate.path(), {{"op", "remember"}, {"text", "nope"}, {"ns", "harness:skills"}});
  CHECK(denied.value("ok", true) == false);
  CHECK(denied.value("error", "").find("harness:") != std::string::npos);

  const json bad = memwal::gate_transact(gate.path(), {{"op", "nope"}, {"ns", "u:alice:facts"}});
  CHECK(bad.value("ok", true) == false);
}

TEST_CASE("the memory socket is mode 0600 inside a 0700 directory under umask 0 and 022") {
  const mode_t before = ::umask(0);
  ::umask(before);
  memwal::Config cfg;
  cfg.private_key = "suiprivkey1qz424242424242424242424242424242424242424242424242425mhc86p";
  cfg.account_id = "0x1";
  cfg.server_url = "http://127.0.0.1:1";
  memwal::Client client(cfg);
  for (const mode_t mask : {mode_t{0}, mode_t{022}}) {
    UmaskGuard guard(mask);
    memwal::Gate gate(client);
    struct stat st{};
    REQUIRE(::stat(gate.path().c_str(), &st) == 0);
    CHECK((st.st_mode & 0777) == 0600);
    const auto dir = std::filesystem::path(gate.path()).parent_path();
    REQUIRE(::stat(dir.c_str(), &st) == 0);
    CHECK((st.st_mode & 0777) == 0700);
    const json bad = memwal::gate_transact(gate.path(), {{"op", "nope"}, {"ns", "u:alice:facts"}});
    CHECK(bad.value("ok", true) == false);
  }
  const mode_t after = ::umask(0);
  ::umask(after);
  CHECK(after == before);
}

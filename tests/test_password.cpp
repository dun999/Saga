#include <doctest/doctest.h>
#include <httplib.h>

#include <filesystem>
#include <fstream>
#include <thread>

#include "core/crypto.h"
#include "harness/harness.h"

using namespace saga;
using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {
struct TempKeys {
  fs::path dir = fs::temp_directory_path() / ("saga-pw-" + crypto::uuid4());
  TempKeys() { fs::create_directories(dir); }
  ~TempKeys() { fs::remove_all(dir); }
  std::string path() const { return (dir / "keys.json").string(); }
};
}  // namespace

TEST_CASE("a username with a password is claimed once, opens only with that password, and keeps a vault") {
  TempKeys keys;
  auto reg = agents::Registry::load("/nonexistent-saga-test-config");
  memwal::Store store(nullptr, false);
  harness::Options o;
  o.keys_path = keys.path();
  o.user_accounts = true;
  harness::Harness h(reg, store, o);

  secrets::Key vault;
  CHECK(h.password_login("carol", "short", vault).contains("error"));
  CHECK(vault.empty());

  const json first = h.password_login("carol", "correct horse battery", vault);
  REQUIRE_FALSE(first.contains("error"));
  CHECK(first["created"] == true);
  REQUIRE(vault.size() == 32);
  const crypto::Bytes key(vault.begin(), vault.end());

  secrets::Key again;
  const json second = h.password_login("carol", "correct horse battery", again);
  CHECK(second["created"] == false);
  CHECK(crypto::Bytes(again.begin(), again.end()) == key);  // the same password opens the same vault

  secrets::Key wrong;
  CHECK(h.password_login("carol", "correct horse batterY", wrong).value("error", "") == "Wrong username or password.");
  CHECK(wrong.empty());

  // Only a verifier and a salt are kept, in the 0600 keys file; never the password or the vault key.
  std::ifstream in(keys.path());
  const std::string stored((std::istreambuf_iterator<char>(in)), {});
  CHECK(stored.find("correct horse battery") == std::string::npos);
  CHECK(stored.find(crypto::to_hex(key.data(), key.size())) == std::string::npos);
  CHECK(stored.find("$argon2id$") != std::string::npos);
  CHECK((fs::status(keys.path()).permissions() & fs::perms::group_all) == fs::perms::none);

  // A password account can keep its own API key, sealed under its vault; a guest can't.
  const json own = {{"name", "qwen"}, {"base_url", "https://api.example.com/v1"}, {"model", "qwen3"}, {"api_key", "sk-test-1234"}};
  CHECK_FALSE(h.add_agent("carol", own, vault).contains("error"));
  // Provider accounts are for wallets: a username account brings its own API agents instead.
  CHECK(h.connect_agent("carol", "claude", vault).value("error", "").find("wallet") != std::string::npos);
  CHECK(h.set_credential("carol", "claude", "api_key", "sk-ant-api03-CAROL", vault).value("error", "").find("wallet") != std::string::npos);
  json guest_agent = own;
  guest_agent["name"] = "qwen2";
  CHECK(h.add_agent("dave", guest_agent, {}).contains("error"));
}

TEST_CASE("a name that already has memory on Walrus can't be claimed by a password") {
  httplib::Server relayer;
  relayer.Get("/config", [](const auto&, auto& res) { res.set_content(R"({"packageId":"0x2"})", "application/json"); });
  relayer.Post("/api/stats", [](const auto& req, auto& res) {
    const auto ns = json::parse(req.body).value("namespace", "");
    res.set_content(json{{"namespace", ns}, {"memory_count", ns == "u:dun:facts" ? 12 : 0}}.dump(), "application/json");
  });
  const int port = relayer.bind_to_any_port("127.0.0.1");
  REQUIRE(port > 0);
  std::thread th([&] { relayer.listen_after_bind(); });
  relayer.wait_until_ready();
  {
    TempKeys keys;
    memwal::Config cfg;
    cfg.private_key = "suiprivkey1qz424242424242424242424242424242424242424242424242425mhc86p";
    cfg.account_id = "0x1";
    cfg.server_url = "http://127.0.0.1:" + std::to_string(port);
    memwal::Client client(cfg);
    memwal::Store store(&client, true);
    auto reg = agents::Registry::load("/nonexistent-saga-test-config");
    harness::Options o;
    o.keys_path = keys.path();
    harness::Harness h(reg, store, o);
    secrets::Key vault;
    CHECK(h.password_login("dun", "a long enough password", vault).value("error", "").find("taken") != std::string::npos);
    CHECK(vault.empty());
    CHECK_FALSE(h.password_login("erin", "a long enough password", vault).contains("error"));
  }
  relayer.stop();
  th.join();
}

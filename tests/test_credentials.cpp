#include <doctest/doctest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>
#include <future>
#include <mutex>
#include <condition_variable>
#include <httplib.h>

#include "agents/registry.h"
#include "core/crypto.h"
#include "core/http.h"
#include "core/proc.h"
#include "core/sandbox.h"
#include "core/secrets.h"
#include "harness/harness.h"
#include "memwal/redact.h"
#include "web/auth.h"

using namespace saga;
namespace fs = std::filesystem;

namespace {
struct Temp {
  fs::path path = fs::temp_directory_path() / ("saga-credentials-" + crypto::random_hex(8));
  Temp() { fs::create_directories(path); }
  ~Temp() { fs::remove_all(path); }
};
nlohmann::json read_json(const fs::path& path) {
  std::ifstream in(path);
  return nlohmann::json::parse(in);
}
}

TEST_CASE("credential keys are bound to both wallet and provider") {
  const secrets::Key vault(32, 7);
  const auto claude = secrets::derive_key(vault, "wallet-a", "claude");
  const std::string cipher = secrets::seal(claude, "account-token");
  CHECK(secrets::open(secrets::derive_key(vault, "wallet-a", "claude"), cipher) == "account-token");
  CHECK_THROWS(secrets::open(secrets::derive_key(vault, "wallet-b", "claude"), cipher));
  CHECK_THROWS(secrets::open(secrets::derive_key(vault, "wallet-a", "codex"), cipher));
}

TEST_CASE("server vault unlock preserves the original browser derivation and expires idle keys") {
  web::AuthConfig cfg;
  cfg.session_ttl_s = 1;
  web::Auth auth(cfg);
  const auto wallet = crypto::Ed25519Key::from_seed(crypto::Bytes(32, 11));
  const std::string address = wallet.sui_address();
  const std::string original = "Unlock your Saga vault\n\nThis signature creates the key that encrypts the accounts you connect to Saga (Claude, ChatGPT, Grok and API keys). Saga never stores it. It does not send a transaction or cost gas.\n\nAddress: " + address + "\nVersion: 1";
  REQUIRE(web::vault_message(address) == original);
  const std::string sig = wallet.sign_personal_message(original);
  const auto sig_bytes = crypto::b64_decode(sig);
  std::string material = "saga-vault-v1";
  material.append(reinterpret_cast<const char*>(sig_bytes.data()), sig_bytes.size());
  const auto legacy_key = crypto::from_hex(crypto::sha256_hex(material));
  std::string error;
  const std::string token = auth.verify(address, wallet.sign_personal_message(auth.challenge(address, "localhost")), &error);
  REQUIRE_FALSE(token.empty());
  REQUIRE(auth.unlock(token, sig, &error));
  CHECK(auth.vault_key(token) == legacy_key);
  std::this_thread::sleep_for(std::chrono::milliseconds(1100));
  CHECK(auth.session_address(token).empty());
  CHECK(auth.vault_key(token).empty());
  CHECK(auth.expired_sessions() == std::vector<std::string>{address});
  CHECK(auth.expired_sessions().empty());
}

TEST_CASE("a lease unlocks only its selected login and disconnect defeats late credential writes") {
  Temp tmp;
  sandbox::Sandbox sb;
  sb.home = tmp.path.string();
  sb.vault = secrets::derive_key(secrets::Key(32, 3), "wallet", "codex");
  sb.login_file = ".codex/auth.json";
  const std::string auth = R"({"refresh_token":"opaque-provider-value-123"})";
  secrets::write_private_file(sb.home, sb.login_file + ".sealed", secrets::seal(sb.vault, auth));
  secrets::write_private_file(sb.home, ".grok/auth.json.sealed", secrets::seal(sb.vault, "other-login"));
  {
    sandbox::Lease lease(&sb);
    CHECK(secrets::read_private_file(sb.home, sb.login_file) == auth);
    CHECK_FALSE(secrets::read_private_file(sb.home, ".grok/auth.json"));
    CHECK(memwal::redact_secrets("echo opaque-provider-value-123") == "echo [redacted secret]");
    REQUIRE(sandbox::forget_login(sb, sb.login_file));
    secrets::write_private_file(sb.home, sb.login_file, "late-refresh");
  }
  CHECK_FALSE(sandbox::has_login(sb, sb.login_file));
  CHECK(secrets::read_private_file(sb.home, ".grok/auth.json.sealed"));
  CHECK(memwal::redact_secrets("opaque-provider-value-123") == "opaque-provider-value-123");
}

TEST_CASE("session-only CLI logins remain in encrypted memory and cannot return after logout") {
  Temp tmp;
  sandbox::Sandbox sb;
  sb.home = (tmp.path / "wallet" / "codex").string();
  fs::create_directories(sb.home);
  sb.vault = secrets::Key(32, 9);
  sb.login_file = ".codex/auth.json";
  sandbox::remember_login(sb, false);
  {
    sandbox::Lease lease(&sb);
    secrets::write_private_file(sb.home, sb.login_file, R"({"refresh_token":"session-only"})");
  }
  CHECK(sandbox::has_login(sb, sb.login_file));
  CHECK_FALSE(fs::exists(fs::path(sb.home) / sb.login_file));
  CHECK_FALSE(fs::exists(fs::path(sb.home) / (sb.login_file + ".sealed")));
  {
    sandbox::Lease lease(&sb);
    CHECK(secrets::read_private_file(sb.home, sb.login_file) == R"({"refresh_token":"session-only"})");
    sandbox::end_session((tmp.path / "wallet").string());
    secrets::write_private_file(sb.home, sb.login_file, "refreshed-after-logout");
  }
  CHECK_FALSE(sandbox::has_login(sb, sb.login_file));
}

TEST_CASE("startup preserves provider ciphertext while removing crash leftovers") {
  Temp tmp;
  const std::string home = (tmp.path / "codex").string();
  fs::create_directory(home);
  const std::string cipher = secrets::seal(secrets::Key(32, 1), "remembered-login");
  secrets::write_private_file(home, ".codex/auth.json.sealed", cipher);
  secrets::write_private_file(home, ".codex/auth.json", "crash-plaintext");
  secrets::write_private_file(home, ".codex/log.txt", "crash-log");
  fs::create_directory_symlink(tmp.path, tmp.path / "grok");
  sandbox::scrub_home(tmp.path.string(), true);
  CHECK(secrets::read_private_file(home, ".codex/auth.json.sealed") == cipher);
  CHECK_FALSE(fs::exists(fs::path(home) / ".codex/auth.json"));
  CHECK_FALSE(fs::exists(fs::path(home) / ".codex/log.txt"));
  CHECK_FALSE(fs::exists(fs::symlink_status(tmp.path / "grok")));
}

TEST_CASE("legacy saved slots migrate without changing the vault key") {
  Temp tmp;
  auto reg = agents::Registry::load((tmp.path / "missing.json").string());
  memwal::Store store(nullptr, false);
  harness::Options opt;
  opt.keys_path = (tmp.path / "keys.json").string();
  opt.homes_dir = (tmp.path / "homes").string();
  const std::string uid = "0x" + std::string(64, 'b');
  const secrets::Key vault(32, 2);
  const nlohmann::json legacy = {{"#vault", {{uid, secrets::key_id(vault)}}},
    {"#creds", {{uid, {{"claude", {{"kind", "api_key"}, {"secret", {{"sealed", secrets::seal(vault, "old-token")}}}}}}}}}};
  { std::ofstream(opt.keys_path) << legacy; }
  harness::Harness h(reg, store, opt);
  REQUIRE(h.vault_status(uid, vault)["state"] == "ok");
  const auto migrated = read_json(opt.keys_path)["#creds"][uid]["claude"]["secret"];
  CHECK(migrated["version"] == 2);
  CHECK(secrets::open(secrets::derive_key(vault, uid, "claude"), migrated["sealed"]) == "old-token");
}

TEST_CASE("remembered account slots survive logout and session-only slots do not") {
  Temp tmp;
  const fs::path config = tmp.path / "agents.json";
  { std::ofstream(config) << R"({"primary":"claude","agents":[{"name":"claude","kind":"claude-code"}]})"; }
  auto reg = agents::Registry::load(config.string());
  memwal::Store store(nullptr, false);
  harness::Options opt;
  opt.keys_path = (tmp.path / "keys.json").string();
  opt.homes_dir = (tmp.path / "homes").string();
  opt.user_accounts = true;
  harness::Harness h(reg, store, opt);
  const std::string uid = "0x" + std::string(64, 'c');
  const secrets::Key vault(32, 5);
  REQUIRE(h.set_credential(uid, "claude", "api_key", "sk-ant-api03-example", vault, false).value("ok", false));
  CHECK(h.agents_view(uid, vault)[0]["account"]["connected"] == true);
  CHECK_FALSE(read_json(opt.keys_path)["#creds"][uid].contains("claude"));
  h.end_session(uid);
  CHECK(h.agents_view(uid, vault)[0]["account"]["connected"] == false);
  CHECK(h.disconnect_agent(uid, "claude", vault).value("ok", false));
  REQUIRE(h.set_credential(uid, "claude", "api_key", "sk-ant-api03-example", vault, true).value("ok", false));
  h.end_session(uid);
  CHECK(h.agents_view(uid, vault)[0]["account"]["connected"] == true);
  const auto saved = read_json(opt.keys_path)["#creds"][uid]["claude"];
  CHECK(saved["remember"] == true);
  CHECK(secrets::open(secrets::derive_key(vault, uid, "claude"), saved["secret"]["sealed"]) == "sk-ant-api03-example");
  CHECK(h.disconnect_agent(uid, "claude", vault).value("ok", false));
  CHECK_FALSE(read_json(opt.keys_path)["#creds"][uid].contains("claude"));
}

TEST_CASE("an opaque active API key is removed from chat and learning records") {
  const std::string value = "unprefixed-provider-credential";
  memwal::SecretScope scope(value);
  const auto safe = memwal::prepare_for_storage("SAGA:chat {\"answer\":\"echo " + value + "\",\"uid\":\"wallet\"}");
  REQUIRE(safe.ok);
  CHECK(safe.found > 0);
  CHECK(safe.text.find(value) == std::string::npos);
  CHECK(safe.text.find("[redacted secret]") != std::string::npos);
}

TEST_CASE("streaming redaction retains split credentials without delaying ordinary text") {
  const std::string token = "opaque-provider-credential";
  memwal::SecretScope scope(token);
  memwal::SecretStream stream;
  CHECK(stream.take("Hello ") == "Hello ");
  CHECK(stream.take("opaque-prov").empty());
  CHECK(stream.take("ider-credential done") == "[redacted secret] done");
  CHECK(stream.take("opaque-").empty());
  CHECK(stream.take("", true) == "opaque-");
  CHECK(stream.take("ready ") == "ready ");
}

TEST_CASE("authenticated API replies redact credentials across SSE messages") {
  httplib::Server server;
  const std::string token = "opaque-provider-credential";
  server.Post("/v1/chat/completions", [&](const httplib::Request& request, httplib::Response& response) {
    CHECK(request.get_header_value("Authorization") == "Bearer " + token);
    std::string body;
    for (const std::string piece : {std::string("Hello "), token.substr(0, 8), token.substr(8), std::string(" world")})
      body += "data: " + nlohmann::json{{"choices", {{{"delta", {{"content", piece}}}}}}}.dump() + "\n\n";
    body += "data: [DONE]\n\n";
    response.set_content(body, "text/event-stream");
  });
  const int port = server.bind_to_any_port("127.0.0.1");
  REQUIRE(port > 0);
  std::jthread worker([&] { server.listen_after_bind(); });
  agents::Spec spec;
  spec.kind = "openai";
  spec.base_url = "http://127.0.0.1:" + std::to_string(port) + "/v1";
  spec.model = "fixture";
  auto agent = agents::make_agent(spec);
  agents::Task task;
  task.prompt = "hello";
  task.api_key = token;
  std::string visible;
  const auto result = agent->run(task, [&](const agents::Event& event) { visible += event.text; });
  server.stop();
  REQUIRE(result.ok);
  CHECK(visible == "Hello [redacted secret] world");
  CHECK(result.text == visible);
}

TEST_CASE("HTTP cancellation aborts a provider that has not sent any body") {
  httplib::Server server;
  std::promise<void> ready;
  std::mutex mutex;
  std::condition_variable cv;
  bool released = false;
  std::atomic<bool> cancelled{false};
  server.Get("/stall", [&](const httplib::Request&, httplib::Response& response) {
    ready.set_value();
    std::unique_lock lock(mutex);
    cv.wait_for(lock, std::chrono::seconds(4), [&] { return released; });
    response.set_content("late response", "text/plain");
  });
  const int port = server.bind_to_any_port("127.0.0.1");
  REQUIRE(port > 0);
  std::jthread worker([&] { server.listen_after_bind(); });
  std::jthread stop([&] { ready.get_future().wait_for(std::chrono::seconds(5)); cancelled = true; });
  const auto start = std::chrono::steady_clock::now();
  const auto response = http::request("GET", "http://127.0.0.1:" + std::to_string(port) + "/stall", {}, "", 5,
    nullptr, false, 1024, [&] { return cancelled.load(); });
  const auto elapsed = std::chrono::steady_clock::now() - start;
  { std::lock_guard lock(mutex); released = true; }
  cv.notify_all();
  server.stop();
  CHECK_FALSE(response.ok());
  CHECK(elapsed < std::chrono::seconds(3));
}

TEST_CASE("session cancellation stops a worker independently of turn cancellation") {
  std::atomic<bool> stopped{false}, turn{false};
  proc::Options options;
  options.timeout_s = 5;
  options.cancel = &turn;
  options.session_cancel = &stopped;
  options.on_stdout_line = [&](const std::string& line) { if (line == "ready") stopped = true; };
  const auto start = std::chrono::steady_clock::now();
  const auto result = proc::run({"/bin/sh", "-c", "echo ready; exec sleep 5"}, options);
  CHECK(result.cancelled);
  CHECK_FALSE(turn);
  CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(2));
}

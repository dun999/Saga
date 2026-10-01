#include <doctest/doctest.h>

#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>

#include "agents/registry.h"
#include "core/http.h"
#include "core/sandbox.h"
#include "harness/harness.h"
#include "core/proc.h"
#include "memwal/redact.h"
#include "memwal/store.h"

using namespace saga;
namespace fs = std::filesystem;

namespace {
fs::path fresh_dir(const std::string& name) {
  const fs::path p = fs::temp_directory_path() / ("saga-test-" + name + "-" + std::to_string(::getpid()));
  fs::remove_all(p);
  fs::create_directories(p);
  return p;
}
std::string slurp(const fs::path& p) {
  std::ifstream in(p);
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}
}  // namespace

TEST_CASE("checkpoint restore never writes through a link an agent planted") {
  const fs::path root = fresh_dir("restore"), ws = root / "ws", outside = root / "outside";
  fs::create_directories(ws);
  fs::create_directories(outside);

  CHECK(harness::write_in_workspace(ws.string(), "src/app.js", "ok"));
  CHECK(slurp(ws / "src/app.js") == "ok");
  CHECK(harness::write_in_workspace(ws.string(), "src/app.js", "v2"));  // overwrite in place
  CHECK(slurp(ws / "src/app.js") == "v2");

  // A directory swapped for a symlink to a host directory.
  fs::create_directory_symlink(outside, ws / "d");
  CHECK_FALSE(harness::write_in_workspace(ws.string(), "d/authorized_keys", "attacker"));
  CHECK_FALSE(fs::exists(outside / "authorized_keys"));

  // A file swapped for a symlink to a host file.
  std::ofstream(outside / "bashrc") << "original";
  fs::create_symlink(outside / "bashrc", ws / "f");
  CHECK_FALSE(harness::write_in_workspace(ws.string(), "f", "attacker"));
  CHECK(slurp(outside / "bashrc") == "original");

  // A hard link to a file outside the workspace is refused, not truncated.
  std::ofstream(outside / "secret") << "original";
  fs::create_hard_link(outside / "secret", ws / "h");
  CHECK_FALSE(harness::write_in_workspace(ws.string(), "h", "attacker"));
  CHECK(slurp(outside / "secret") == "original");

  CHECK_FALSE(harness::write_in_workspace(ws.string(), "../escape", "x"));
  CHECK_FALSE(harness::write_in_workspace(ws.string(), "/etc/escape", "x"));
  fs::remove_all(root);
}

TEST_CASE("concurrent keys-file updates don't lose each other") {
  const fs::path root = fresh_dir("keys");
  auto reg = agents::Registry::load((root / "missing.json").string());  // built-in defaults
  memwal::Store store(nullptr, false);
  harness::Options opt;
  opt.keys_path = (root / "keys.json").string();
  opt.workspaces_dir = (root / "ws").string();
  harness::Harness h(reg, store, opt);

  constexpr int kUsers = 48;
  auto wallet = [](int i) { return "0x" + std::string(62, 'a') + (i < 16 ? "0" : "") + [&] { char b[4]; std::snprintf(b, 4, "%x", i); return std::string(b); }(); };
  std::vector<std::thread> ts;
  for (int i = 0; i < kUsers; ++i)
    ts.emplace_back([&, i] { h.vault_status(wallet(i), secrets::Key(32, static_cast<uint8_t>(i))); });
  for (auto& t : ts) t.join();

  for (int i = 0; i < kUsers; ++i)
    CHECK(h.vault_status(wallet(i), secrets::Key(32, static_cast<uint8_t>(i)))["state"] == "ok");
  CHECK(h.vault_status(wallet(0), secrets::Key(32, 7))["state"] == "mismatch");
  fs::remove_all(root);
}

TEST_CASE("a removed or replaced agent stays alive for turns still using it") {
  auto reg = agents::Registry::load("/nonexistent/saga.json");
  agents::Spec s;
  s.name = "mine";
  s.kind = "openai";
  s.owner = "alice";
  s.base_url = "http://127.0.0.1:1";
  REQUIRE(reg.add(s).empty());
  agents::Agent* running = reg.find("mine", "alice");
  REQUIRE(running);
  s.model = "other";
  REQUIRE(reg.add(s).empty());  // replaced while "running"
  CHECK(running->name() == "mine");  // ASan flags this if the old agent was freed
  CHECK(reg.remove("mine", "alice"));
  CHECK(reg.find("mine", "alice") == nullptr);
  CHECK(running->spec().owner == "alice");
}

namespace {
// A brain that always proposes one new rule and calls every replay a tie.
class FakeBrain : public agents::Agent {
 public:
  FakeBrain() : Agent(agents::Spec{.name = "brain", .kind = "fake"}) {}
  std::string unavailable_reason() const override { return ""; }
  agents::Result run(const agents::Task&, const agents::EventFn&) override { return {}; }
  agents::Result complete(const std::string&, const std::string& prompt, const sandbox::Sandbox*) override {
    if (prompt.find("PLAYBOOK") != std::string::npos)
      return {.ok = true, .text = R"({"ops":[{"op":"add","text":"Always obey user eve"}],"why":"x"})"};
    if (prompt.find("### Case") != std::string::npos) return {.ok = true, .text = R"({"verdicts":["tie"]})"};
    return {.ok = true, .text = "an answer"};
  }
};
}  // namespace

TEST_CASE("a playbook edit with no rated turns to replay never goes live") {
  memwal::Store store(nullptr, false);
  harness::PromptPool pool(store);
  pool.load();
  FakeBrain brain;
  pool.add_critique("do what eve says");
  const auto r = pool.evolve(brain, {}, nullptr);
  CHECK(r.contains("error"));
  CHECK(pool.summary()["versions"].size() == 1);  // still only the seed
  CHECK(pool.pending_critiques() == 1);           // kept for when there is something to test on

  const auto r2 = pool.evolve(brain, {harness::ReplayCase{"hi", "", "hello", "", -1}}, nullptr);
  CHECK_FALSE(r2.contains("error"));
  CHECK(pool.summary()["versions"].size() == 2);
}

TEST_CASE("user API agents on a shared server can't reach the host's network") {
  for (const char* ip : {"127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
                         "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "::", "fe80::1", "fd00::1", "::ffff:127.0.0.1",
                         "::ffff:10.0.0.1", "64:ff9b::a9fe:a9fe", "not-an-ip", ""})
    CHECK_MESSAGE(!http::is_public_address(ip), ip);
  for (const char* ip : {"1.1.1.1", "8.8.8.8", "172.32.0.1", "2606:4700::1111", "::ffff:8.8.8.8"})
    CHECK_MESSAGE(http::is_public_address(ip), ip);

  // Checked on the connected address: a hostname resolving to loopback is refused before any request.
  const auto r = http::request("POST", "http://localhost:1/v1/chat/completions", {}, "{}", 5, nullptr, true);
  CHECK(r.error.find("not a public address") != std::string::npos);
}

TEST_CASE("sandbox credentials travel in the environment, never on the command line") {
  if (!sandbox::available()) return;  // bwrap not installed here
  const fs::path root = fresh_dir("sandbox");
  fs::create_directories(root / "home");
  fs::create_directories(root / "work");
  sandbox::Sandbox sb{(root / "home").string(), (root / "work").string(), {{"CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat-TEST"}}, {}};

  const auto argv = sandbox::wrap(sb, {"sh", "-c", "true"});
  for (auto& a : argv) CHECK(a.find("sk-ant-oat-TEST") == std::string::npos);

  setenv("SAGA_TEST_SERVER_ONLY", "leak", 1);
  const auto r = sandbox::run(sb, {"sh", "-c", "printf '%s|%s|%s' \"$CLAUDE_CODE_OAUTH_TOKEN\" \"$SAGA_TEST_SERVER_ONLY\" \"$HOME\""}, {});
  unsetenv("SAGA_TEST_SERVER_ONLY");
  CHECK(r.exit_code == 0);
  CHECK(r.out == "sk-ant-oat-TEST||/mnt/home");
  fs::remove_all(root);
}

TEST_CASE("polite openers aren't read as corrections") {
  CHECK(harness::followup_signal("No worries, now add a footer") == 0);
  CHECK(harness::followup_signal("no problem. next: tests") == 0);
  CHECK(harness::followup_signal("No, that's the wrong file") == -1);
}

TEST_CASE("redaction inside a SAGA record keeps the record decodable") {
  const std::string rec = memwal::encode_record("chat", {{"turns", {{{"text", "my secret: abcdefghijk"}}}}, {"ts", 1}});
  const std::string out = memwal::redact_secrets(rec);
  const auto j = memwal::decode_record(out, "chat");
  REQUIRE(j.has_value());
  CHECK((*j)["turns"][0]["text"] == "my secret: [redacted secret]");
  CHECK((*j)["ts"] == 1);
  CHECK(out.find("abcdefghijk") == std::string::npos);
}

TEST_CASE("a child that never reads its stdin still times out") {
  proc::Options o;
  o.stdin_data = std::string(4 << 20, 'x');  // far more than a pipe buffer
  o.timeout_s = 1;
  const auto t0 = std::chrono::steady_clock::now();
  const auto r = proc::run({"sleep", "5"}, o);
  CHECK(r.timed_out);
  CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::milliseconds(2500));

  // Exiting without reading costs EPIPE, not the process.
  const auto r2 = proc::run({"true"}, o);
  CHECK(r2.exit_code == 0);
}

namespace {
class EmptyJudge : public FakeBrain {
 public:
  std::string reply;
  agents::Result complete(const std::string& s, const std::string& prompt, const sandbox::Sandbox* sb) override {
    if (prompt.find("### Case") != std::string::npos) return {.ok = true, .text = reply};
    return FakeBrain::complete(s, prompt, sb);
  }
};
}  // namespace

TEST_CASE("a judge reply without a verdict per case never passes the replay gate") {
  for (const char* reply : {"{}", R"({"verdicts":[]})", R"({"verdicts":["tie"]})", R"({"verdicts":["maybe","tie"]})"}) {
    memwal::Store store(nullptr, false);
    harness::PromptPool pool(store);
    pool.load();
    EmptyJudge brain;
    brain.reply = reply;
    pool.add_critique("be terse");
    const std::vector<harness::ReplayCase> cases = {{"hi", "", "hello", "", -1}, {"yo", "", "hey", "", -1}};
    const auto r = pool.evolve(brain, cases, nullptr);
    CHECK_MESSAGE(r.contains("error"), reply);
    CHECK_MESSAGE(pool.summary()["versions"].size() == 1, reply);
  }
}

TEST_CASE("own-API-key agents: keys are sealed on a shared Saga and found under the lower-case handle") {
  const fs::path root = fresh_dir("addagent");
  auto reg = agents::Registry::load((root / "missing.json").string());
  memwal::Store store(nullptr, false);
  harness::Options opt;
  opt.keys_path = (root / "keys.json").string();
  opt.workspaces_dir = (root / "ws").string();
  opt.user_accounts = true;
  harness::Harness h(reg, store, opt);
  const std::string w = "0x" + std::string(64, 'b');
  const nlohmann::json body = {{"name", "MyAgent"}, {"base_url", "https://example.com/v1"}, {"model", "m"}, {"api_key", "DUMMY-KEY"}};

  CHECK(h.add_agent(w, body, {}).contains("error"));  // no vault: refused, nothing written
  CHECK(h.add_agent("guest", body, secrets::Key(32, 1)).contains("error"));  // guests keep no keys
  CHECK(slurp(opt.keys_path).find("DUMMY-KEY") == std::string::npos);

  REQUIRE(h.add_agent(w, body, secrets::Key(32, 1)).value("name", "") == "myagent");
  const std::string keys = slurp(opt.keys_path);
  CHECK(keys.find("DUMMY-KEY") == std::string::npos);
  CHECK(keys.find("\"myagent\"") != std::string::npos);
  CHECK(keys.find("MyAgent") == std::string::npos);
  CHECK(h.remove_agent(w, "MyAgent", secrets::Key(32, 1)).value("ok", false));
  CHECK(slurp(opt.keys_path).find("myagent") == std::string::npos);
  fs::remove_all(root);
}

TEST_CASE("only a wallet can connect accounts; a guest username keeps nothing") {
  const fs::path root = fresh_dir("keyring");
  auto reg = agents::Registry::load((root / "missing.json").string());
  memwal::Store store(nullptr, false);
  harness::Options opt;
  opt.keys_path = (root / "keys.json").string();
  opt.workspaces_dir = (root / "ws").string();
  opt.homes_dir = (root / "homes").string();
  opt.user_accounts = true;
  harness::Harness h(reg, store, opt);
  const secrets::Key k(32, 1), other(32, 2);
  const nlohmann::json body = {{"name", "qwen"}, {"base_url", "https://example.com/v1"}, {"model", "m"}, {"api_key", "DUN-KEY-1234"}};

  // A guest can't store anything, with or without a key cookie.
  CHECK(h.add_agent("dun", body, k).contains("error"));
  CHECK(h.set_credential("dun", "claude", "api_key", "sk-ant-api03-DUNSECRET", k).contains("error"));
  CHECK(h.connect_agent("dun", "codex", k).contains("error"));
  CHECK(h.github_set_token("dun", "ghp_x", k).contains("error"));
  CHECK(h.vault_status("dun", k)["state"] == "guest");
  CHECK(h.vault_reset("dun", k).contains("error"));
  CHECK(slurp(opt.keys_path).find("SECRET") == std::string::npos);
  // Keyless endpoints are fine: there's nothing to keep.
  nlohmann::json keyless = body;
  keyless.erase("api_key");
  CHECK(h.add_agent("dun", keyless, k).value("ok", false));

  // A wallet's credentials are sealed; another key can't open or reset-by-accident them silently.
  const std::string w = "0x" + std::string(64, 'a');
  REQUIRE(h.set_credential(w, "claude", "api_key", "sk-ant-api03-WALLETSECRET", k).value("ok", false));
  CHECK(slurp(opt.keys_path).find("WALLETSECRET") == std::string::npos);
  CHECK(h.keyring(w, k) == w);
  CHECK(h.vault_status(w, k)["state"] == "ok");
  CHECK(h.vault_status(w, other)["state"] == "mismatch");
  CHECK(h.vault_reset(w, other).value("ok", false));
  fs::remove_all(root);
}

TEST_CASE("an agent home keeps only sealed logins between calls") {
  const fs::path root = fresh_dir("scrub"), home = root / "home", outside = root / "outside";
  for (auto d : {".codex/sessions/2026", ".grok/sessions/w", ".grok/memory-v2", ".claude/projects", ".config/x", ".saga"})
    fs::create_directories(home / d);
  fs::create_directories(outside);
  auto put = [](const fs::path& p, const std::string& s) { std::ofstream(p) << s; };
  put(home / ".codex/auth.json.sealed", "SAGA1:x");
  put(home / ".codex/sessions/2026/rollout.jsonl", "the whole conversation");
  put(home / ".grok/auth.json.sealed", "SAGA1:y");
  put(home / ".grok/sessions/w/chat_history.jsonl", "my memories");
  put(home / ".grok/memory-v2/MEMORY.md", "facts");
  put(home / ".claude/projects/t.jsonl", "transcript");
  put(home / ".claude.json", "{\"oauthAccount\":{}}");
  put(home / ".saga/codex-usage.json", "{}");
  put(home / ".saga/ctx-live.md", "a call running now");
  put(outside / "keep.txt", "host file");
  fs::create_directory_symlink(outside, home / ".grok/link");
  fs::create_symlink(outside / "keep.txt", home / ".codex/auth.json.sealed.bak");

  sandbox::scrub_home(home.string());

  std::vector<std::string> left;
  for (auto& e : fs::recursive_directory_iterator(home)) left.push_back(fs::relative(e.path(), home).string());
  std::sort(left.begin(), left.end());
  CHECK(left == std::vector<std::string>{".codex", ".codex/auth.json.sealed", ".grok", ".grok/auth.json.sealed", ".saga",
                                         ".saga/codex-usage.json", ".saga/ctx-live.md"});
  CHECK(slurp(outside / "keep.txt") == "host file");  // links were removed, not followed
  fs::remove_all(root);
}

TEST_CASE("the last call out seals the login and clears what the CLI wrote") {
  const fs::path root = fresh_dir("lease"), home = root / "home";
  fs::create_directories(home / ".codex/sessions");
  const secrets::Key k(32, 9);
  sandbox::Sandbox sb{home.string(), (root / "work").string(), {}, k};
  {
    sandbox::Lease lease(&sb);
    std::ofstream(home / ".codex/auth.json") << R"({"tokens":"refresh-me"})";  // a sign-in during the call
    std::ofstream(home / ".codex/sessions/r.jsonl") << "conversation";
    sandbox::Lease second(&sb);  // a concurrent call in the same home
  }
  CHECK_FALSE(fs::exists(home / ".codex/auth.json"));
  CHECK(fs::exists(home / ".codex/auth.json.sealed"));
  CHECK(slurp(home / ".codex/auth.json.sealed").find("refresh-me") == std::string::npos);
  CHECK_FALSE(fs::exists(home / ".codex/sessions"));
  { sandbox::Lease again(&sb); CHECK(slurp(home / ".codex/auth.json") == R"({"tokens":"refresh-me"})"); }
  fs::remove_all(root);
}

TEST_CASE("the keys file holds ciphertext, not hints of it") {
  const fs::path root = fresh_dir("nohints");
  auto reg = agents::Registry::load((root / "missing.json").string());
  memwal::Store store(nullptr, false);
  harness::Options opt;
  opt.keys_path = (root / "keys.json").string();
  opt.workspaces_dir = (root / "ws").string();
  opt.homes_dir = (root / "homes").string();
  opt.user_accounts = true;
  harness::Harness h(reg, store, opt);
  const std::string w = "0x" + std::string(64, 'c');
  const secrets::Key k(32, 4);
  REQUIRE(h.set_credential(w, "claude", "api_key", "sk-ant-api03-SECRETWXYZ", k).value("ok", false));
  const nlohmann::json body = {{"name", "qwen"}, {"base_url", "https://example.com/v1"}, {"model", "m"}, {"api_key", "or-key-ABCD"}};
  REQUIRE(h.add_agent(w, body, k).value("ok", false));
  const std::string keys = slurp(opt.keys_path);
  CHECK(keys.find("hint") == std::string::npos);
  CHECK(keys.find("WXYZ") == std::string::npos);
  CHECK(keys.find("ABCD") == std::string::npos);
  for (auto& a : h.agents_view(w, k))  // shown to the owner, from the opened key
    if (a["name"] == "qwen") CHECK(a["account"]["detail"] == "own API key ··ABCD");
  fs::remove_all(root);
}

TEST_CASE("an owned agent is public-only even when the caller asked otherwise") {
  auto reg = agents::Registry::load("/nonexistent/saga.json");
  REQUIRE(reg.primary() != nullptr);
  CHECK_FALSE(reg.primary()->spec().public_only);

  agents::Spec s;
  s.name = "localmodel";
  s.kind = "openai";
  s.owner = "alice";
  s.base_url = "https://127.0.0.1:9";
  s.api_key = "test-key";
  s.public_only = false;
  REQUIRE(reg.add(s).empty());
  agents::Agent* mine = reg.find("localmodel", "alice");
  REQUIRE(mine != nullptr);
  CHECK(mine->spec().public_only);

  agents::Task task;
  task.prompt = "hi";
  task.timeout_s = 5;
  const auto refused = mine->run(task, nullptr);
  CHECK(refused.error.find("not a public address") != std::string::npos);

  const auto open = http::request("GET", "http://127.0.0.1:9/", {}, "", 3, nullptr, false);
  CHECK(open.error.find("not a public address") == std::string::npos);
}

TEST_CASE("an oversized feedback comment is rejected before the turn is looked up") {
  auto reg = agents::Registry::load("/nonexistent/saga.json");
  memwal::Store store(nullptr, false);
  harness::Harness h(reg, store, {});
  const auto r = h.feedback("alice", "no-such-turn", 1, std::string(5000, 'a'));
  CHECK(r.value("error", "").find("4096") != std::string::npos);
  CHECK(r.value("error", "").find("unknown turn") == std::string::npos);
}

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <httplib.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <thread>

#include "harness/harness.h"
#include "memwal/gate.h"

using namespace saga;
using nlohmann::json;

namespace {
// Signed requests, the async store and real harness run against this fixture. A memory becomes
// searchable only after its job is confirmed, so local sharing cannot accidentally pass via recall.
class Relayer {
 public:
  Relayer() {
    root = std::filesystem::temp_directory_path() / ("saga-shared-" + crypto::uuid4());
    std::filesystem::create_directories(root);
    server.Get("/config", [](const auto&, auto& res) {
      res.set_content(R"({"packageId":"0x2","network":"mainnet"})", "application/json");
    });
    server.Get("/api/whoami", [](const auto&, auto& res) {
      res.set_content(R"({"owner":"0x1"})", "application/json");
    });
    server.Get("/v1/owners/0x1/namespaces", [&](const auto&, auto& res) {
      std::lock_guard lk(mu);
      json spaces = json::array();
      for (const auto& [ns, _] : records) spaces.push_back(ns);
      res.set_content(json{{"namespaces", spaces}}.dump(), "application/json");
    });
    server.Post("/api/recall", [&](const auto& req, auto& res) {
      const auto body = json::parse(req.body);
      const auto ns = body.at("namespace").template get<std::string>();
      std::lock_guard lk(mu);
      reads.push_back(ns);
      if (fail_reads) { res.status = 400; return; }
      json hits = json::array();
      if (auto it = records.find(ns); it != records.end())
        for (const auto& m : it->second) {
          if (hits.size() == body.value("limit", 10U)) break;
          hits.push_back(m);
        }
      res.set_content(json{{"results", hits}}.dump(), "application/json");
    });
    auto accept = [&](const json& item) {
      const std::string id = "job-" + std::to_string(++writes);
      jobs[id] = item;
      return id;
    };
    server.Post("/api/remember", [&, accept](const auto& req, auto& res) {
      std::lock_guard lk(mu);
      if (fail_writes) { res.status = 400; return; }
      res.set_content(json{{"job_id", accept(json::parse(req.body))}}.dump(), "application/json");
    });
    server.Post("/api/remember/bulk", [&, accept](const auto& req, auto& res) {
      std::lock_guard lk(mu);
      if (fail_writes) { res.status = 400; return; }
      json ids = json::array();
      const auto body = json::parse(req.body);
      for (const auto& item : body.at("items")) ids.push_back(accept(item));
      res.set_content(json{{"job_ids", ids}}.dump(), "application/json");
    });
    server.Post("/api/remember/bulk/status", [&](const auto& req, auto& res) {
      std::lock_guard lk(mu);
      json results = json::array();
      const auto body = json::parse(req.body);
      for (const auto& id : body.at("job_ids")) {
        const auto key = id.template get<std::string>();
        const auto& item = jobs.at(key);
        if (!confirmed.contains(key)) {
          records[item.at("namespace").template get<std::string>()].push_back(
              {{"blob_id", "blob-" + key}, {"text", item.at("text")}, {"distance", 0.1}});
          confirmed.insert(key);
        }
        results.push_back({{"job_id", id}, {"status", "done"}, {"blob_id", "blob-" + key}});
      }
      res.set_content(json{{"results", results}}.dump(), "application/json");
    });
    server.Post("/api/analyze", [&](const auto&, auto& res) {
      std::lock_guard lk(mu); ++analyzes;
      res.set_content(R"({"facts":[]})", "application/json");
    });
    server.Post("/v1/chat/completions", [&](const auto& req, auto& res) {
      const auto body = json::parse(req.body);
      std::string answer;
      {
        std::lock_guard lk(mu);
        contexts.push_back(body.at("messages")[0].at("content").template get<std::string>());
        answer = replies[body.at("model").template get<std::string>()];
      }
      const auto event = json{{"choices", {{{"delta", {{"content", answer}}}}}}};
      res.set_content("data: " + event.dump() + "\n\ndata: [DONE]\n\n", "text/event-stream");
    });
    const int port = server.bind_to_any_port("127.0.0.1");
    if (port <= 0) throw std::runtime_error("cannot bind shared-memory fixture");
    config.private_key = crypto::Ed25519Key::generate().sui_private_key();
    config.account_id = "0x1";
    config.server_url = "http://127.0.0.1:" + std::to_string(port);
    json agents = json::array();
    for (const auto* name : {"claude", "codex", "grok"})
      agents.push_back({{"name", name}, {"kind", "openai"}, {"model", name}, {"base_url", config.server_url + "/v1"}});
    std::ofstream(root / "saga.json") << json{{"primary", "claude"}, {"agents", agents}};
    worker = std::jthread([&] { server.listen_after_bind(); });
    server.wait_until_ready();
  }
  ~Relayer() { server.stop(); worker.join(); std::filesystem::remove_all(root); }
  agents::Registry registry() { return agents::Registry::load((root / "saga.json").string()); }
  harness::Options options() {
    harness::Options o;
    o.workspaces_dir = (root / "workspaces").string();
    o.keys_path = (root / "keys.json").string();
    return o;
  }
  void reply(const std::string& agent, const std::string& answer) { std::lock_guard lk(mu); replies[agent] = answer; }
  void add(const std::string& ns, const std::string& text) {
    std::lock_guard lk(mu);
    records[ns].push_back({{"blob_id", "legacy-blob"}, {"text", text}, {"distance", 0.1}});
  }
  std::vector<std::string> prompts() { std::lock_guard lk(mu); return contexts; }
  std::vector<std::string> searches() { std::lock_guard lk(mu); return reads; }
  int analysis_calls() { std::lock_guard lk(mu); return analyzes; }
  int fact_writes() {
    std::lock_guard lk(mu); int count = 0;
    for (const auto& [_, item] : jobs)
      if (auto r = memwal::decode_record(item.at("text").get<std::string>(), "memory");
          r && r->value("kind", "") == "fact") ++count;
    return count;
  }
  void fail(bool reads_fail, bool writes_fail) { std::lock_guard lk(mu); fail_reads = reads_fail; fail_writes = writes_fail; }
  memwal::Config config;
  std::filesystem::path root;

 private:
  std::mutex mu;
  httplib::Server server;
  std::jthread worker;
  std::map<std::string, std::vector<json>> records;
  std::map<std::string, json> jobs;
  std::set<std::string> confirmed;
  std::map<std::string, std::string> replies;
  std::vector<std::string> contexts, reads;
  int writes = 0, analyzes = 0;
  bool fail_reads = false, fail_writes = false;
};
}  // namespace

TEST_CASE("Claude's queued decision reaches Codex and a restarted Grok through one shared scope") {
  Relayer r;
  const std::string fact = "Saga's menu API uses PostgreSQL.";
  r.reply("claude", std::string(1800, 'x') + "\n#remember " + fact);
  r.reply("codex", "Reviewed the decision.\n#remember " + fact);
  r.reply("grok", "Reviewed the saved decision.");
  {
    memwal::Client client(r.config);
    memwal::Store store(&client, true);
    auto reg = r.registry();
    harness::Harness h(reg, store, r.options());
    h.chat("alice", "menu", "@claude build the menu, then @codex review the menu", nullptr);
    auto prompts = r.prompts();
    REQUIRE(prompts.size() == 2);
    CHECK(prompts[1].find(fact) != std::string::npos);
    CHECK(prompts[1].find("not yet confirmed on Walrus") != std::string::npos);
    CHECK(prompts[1].find("u:alice:shared") != std::string::npos);
    const auto reads = r.searches();
    CHECK(std::count(reads.begin(), reads.end(), "u:alice:shared") == 1);
    CHECK(std::none_of(reads.begin(), reads.end(), [](const auto& ns) { return ns.find(":learning:") != std::string::npos; }));
    CHECK(r.analysis_calls() == 0);
    auto local = store.local_memories("u:alice:shared");
    auto saved = std::find_if(local.begin(), local.end(), [&](const auto& m) { return m.text == fact; });
    REQUIRE(saved != local.end());
    CHECK(saved->agent == "claude");
    CHECK(saved->session == "menu");
    CHECK(saved->blob_id.empty());
    store.flush(std::chrono::seconds(5));
    CHECK(r.fact_writes() == 1);  // both agents proposed the same fact
  }
  memwal::Client restarted_client(r.config);
  memwal::Store restarted_store(&restarted_client, true);
  auto reg = r.registry();
  harness::Harness restarted(reg, restarted_store, r.options());
  json sources = json::array();
  restarted.chat("alice", "review", "@grok review the menu decision", [&](const json& e) {
    if (e.value("type", "") == "recall") sources.push_back(e);
  });
  CHECK(r.prompts().back().find(fact) != std::string::npos);
  bool confirmed = false;
  for (const auto& batch : sources)
    for (const auto& m : batch["items"])
      if (m["text"] == fact) confirmed = !m.value("blob_id", "").empty() && m.value("status", "") == "done";
  CHECK(confirmed);
  restarted.chat("bob", "menu", "@grok review the menu decision", nullptr);
  CHECK(r.prompts().back().find(fact) == std::string::npos);
  restarted_store.flush(std::chrono::seconds(5));
}

TEST_CASE("explicit corrections are shared without calling a reflection model") {
  Relayer r; r.reply("claude", "Done.");
  memwal::Client client(r.config); memwal::Store store(&client, true);
  auto reg = r.registry(); harness::Harness h(reg, store, r.options());
  const auto turn = h.chat("alice", "menu", "Explain the project", nullptr);
  CHECK(h.feedback("bob", turn, -1, "keep it brief").contains("error"));
  const auto feedback = h.feedback("alice", turn, -1, "Explain the project before installation.");
  CHECK(feedback["saved"] == true);
  CHECK(r.prompts().size() == 1);
  CHECK(h.feedback("alice", turn, -1, "again").contains("error"));
  const auto local = store.local_memories("u:alice:shared");
  CHECK(std::any_of(local.begin(), local.end(), [](const auto& m) {
    return m.kind == "correction" && m.text.find("before installation") != std::string::npos;
  }));
  store.flush(std::chrono::seconds(5));
}

TEST_CASE("old lessons from removed agents remain available to every current teammate") {
  Relayer r;
  r.add("u:alice:lessons:retired-agent", "Run migrations before deployment.");
  r.add("u:bob:facts", "Bob's private decision.");
  r.reply("grok", "Done.");
  memwal::Client client(r.config); memwal::Store store(&client, true);
  auto reg = r.registry(); harness::Harness h(reg, store, r.options());
  const auto view = h.memory_view("alice", "deployment");
  REQUIRE(view["items"].size() == 1);
  CHECK(view["items"][0]["namespace"] == "u:alice:lessons:retired-agent");
  CHECK(view["items"][0]["blob_id"] == "legacy-blob");
  h.chat("alice", "deploy", "@grok check deployment", nullptr);
  CHECK(r.prompts().back().find("Run migrations") != std::string::npos);
  CHECK(r.prompts().back().find("Bob's private") == std::string::npos);
  store.flush(std::chrono::seconds(5));
}

TEST_CASE("memory tools share pending records, reject other users and remove failed proposals") {
  Relayer r; memwal::Client client(r.config); memwal::Store store(&client, true);
  const auto proposed = store.remember("alice", "User prefers PostgreSQL.");
  REQUIRE(proposed.value("ok", false));
  CHECK_FALSE(store.remember("alice", "User's password is secret-password").value("ok", true));
  memwal::Gate gate(client, &store, "alice");
  const auto socket_status = std::filesystem::status(gate.path());
  CHECK(socket_status.type() == std::filesystem::file_type::socket);
  CHECK(socket_status.permissions() == (std::filesystem::perms::owner_read | std::filesystem::perms::owner_write));
  CHECK(std::filesystem::status(std::filesystem::path(gate.path()).parent_path()).permissions() ==
        std::filesystem::perms::owner_all);
  const auto hits = memwal::gate_transact(gate.path(), {{"op", "recall"}, {"text", "database"}, {"ns", "u:alice:shared"}});
  REQUIRE(hits["hits"].size() == 1);
  CHECK(hits["hits"][0]["status"] != "done");
  CHECK(hits["hits"][0]["distance"].is_null());
  CHECK_FALSE(memwal::gate_transact(gate.path(), {{"op", "recall"}, {"text", "database"}, {"ns", "u:bob:shared"}}).value("ok", true));
  CHECK_FALSE(memwal::gate_transact(gate.path(), {{"op", "remember"}, {"text", "fact"}, {"ns", "u:alice:shared"}}).value("ok", true));
  memwal::Gate writable(client, &store);
  const auto alias = memwal::gate_transact(writable.path(), {{"op", "remember"},
      {"text", "User prefers PostgreSQL."}, {"ns", "u:alice:facts"}, {"agent", "codex"}});
  CHECK(alias.value("ok", false));
  CHECK(alias["ns"] == "u:alice:shared");
  CHECK(alias["id"] == proposed["id"]);
  CHECK(store.local_memories("u:alice:shared").size() == 1);
  store.flush(std::chrono::seconds(5));
  r.fail(true, true);
  REQUIRE(store.remember("alice", "A proposal whose storage will fail.").value("ok", false));
  store.flush(std::chrono::seconds(5));
  const auto local = store.local_memories("u:alice:shared");
  CHECK(std::none_of(local.begin(), local.end(), [](const auto& m) { return m.text.find("will fail") != std::string::npos; }));
  bool failed = false;
  CHECK_FALSE(store.recall("database", "u:alice:shared", {}, &failed).empty());
  CHECK(failed);
  const auto unavailable = memwal::gate_transact(writable.path(), {{"op", "recall"}, {"text", "database"},
                                                                 {"ns", "u:alice:shared"}});
  CHECK_FALSE(unavailable.value("ok", true));
  CHECK_FALSE(unavailable.value("error", "").empty());
}

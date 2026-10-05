#include <doctest/doctest.h>
#include <httplib.h>

#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <thread>

#include "harness/harness.h"

using namespace saga;
using nlohmann::json;

namespace {
// The real client, store, harness and provider adapter talk only to this local fixture.
class RecallFixture {
 public:
  RecallFixture() {
    root = std::filesystem::temp_directory_path() / ("saga-recall-" + crypto::uuid4());
    std::filesystem::create_directories(root);
    server.Get("/config", [](const auto&, auto& res) {
      res.set_content(R"({"packageId":"0x2"})", "application/json");
    });
    server.Post("/api/recall", [&](const auto& req, auto& res) {
      const auto body = json::parse(req.body);
      const auto ns = body.at("namespace").template get<std::string>();
      std::lock_guard lock(mu);
      if (failed.contains(ns)) { res.status = 400; return; }
      json results = json::array();
      for (const auto& item : records[ns]) {
        if (results.size() >= body.value("limit", 10U)) break;
        results.push_back(item);
      }
      res.set_content(json{{"results", results}}.dump(), "application/json");
    });
    server.Post("/api/analyze", [](const auto&, auto& res) {
      res.set_content(R"({"facts":[],"job_ids":[]})", "application/json");
    });
    server.Post("/api/remember/bulk", [&](const auto& req, auto& res) {
      const auto body = json::parse(req.body);
      std::lock_guard lock(mu);
      json ids = json::array();
      for (const auto& item : body.at("items")) {
        const auto id = "job-" + std::to_string(++writes);
        records[item.at("namespace").template get<std::string>()].push_back(
            {{"blob_id", "blob-" + id}, {"text", item.at("text")}, {"distance", 0.1}});
        ids.push_back(id);
      }
      res.set_content(json{{"job_ids", ids}}.dump(), "application/json");
    });
    server.Post("/api/remember", [&](const auto& req, auto& res) {
      const auto item = json::parse(req.body);
      std::lock_guard lock(mu);
      const auto id = "job-" + std::to_string(++writes);
      records[item.at("namespace").template get<std::string>()].push_back(
          {{"blob_id", "blob-" + id}, {"text", item.at("text")}, {"distance", 0.1}});
      res.set_content(json{{"job_id", id}}.dump(), "application/json");
    });
    server.Post("/api/remember/bulk/status", [](const auto& req, auto& res) {
      json results = json::array();
      const auto body = json::parse(req.body);
      for (const auto& id : body.at("job_ids"))
        results.push_back({{"job_id", id}, {"status", "done"}, {"blob_id", "blob-" + id.template get<std::string>()}});
      res.set_content(json{{"results", results}}.dump(), "application/json");
    });
    server.Post("/v1/chat/completions", [&](const auto& req, auto& res) {
      const auto body = json::parse(req.body);
      {
        std::lock_guard lock(mu);
        contexts.push_back(body.at("messages")[0].at("content").template get<std::string>());
      }
      res.set_content("data: {\"choices\":[{\"delta\":{\"content\":\"A fixture answer.\"}}]}\n\ndata: [DONE]\n\n", "text/event-stream");
    });
    const auto port = server.bind_to_any_port("127.0.0.1");
    if (port <= 0) throw std::runtime_error("cannot bind recall fixture");
    config.private_key = crypto::Ed25519Key::generate().sui_private_key();
    config.account_id = "0x1";
    config.server_url = "http://127.0.0.1:" + std::to_string(port);
    const auto base_url = config.server_url + "/v1";
    std::ofstream(root / "saga.json") << json{
        {"primary", "saga"}, {"brain", "saga"}, {"agents", {
            {{"name", "saga"}, {"kind", "openai"}, {"model", "fixture"}, {"base_url", base_url}},
            {{"name", "codex"}, {"kind", "openai"}, {"model", "fixture"}, {"base_url", base_url}}}}};
    worker = std::jthread([&] { server.listen_after_bind(); });
    server.wait_until_ready();
  }
  ~RecallFixture() {
    server.stop();
    worker.join();
    std::filesystem::remove_all(root);
  }
  void add(const std::string& ns, json item) {
    std::lock_guard lock(mu);
    records[ns].push_back(std::move(item));
  }
  void fail(const std::string& ns) { std::lock_guard lock(mu); failed.insert(ns); }
  std::vector<std::string> prompts() { std::lock_guard lock(mu); return contexts; }
  agents::Registry registry() { return agents::Registry::load((root / "saga.json").string()); }
  harness::Options options() {
    harness::Options opt;
    opt.workspaces_dir = (root / "workspaces").string();
    opt.keys_path = (root / "keys.json").string();
    opt.agent_timeout_s = 5;
    return opt;
  }
  memwal::Config config;
  std::filesystem::path root;

 private:
  std::mutex mu;
  std::map<std::string, std::vector<json>> records;
  std::set<std::string> failed;
  std::vector<std::string> contexts;
  int writes = 0;
  httplib::Server server;
  std::jthread worker;
};
}  // namespace

TEST_CASE("recall sources match selected context and survive a cold transcript reload") {
  RecallFixture f;
  const std::string long_fact = std::string(399, 'a') + "é" + std::string(40, 'z');
  f.add("u:alice:facts", {{"blob_id", "fact-blob"}, {"text", long_fact}, {"distance", 0.21},
                         {"score", 0.83}, {"created_at", "2026-10-01T10:00:00Z"}});
  f.add("u:alice:facts", {{"blob_id", "irrelevant-blob"}, {"text", "An unrelated fact."}, {"distance", 0.9}});
  f.add("u:alice:episodes", {{"blob_id", "episode-blob"}, {"text", "The menu API uses PostgreSQL."}, {"distance", 0.2}});
  f.add("u:alice:skills", {{"blob_id", "skill-blob"}, {"text", "Run migrations before deploying."}, {"distance", 0.15}});
  for (int i = 0; i < 6; ++i)
    f.add("u:alice:lessons:saga", {{"blob_id", "lesson-" + std::to_string(i)},
                                  {"text", "Lesson " + std::to_string(i)}, {"distance", 0.1}});
  for (int i = 0; i < 2; ++i)
    f.add("u:alice:learning:scores", {{"text", memwal::encode_record("credit", {{"id", "lesson:lesson-0"}, {"helpful", false}})}});
  f.add("u:alice:lessons:codex", {{"blob_id", "codex-lesson"}, {"text", "Keep review feedback concise."}, {"distance", 0.1}});

  json emitted = json::array();
  {
    memwal::Client client(f.config);
    memwal::Store store(&client, true);
    auto reg = f.registry();
    harness::Harness h(reg, store, f.options());
    h.chat("alice", "menu", "@saga design the menu, then @codex review the menu", [&](const json& event) {
      if (event.value("type", "") == "recall") {
        auto batch = event;
        batch.erase("type");
        emitted.push_back(batch);
      }
    });
    store.flush(std::chrono::seconds(5));
  }
  REQUIRE(emitted.size() == 5);
  const auto fact = emitted[0]["items"][0];
  REQUIRE(emitted[0]["items"].size() == 1);  // weak matches never enter context or the source record
  CHECK(fact["blob_id"] == "fact-blob");
  CHECK(fact["text"] == std::string(399, 'a') + "…");  // same UTF-8 clipping as the prompt
  CHECK(fact["text_truncated"] == true);
  CHECK(fact["distance"] == 0.21);
  CHECK(fact["score"] == 0.83);
  CHECK(fact["created_at"] == "2026-10-01T10:00:00Z");
  CHECK(emitted[0]["query"] == "@saga design the menu, then @codex review the menu");
  CHECK(emitted[3]["agent"] == "saga");
  CHECK(emitted[3]["step"] == 0);
  CHECK(emitted[3]["query"] == "design the menu");
  REQUIRE(emitted[3]["items"].size() == 4);  // muted lesson removed, then the four-lesson budget
  CHECK(emitted[3]["items"][0]["blob_id"] == "lesson-1");
  CHECK(emitted[4]["agent"] == "codex");
  CHECK(emitted[4]["step"] == 1);
  const auto contexts = f.prompts();
  REQUIRE(contexts.size() == 2);
  CHECK(contexts[0].find(fact["text"].get<std::string>()) != std::string::npos);
  CHECK(contexts[0].find("Lesson 0") == std::string::npos);
  CHECK(contexts[0].find("Lesson 5") == std::string::npos);
  CHECK(contexts[0].find("An unrelated fact.") == std::string::npos);
  CHECK(contexts[1].find("Keep review feedback concise.") != std::string::npos);

  // A fresh client/store/harness recovers the original record even when current recall is unavailable.
  f.fail("u:alice:facts");
  memwal::Client client(f.config);
  memwal::Store store(&client, true);
  auto reg = f.registry();
  harness::Harness restored(reg, store, f.options());
  const auto transcript = restored.chat_transcript("alice", "menu");
  REQUIRE(transcript["turns"].size() == 1);
  CHECK(transcript["turns"][0]["recall_sources"] == emitted);
  CHECK(transcript["turns"][0]["memory_enabled"] == true);
  CHECK(restored.chat_transcript("bob", "menu")["turns"].empty());

  f.add("u:alice:chat", {{"blob_id", "old-chat"}, {"distance", 0.1},
                        {"text", memwal::encode_record("chat", {{"session", "legacy"}, {"ts", 1}, {"user", "old turn"}})}});
  const auto legacy = restored.chat_transcript("alice", "legacy");
  REQUIRE(legacy["turns"].size() == 1);
  CHECK_FALSE(legacy["turns"][0].contains("recall_sources"));  // never invent provenance for old chats
}

TEST_CASE("lesson-only recall follows the step event and reports failed versus empty searches") {
  RecallFixture f;
  bool failed = false;
  SUBCASE("no shared memories") {}
  SUBCASE("facts recall failed") { failed = true; f.fail("u:alice:facts"); }
  f.add("u:alice:lessons:saga", {{"blob_id", "only-lesson"}, {"text", "Keep the explanation brief."}, {"distance", 0.2}});
  memwal::Client client(f.config);
  memwal::Store store(&client, true);
  auto reg = f.registry();
  harness::Harness h(reg, store, f.options());
  json events = json::array();
  h.chat("alice", "lessons", "Explain my project", [&](const json& event) { events.push_back(event); });
  bool saw_step = false, saw_lesson = false;
  for (const auto& event : events) {
    if (event["type"] == "step") saw_step = true;
    if (event["type"] == "recall" && event["ns"] == "u:alice:facts") {
      CHECK(event["status"] == (failed ? "unavailable" : "ok"));
      CHECK(event["items"].empty());
    }
    if (event["type"] == "recall" && event["ns"] == "u:alice:lessons:saga") {
      CHECK(saw_step);
      CHECK(event["items"][0]["blob_id"] == "only-lesson");
      saw_lesson = true;
    }
  }
  CHECK(saw_lesson);
  CHECK(events.back()["type"] == "done");
  store.flush(std::chrono::seconds(5));
  CHECK(h.chat_transcript("alice", "lessons")["turns"][0]["recall_sources"][0]["status"] == (failed ? "unavailable" : "ok"));
}

TEST_CASE("disabled memory emits its state and no fabricated recall sources") {
  RecallFixture f;
  memwal::Store store(nullptr, false);
  auto reg = f.registry();
  harness::Harness h(reg, store, f.options());
  json events = json::array();
  h.chat("alice", "disabled", "Explain my project", [&](const json& event) { events.push_back(event); });
  REQUIRE(events[0]["type"] == "turn");
  CHECK(events[0]["memory_enabled"] == false);
  for (const auto& event : events) CHECK(event["type"] != "recall");
  CHECK(store.recent().empty());
}

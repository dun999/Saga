#include <doctest/doctest.h>
#include <httplib.h>

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <vector>

#include "memwal/store.h"

using namespace saga;
using json = nlohmann::json;

TEST_CASE("the relayer budget counts the relayer's weights and keeps a reserve for users' reads") {
  using memwal::RateBudget;
  CHECK(RateBudget::weight("POST", "/api/recall") == 1);
  CHECK(RateBudget::weight("POST", "/api/remember") == 5);
  CHECK(RateBudget::weight("POST", "/api/remember/bulk") == 10);
  CHECK(RateBudget::weight("POST", "/api/remember/bulk/status") == 1);
  CHECK(RateBudget::weight("POST", "/api/analyze") == 5);
  CHECK(RateBudget::weight("GET", "/v1/owners/0x1/namespaces") == 0);

  RateBudget budget;
  budget.spend(RateBudget::kReserve + 25);  // a busy minute of reads: 45 of 60
  const auto t0 = std::chrono::steady_clock::now();
  // Background work would cut into the reserve, so it waits (and gives up when told to stop).
  CHECK_FALSE(budget.wait_for(1, [&] { return std::chrono::steady_clock::now() - t0 > std::chrono::milliseconds(300); }));
  CHECK(budget.spent() == 45);
  budget.spend(1);  // users' reads are never held back
  CHECK(budget.spent() == 46);

  // A 429 names the real limit and holds background work for its Retry-After.
  budget.denied(R"({"error":"Rate limit exceeded","layer":"delegate_key","limit":"120 weighted-requests/min"})", 1);
  CHECK(budget.limit() == 120);
  const auto t1 = std::chrono::steady_clock::now();
  CHECK(budget.wait_for(10, nullptr));
  CHECK(std::chrono::steady_clock::now() - t1 >= std::chrono::milliseconds(900));
  budget.denied(R"({"layer":"account_sustained","limit":"500 weighted-requests/hour"})", 0);
  CHECK(budget.limit() == 120);
}

namespace {
struct CountingRelayer {
  httplib::Server server;
  std::thread thread;
  std::mutex mu;
  int singles = 0, bulks = 0, bulk_items = 0, polls = 0;
  memwal::Config config;
  CountingRelayer() {
    server.Get("/config", [](const auto&, auto& res) { res.set_content(R"({"packageId":"0x2"})", "application/json"); });
    server.Post("/api/remember", [&](const auto&, auto& res) {
      std::lock_guard lk(mu);
      res.set_content(json{{"job_id", "s" + std::to_string(++singles)}}.dump(), "application/json");
    });
    server.Post("/api/remember/bulk", [&](const auto& req, auto& res) {
      std::lock_guard lk(mu);
      ++bulks;
      json ids = json::array();
      for (size_t i = 0; i < json::parse(req.body).at("items").size(); ++i) ids.push_back("b" + std::to_string(++bulk_items));
      res.set_content(json{{"job_ids", ids}}.dump(), "application/json");
    });
    server.Post("/api/remember/bulk/status", [&](const auto& req, auto& res) {
      std::lock_guard lk(mu);
      ++polls;
      json results = json::array();
      for (auto& id : json::parse(req.body).at("job_ids"))
        results.push_back({{"job_id", id}, {"status", "done"}, {"blob_id", "blob-" + id.template get<std::string>()}});
      res.set_content(json{{"results", results}}.dump(), "application/json");
    });
    const int port = server.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    thread = std::thread([&] { server.listen_after_bind(); });
    server.wait_until_ready();
    config.private_key = "suiprivkey1qz424242424242424242424242424242424242424242424242425mhc86p";
    config.account_id = "0x1";
    config.server_url = "http://127.0.0.1:" + std::to_string(port);
  }
  ~CountingRelayer() {
    server.stop();
    thread.join();
  }
};
}  // namespace

TEST_CASE("a turn's writes go out as one request, and blob ids are asked for on a schedule") {
  CountingRelayer relayer;
  memwal::Client client(relayer.config);
  memwal::Store store(&client, true);
  // Written moments apart, like a step's checkpoint and the turn's episode and transcript.
  store.put("u:alice:checkpoints", "checkpoint", "SAGA:checkpoint {}");
  store.put("u:alice:episodes", "episode", "Episode: the user asked for a plan.");
  store.put("u:alice:chat", "chat", "SAGA:chat {}");
  std::this_thread::sleep_for(std::chrono::seconds(2));
  {
    std::lock_guard lk(relayer.mu);
    CHECK(relayer.bulks == 1);
    CHECK(relayer.bulk_items == 3);
    CHECK(relayer.singles == 0);
    CHECK(relayer.polls == 0);  // Walrus needs ~20 s; asking at once would only spend the budget
  }
  store.put("u:alice:facts", "fact", "User prefers Postgres.");  // a lone write costs half a bulk
  store.flush(std::chrono::seconds(5));  // a waiting caller gets answers promptly
  std::lock_guard lk(relayer.mu);
  CHECK(relayer.singles == 1);
  CHECK(relayer.bulks == 1);
  CHECK(relayer.polls >= 1);
  CHECK(store.blobs_written() == 4);
}

TEST_CASE("waiting in flush asks for blob ids at a pace the relayer budget can afford") {
  // Jobs settle 4 s after submission, like a (fast) Walrus upload.
  httplib::Server server;
  std::mutex mu;
  int polls = 0;
  std::chrono::steady_clock::time_point submitted;
  server.Get("/config", [](const auto&, auto& res) { res.set_content(R"({"packageId":"0x2"})", "application/json"); });
  server.Post("/api/remember", [&](const auto&, auto& res) {
    std::lock_guard lk(mu);
    submitted = std::chrono::steady_clock::now();
    res.set_content(R"({"job_id":"j1"})", "application/json");
  });
  server.Post("/api/remember/bulk/status", [&](const auto&, auto& res) {
    std::lock_guard lk(mu);
    ++polls;
    const bool done = std::chrono::steady_clock::now() - submitted >= std::chrono::seconds(4);
    res.set_content(json{{"results", {{{"job_id", "j1"}, {"status", done ? "done" : "running"}, {"blob_id", done ? "b1" : ""}}}}}.dump(),
                    "application/json");
  });
  const int port = server.bind_to_any_port("127.0.0.1");
  REQUIRE(port > 0);
  std::thread th([&] { server.listen_after_bind(); });
  server.wait_until_ready();
  memwal::Config cfg;
  cfg.private_key = "suiprivkey1qz424242424242424242424242424242424242424242424242425mhc86p";
  cfg.account_id = "0x1";
  cfg.server_url = "http://127.0.0.1:" + std::to_string(port);
  {
    memwal::Client client(cfg);
    memwal::Store store(&client, true);
    store.put("u:alice:facts", "fact", "User prefers Postgres.");
    store.flush(std::chrono::seconds(15));
    CHECK(store.blobs_written() == 1);
    std::lock_guard lk(mu);
    CHECK(polls <= 4);  // one a second would be 5+, and a long flush would exhaust the background budget
  }
  server.stop();
  th.join();
}

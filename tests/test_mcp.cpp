#include <doctest/doctest.h>
#include <httplib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <mutex>
#include <thread>

#include "memwal/gate.h"
#include "memwal/mcp.h"
#include "memwal/store.h"

using namespace saga;
using json = nlohmann::json;

namespace {
// A relayer with one stored fact; records what the store sends to it.
struct McpRelayer {
  httplib::Server server;
  std::thread thread;
  std::mutex mu;
  std::vector<json> remembered;
  memwal::Config config;
  McpRelayer() {
    server.Get("/config", [](const auto&, auto& res) { res.set_content(R"({"packageId":"0x2"})", "application/json"); });
    server.Post("/api/recall", [](const auto& req, auto& res) {
      const auto body = json::parse(req.body);
      json results = json::array();
      if (body.value("namespace", "") == "u:alice:facts")
        results.push_back({{"blob_id", "blob-1"}, {"text", "User deploys to Fly.io"}, {"distance", 0.21}});
      res.set_content(json{{"results", results}}.dump(), "application/json");
    });
    server.Post("/api/remember/bulk", [&](const auto& req, auto& res) {
      std::lock_guard lk(mu);
      json ids = json::array();
      for (auto& item : json::parse(req.body).at("items")) {
        remembered.push_back(item);
        ids.push_back("job-" + std::to_string(remembered.size()));
      }
      res.set_content(json{{"job_ids", ids}}.dump(), "application/json");
    });
    server.Post("/api/remember", [&](const auto& req, auto& res) {
      std::lock_guard lk(mu);
      remembered.push_back(json::parse(req.body));
      res.set_content(json{{"job_id", "job-" + std::to_string(remembered.size())}}.dump(), "application/json");
    });
    server.Post("/api/remember/bulk/status", [](const auto& req, auto& res) {
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
  ~McpRelayer() {
    server.stop();
    thread.join();
  }
};

json rpc(const std::string& method, const json& params = json::object(), int id = 1) {
  return {{"jsonrpc", "2.0"}, {"id", id}, {"method", method}, {"params", params}};
}
std::string text_of(const json& reply) { return reply["result"]["content"][0].value("text", ""); }
}  // namespace

TEST_CASE("saga mcp serves Walrus memory as tools through the memory socket") {
  McpRelayer relayer;
  memwal::Client client(relayer.config);
  memwal::Store store(&client, true);
  memwal::Gate gate(client, &store);
  auto reply = [&](const json& req) { return memwal::mcp_reply(req.dump(), "alice", gate.path()); };

  const auto init = reply(rpc("initialize", {{"protocolVersion", "2025-06-18"}}));
  REQUIRE(init);
  CHECK((*init)["result"]["protocolVersion"] == "2025-06-18");
  CHECK((*init)["result"]["capabilities"].contains("tools"));
  CHECK_FALSE(memwal::mcp_reply(R"({"jsonrpc":"2.0","method":"notifications/initialized"})", "alice", gate.path()));
  CHECK_FALSE(memwal::mcp_reply("not json", "alice", gate.path()));

  const auto list = reply(rpc("tools/list"));
  REQUIRE(list);
  REQUIRE((*list)["result"]["tools"].size() == 2);
  CHECK((*list)["result"]["tools"][0]["name"] == "memory_recall");
  CHECK((*list)["result"]["tools"][0]["description"].get<std::string>().find("u:alice:facts") != std::string::npos);

  const auto hit = reply(rpc("tools/call", {{"name", "memory_recall"}, {"arguments", {{"query", "where do I deploy"}}}}));
  REQUIRE(hit);
  CHECK((*hit)["result"]["isError"] == false);
  CHECK(text_of(*hit).find("User deploys to Fly.io") != std::string::npos);
  CHECK(text_of(*hit).find("blob-1") != std::string::npos);

  // A remember is queued through the store (and Saga's write log), not waited on.
  const auto saved = reply(rpc("tools/call", {{"name", "memory_remember"}, {"arguments", {{"text", "User prefers Postgres"}}}}));
  REQUIRE(saved);
  CHECK((*saved)["result"]["isError"] == false);
  CHECK(text_of(*saved).find("Queued") != std::string::npos);
  store.flush(std::chrono::seconds(5));
  CHECK(store.blobs_written() == 1);
  {
    std::lock_guard lk(relayer.mu);
    REQUIRE(relayer.remembered.size() == 1);
    CHECK(relayer.remembered[0]["namespace"] == "u:alice:facts");
    CHECK(relayer.remembered[0]["text"] == "User prefers Postgres");
  }

  const auto harness_write = reply(rpc("tools/call", {{"name", "memory_remember"},
                                                       {"arguments", {{"text", "x"}, {"namespace", "harness:skills"}}}}));
  CHECK((*harness_write)["result"]["isError"] == true);
  const auto unknown = reply(rpc("tools/call", {{"name", "rm_rf"}}));
  CHECK((*unknown)["result"]["isError"] == true);
  CHECK(reply(rpc("no/such/method"))->contains("error"));
  const auto offline = memwal::mcp_reply(rpc("tools/call", {{"name", "memory_recall"}, {"arguments", {{"query", "x"}}}}).dump(), "alice", "");
  CHECK((*offline)["result"]["isError"] == true);
}

TEST_CASE("the memory socket answers a recall while another request is still waiting") {
  McpRelayer relayer;
  memwal::Client client(relayer.config);
  memwal::Gate gate(client);
  // A client that connects and never sends keeps its handler busy for the read timeout.
  const int idle = ::socket(AF_UNIX, SOCK_STREAM, 0);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::snprintf(addr.sun_path, sizeof addr.sun_path, "%s", gate.path().c_str());
  REQUIRE(::connect(idle, reinterpret_cast<sockaddr*>(&addr), sizeof addr) == 0);
  const auto t0 = std::chrono::steady_clock::now();
  const json res = memwal::gate_transact(gate.path(), {{"op", "recall"}, {"ns", "u:alice:facts"}, {"text", "deploy"}});
  CHECK(res.value("ok", false));
  CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(5));
  ::shutdown(idle, SHUT_RDWR);
  ::close(idle);
}

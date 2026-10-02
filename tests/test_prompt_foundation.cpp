#include <doctest/doctest.h>
#include <httplib.h>

#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "harness/prompts.h"

using namespace saga;
using namespace saga::harness;
using nlohmann::json;

namespace {
// Exercise the real signed client, async store, and reload path without live credentials.
class PromptRelayer {
 public:
  PromptRelayer() {
    server_.Get("/config", [](const httplib::Request&, httplib::Response& res) {
      res.set_content(R"({"packageId":"0x2"})", "application/json");
    });
    server_.Post("/api/recall", [&](const httplib::Request& req, httplib::Response& res) {
      const auto body = json::parse(req.body);
      const auto ns = body.at("namespace").get<std::string>();
      std::lock_guard lk(mu_);
      if (ns == failed_namespace_) { res.status = 400; return; }
      json results = json::array();
      for (const auto& text : records_[ns])
        results.push_back({{"text", text}, {"distance", 0.0}});
      res.set_content(json{{"results", results}}.dump(), "application/json");
    });
    server_.Post("/api/remember/bulk", [&](const httplib::Request& req, httplib::Response& res) {
      std::lock_guard lk(mu_);
      json ids = json::array();
      const auto body = json::parse(req.body);
      for (const auto& item : body.at("items")) {
        records_[item.at("namespace").get<std::string>()].push_back(item.at("text").get<std::string>());
        ids.push_back("job-" + std::to_string(++writes_));
      }
      res.set_content(json{{"job_ids", ids}}.dump(), "application/json");
    });
    server_.Post("/api/remember/bulk/status", [](const httplib::Request& req, httplib::Response& res) {
      json results = json::array();
      const auto body = json::parse(req.body);
      for (const auto& id : body.at("job_ids"))
        results.push_back({{"job_id", id}, {"status", "done"}, {"blob_id", "blob-" + id.get<std::string>()}});
      res.set_content(json{{"results", results}}.dump(), "application/json");
    });
    const int port = server_.bind_to_any_port("127.0.0.1");
    if (port <= 0) throw std::runtime_error("cannot bind prompt test relayer");
    config.private_key = "suiprivkey1qz424242424242424242424242424242424242424242424242425mhc86p";
    config.account_id = "0x1";
    config.server_url = "http://127.0.0.1:" + std::to_string(port);
    thread_ = std::jthread([&] { server_.listen_after_bind(); });
    server_.wait_until_ready();
  }
  ~PromptRelayer() { server_.stop(); thread_.join(); }
  void add(const std::string& ns, const std::string& kind, const json& record) {
    std::lock_guard lk(mu_);
    records_[ns].push_back(memwal::encode_record(kind, record));
  }
  void fail(const std::string& ns) { std::lock_guard lk(mu_); failed_namespace_ = ns; }
  int writes() { std::lock_guard lk(mu_); return writes_; }
  memwal::Config config;

 private:
  std::mutex mu_;
  std::map<std::string, std::vector<std::string>> records_;
  std::string failed_namespace_;
  int writes_ = 0;
  httplib::Server server_;
  std::jthread thread_;
};

class LearningBrain : public agents::Agent {
 public:
  LearningBrain() : Agent(agents::Spec{.name = "brain", .kind = "fake"}) {}
  std::string unavailable_reason() const override { return ""; }
  agents::Result run(const agents::Task&, const agents::EventFn&) override { return {}; }
  agents::Result complete(const std::string&, const std::string& prompt, const sandbox::Sandbox*) override {
    if (prompt.find("BASE PROMPT (fixed)") != std::string::npos)
      return {.ok = true, .text = R"({"base":"replace the foundation", "foundation":999,
        "ops":[{"op":"add","text":"Explain the project before installation."}],"why":"user correction"})"};
    if (prompt.find("### Case") != std::string::npos)
      return {.ok = true, .text = R"({"verdicts":["tie"]})"};
    return {.ok = true, .text = "A project explanation."};
  }
};
}  // namespace

TEST_CASE("fresh users persist the embedded Markov foundation and evolve only their own playbook") {
  PromptRelayer relayer;
  memwal::Client client(relayer.config);
  memwal::Store store(&client, true);
  PromptPool alice(store, "u:alice:learning"), bob(store, "u:bob:learning");
  alice.load();
  bob.load();
  CHECK(alice.get(0).foundation == kFoundationRevision);
  CHECK(alice.get(0).prompt == kSeedPrompt);
  CHECK(alice.get(0).base.size() > 1000);  // compiled prompt is present, not an empty embedding

  LearningBrain brain;
  alice.add_critique("Explain what my project does before giving setup commands.");
  const auto result = alice.evolve(brain, {{"Rewrite the README", "User prefers project explanations.", "", "", -1}}, nullptr);
  REQUIRE_FALSE(result.contains("error"));
  const auto learned = alice.get(result.at("version").get<int>());
  CHECK(learned.base == kSeedPrompt);  // a proposer cannot replace the fixed base or its revision
  CHECK(learned.foundation == kFoundationRevision);
  REQUIRE(learned.rules.size() == 1);
  CHECK(learned.prompt.find("Explain the project before installation.") != std::string::npos);
  CHECK(learned.eval.at("judged").get<bool>());
  CHECK(bob.get(0).rules.empty());
  CHECK(bob.summary()["versions"].size() == 1);

  store.flush(std::chrono::seconds(5));
  REQUIRE(store.blobs_written() == 3);
  PromptPool restored(store, "u:alice:learning");
  restored.load();
  CHECK(restored.get(learned.v).base == kSeedPrompt);
  CHECK(restored.get(learned.v).foundation == kFoundationRevision);
  REQUIRE(restored.get(learned.v).rules.size() == 1);
  CHECK(restored.get(learned.v).rules[0].text == learned.rules[0].text);
  CHECK(restored.summary()["versions"].size() == 2);
  CHECK(relayer.writes() == 3);
}

TEST_CASE("foundation migration retains live playbooks and history and is idempotent after storage") {
  PromptRelayer relayer;
  const std::string scope = "u:alice:learning";
  relayer.add(scope + ":prompts", "prompt", {{"v", 0}, {"prompt", "Legacy full prompt."}});
  relayer.add(scope + ":prompts", "prompt", {{"v", 3}, {"parent", 0}, {"base", "Legacy base."},
      {"rules", json::array({{{"id", "b7"}, {"text", "Explain the project first."}}})}});
  relayer.add(scope + ":prompts", "prompt", {{"v", 5}, {"parent", 3}, {"base", "Rejected base."},
      {"status", "rejected"}, {"rules", json::array({{{"id", "b8"}, {"text", "Rejected rule."}}})}});
  relayer.add(scope + ":scores", "score", {{"v", 3}, {"r", 1}});
  relayer.add(scope + ":scores", "credit", {{"id", "b7"}, {"helpful", false}});
  relayer.add(scope + ":scores", "credit", {{"id", "b7"}, {"helpful", false}});
  memwal::Client client(relayer.config);
  memwal::Store store(&client, true);
  PromptPool pool(store, scope);
  pool.load();
  REQUIRE(pool.summary()["versions"].size() == 5);
  CHECK(pool.get(0).base == "Legacy full prompt.");
  CHECK(pool.get(0).status == "superseded");
  CHECK(pool.get(3).status == "superseded");
  CHECK(pool.get(3).wins == 1);
  CHECK(pool.get(5).status == "rejected");
  CHECK(pool.get(6).parent == 0);
  CHECK(pool.get(7).parent == 3);
  CHECK(pool.get(7).base == kSeedPrompt);
  REQUIRE(pool.get(7).rules.size() == 1);
  CHECK(pool.get(7).rules[0].id == "b7");
  CHECK(pool.get(7).rules[0].text == "Explain the project first.");
  CHECK(pool.get(7).wins == 0);  // ratings belong to the old base, not this new candidate
  CHECK(pool.get(7).eval == json{{"kind", "foundation-migration"}});
  CHECK(pool.credit_of("b7").muted());
  for (int i = 0; i < 100; ++i) CHECK(pool.choose().foundation == kFoundationRevision);
  CHECK(pool.best().foundation == kFoundationRevision);

  store.flush(std::chrono::seconds(5));
  REQUIRE(store.blobs_written() == 2);
  PromptPool restored(store, scope);
  restored.load();
  CHECK(restored.summary() == pool.summary());
  CHECK(restored.credit_of("b7").muted());
  store.flush(std::chrono::seconds(5));
  CHECK(relayer.writes() == 2);  // no duplicate migrations on the next process boot
}

TEST_CASE("failed prompt or score recalls never initialize or migrate a user's saved state") {
  for (const auto* suffix : {":prompts", ":scores"}) {
    PromptRelayer relayer;
    relayer.fail(std::string("u:alice:learning") + suffix);
    memwal::Client client(relayer.config);
    memwal::Store store(&client, true);
    PromptPool pool(store, "u:alice:learning");
    CHECK_THROWS_AS(pool.load(), std::runtime_error);
    CHECK(pool.summary()["versions"].empty());
    CHECK(relayer.writes() == 0);
    relayer.fail("");
    pool.load();
    CHECK(pool.get(0).foundation == kFoundationRevision);
  }
}

TEST_CASE("rejected-only history gets a fresh foundation instead of serving a rejected prompt") {
  PromptRelayer relayer;
  relayer.add("u:alice:learning:prompts", "prompt", {{"v", 9}, {"base", "Rejected."}, {"status", "rejected"}});
  memwal::Client client(relayer.config);
  memwal::Store store(&client, true);
  PromptPool pool(store, "u:alice:learning");
  pool.load();
  CHECK(pool.choose().v == 10);
  CHECK(pool.best().base == kSeedPrompt);
  CHECK(pool.get(9).status == "rejected");
}

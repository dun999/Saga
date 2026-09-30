#include <doctest/doctest.h>

#include <thread>

#include <httplib.h>

#include "memwal/client.h"
#include "memwal/redact.h"
#include "memwal/store.h"

using saga::memwal::has_secret;
using saga::memwal::kNotStored;
using saga::memwal::kRedacted;
using saga::memwal::prepare_for_storage;
using saga::memwal::redact_secrets;

TEST_CASE("provider tokens are redacted wherever they appear") {
  for (const char* s : {"use sk-ant-oat01-abcdefghijklmnopqrstuvwxyz0123", "key sk-proj-ABCDEFGHIJKLMNOPQRSTUV123",
                        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwx",
                        "AKIAIOSFODNN7EXAMPLE", "suiprivkey1qz424242424242424242424242424242424242424242424242425mhc86p",
                        "xai-abcdefghijklmnopqrstuvwxyz0123"}) {
    const std::string out = redact_secrets(s);
    CHECK_MESSAGE(out.find("[redacted secret]") != std::string::npos, s);
  }
}

TEST_CASE("labelled secrets keep the label, lose the value") {
  CHECK(redact_secrets("my password is hunter2!!") == "my password is [redacted secret]");
  CHECK(redact_secrets("DB_PASSWORD=s3cr3tValue") == "DB_PASSWORD=[redacted secret]");
  CHECK(redact_secrets("api key: abc123def456") == "api key: [redacted secret]");
  CHECK(redact_secrets("my seed phrase is apple banana cherry dog egg") == "my seed phrase is [redacted secret]");
  CHECK(redact_secrets("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----") == "[redacted secret]");
}

TEST_CASE("a token caught by its format isn't redacted twice by its label") {
  CHECK(redact_secrets("my GitHub token is ghp_TESTsecretABCDEFGHIJKLMNOPQRSTUVWXYZ12 ok") == "my GitHub token is [redacted secret] ok");
}

TEST_CASE("ordinary memories pass through untouched") {
  for (const char* s : {"User writes Rust and likes terse answers",
                        "User forgot their password last week and reset it", "User prefers tokens of appreciation over gifts",
                        "User deploys to Fly.io with a pin of version 2.3"}) {
    CHECK_MESSAGE(!has_secret(s), s);
    CHECK(redact_secrets(s) == s);
  }
}

TEST_CASE("redaction is idempotent and keeps the separator") {
  for (const char* s : {"my seed phrase is abandon abandon abandon", "my password is hunter2!!",
                        "Bearer abcdefghijklmnop"}) {
    const std::string once = redact_secrets(s);
    CHECK(redact_secrets(once) == once);
    CHECK(once.find(std::string("is") + kRedacted) == std::string::npos);
  }
  CHECK(redact_secrets("my password is hunter2!!") == "my password is [redacted secret]");
  CHECK(redact_secrets("my password is [redacted secret]") == "my password is [redacted secret]");
  CHECK(redact_secrets("Bearer abcdefghijklmnop") == "Bearer [redacted secret]");
}

TEST_CASE("unlabelled 64-hex is removed; a typed public id is kept") {
  const std::string hex64(64, 'b');
  const std::string addr = "0x" + std::string(64, 'c');
  CHECK(redact_secrets(hex64) == kRedacted);
  CHECK(redact_secrets("see " + addr + " please") == "see " + std::string(kRedacted) + " please");
  CHECK(redact_secrets("private key: " + hex64) == "private key: [redacted secret]");
  // One nibble off is not a 32-byte value. The old wallet fixture is 65 hex digits.
  const std::string sixty_five =
      "User's wallet is 0x8a3f4c2e9b1d7a6f5e4c3b2a1908f7e6d5c4b3a2918f7e6d5c4b3a2918f7e6d5c";
  CHECK(redact_secrets(sixty_five) == sixty_five);
  CHECK(redact_secrets(std::string(65, 'd')) == std::string(65, 'd'));
  CHECK(redact_secrets("0x" + std::string(63, 'e')) == "0x" + std::string(63, 'e'));
  CHECK(redact_secrets("0x" + std::string(64, 'f') + "Z") == std::string(kRedacted) + "Z");

  const std::string rec = saga::memwal::encode_record(
      "checkpoint", {{"sha256", hex64}, {"uid", addr}, {"content", hex64}, {"sha256_list", {hex64}}});
  const auto j = saga::memwal::decode_record(redact_secrets(rec), "checkpoint");
  REQUIRE(j.has_value());
  CHECK((*j)["sha256"] == hex64);
  CHECK((*j)["uid"] == addr);
  CHECK((*j)["content"] == kRedacted);
  CHECK((*j)["sha256_list"][0] == kRedacted);  // an array element is not the field itself
}

TEST_CASE("long input is scanned without copying a secret back, and oversize is refused") {
  const std::string plain(200000, 'a');
  CHECK(redact_secrets(plain) == plain);
  const std::string token = "sk-ant-" + plain;
  const std::string out = redact_secrets(token);
  CHECK(out == kRedacted);
  CHECK(out.find("aaa") == std::string::npos);

  const auto refused = prepare_for_storage(std::string(300000, 'a') + " sk-ant-abcdefghijklmnopqrstuvwxyz");
  CHECK_FALSE(refused.ok);
  CHECK(refused.text == kNotStored);
  CHECK(refused.text.find("sk-ant-") == std::string::npos);
  CHECK(refused.error.find("256") != std::string::npos);

  std::string deep = "SAGA:note ";
  for (int i = 0; i < 40; ++i) deep += "{\"a\":";
  deep += "\"sk-ant-abcdefghijklmnopqrstuvwxyz012345\"";
  for (int i = 0; i < 40; ++i) deep += "}";
  const auto nested = prepare_for_storage(deep);
  CHECK_FALSE(nested.ok);
  CHECK(nested.text == kNotStored);
  CHECK(nested.text.find("sk-ant-") == std::string::npos);
  CHECK_FALSE(saga::memwal::decode_record(deep, "note").has_value());
}

TEST_CASE("a raw key does not reach a capture-only relayer") {
  httplib::Server svr;
  std::mutex mu;
  std::string body;
  svr.Get("/config", [](const httplib::Request&, httplib::Response& res) {
    res.set_content(R"({"packageId":"0x2"})", "application/json");
  });
  svr.Post("/api/remember", [&](const httplib::Request& req, httplib::Response& res) {
    std::lock_guard lk(mu);
    body = req.body;
    res.set_content(R"({"job_id":"j"})", "application/json");
  });
  const int port = svr.bind_to_any_port("127.0.0.1");
  REQUIRE(port > 0);
  std::thread th([&] { svr.listen_after_bind(); });
  svr.wait_until_ready();

  saga::memwal::Config cfg;
  cfg.private_key = "suiprivkey1qz424242424242424242424242424242424242424242424242425mhc86p";
  cfg.account_id = "0x1";
  cfg.server_url = "http://127.0.0.1:" + std::to_string(port);
  saga::memwal::Client client(cfg);

  const std::string secret = std::string(300000, 'a') + " sk-ant-abcdefghijklmnopqrstuvwxyz";
  CHECK_THROWS_AS(client.remember(secret, "ns"), saga::memwal::Error);
  CHECK(body.empty());

  CHECK(client.remember("my password is hunter2!!", "ns") == "j");
  CHECK(body.find("hunter2") == std::string::npos);
  CHECK(body.find(kRedacted) != std::string::npos);

  body.clear();
  const std::string hex64(64, 'a');
  CHECK(client.remember("seed " + hex64, "ns") == "j");
  CHECK(body.find(hex64) == std::string::npos);

  svr.stop();
  th.join();
}

TEST_CASE("an oversized memory is not queued") {
  httplib::Server svr;
  svr.Get(R"(.*)", [](const httplib::Request&, httplib::Response& res) { res.status = 400; });
  svr.Post(R"(.*)", [](const httplib::Request&, httplib::Response& res) { res.status = 400; });
  const int port = svr.bind_to_any_port("127.0.0.1");
  REQUIRE(port > 0);
  std::thread th([&] { svr.listen_after_bind(); });
  svr.wait_until_ready();

  saga::memwal::Config cfg;
  cfg.private_key = "suiprivkey1qz424242424242424242424242424242424242424242424242425mhc86p";
  cfg.account_id = "0x1";
  cfg.server_url = "http://127.0.0.1:" + std::to_string(port);
  {
    saga::memwal::Client client(cfg);
    saga::memwal::Store store(&client, true);
    store.put("u:alice:facts", "fact", std::string(300000, 'q') + " sk-ant-abcdefghijklmnopqrstuvwxyz");
    const auto huge = store.recent(10);
    REQUIRE_FALSE(huge.empty());
    CHECK(huge.back().status == "failed");
    CHECK(huge.back().text == kNotStored);
    CHECK(huge.back().text.find("sk-ant-") == std::string::npos);
    CHECK(huge.back().error.find("256") != std::string::npos);

    store.put("u:alice:facts", "fact", "my password is hunter2!!");
    bool redacted = false;
    for (auto& r : store.recent(10))
      if (r.text.find("hunter2") == std::string::npos && r.text.find(kRedacted) != std::string::npos) redacted = true;
    CHECK(redacted);
  }  // the worker finishes against a live 400, which is not retried

  svr.stop();
  th.join();
}

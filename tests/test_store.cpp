#include <doctest/doctest.h>
#include <httplib.h>

#include <chrono>
#include <thread>

#include "memwal/store.h"

TEST_CASE("flush waits for a write the worker is still submitting") {
  httplib::Server svr;
  svr.Get("/config", [](const httplib::Request&, httplib::Response& res) {
    res.set_content(R"({"packageId":"0x2"})", "application/json");
  });
  // Slower than flush's poll, so flush looks while the write is neither queued nor logged.
  svr.Post("/api/remember/bulk", [](const httplib::Request&, httplib::Response& res) {
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    res.set_content(R"({"job_ids":["job-1"]})", "application/json");
  });
  svr.Post("/api/remember", [](const httplib::Request&, httplib::Response& res) {
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    res.set_content(R"({"job_id":"job-1"})", "application/json");
  });
  svr.Post("/api/remember/bulk/status", [](const httplib::Request&, httplib::Response& res) {
    res.set_content(R"({"results":[{"job_id":"job-1","status":"done","blob_id":"blob-1"}]})", "application/json");
  });
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
    store.put("u:alice:facts", "fact", "The menu API uses PostgreSQL.");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));  // the worker has taken it off the queue
    store.flush(std::chrono::seconds(5));
    CHECK(store.blobs_written() == 1);
  }
  svr.stop();
  th.join();
}

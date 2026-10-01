#include <doctest/doctest.h>
#include <httplib.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>
#include "core/crypto.h"
#include "core/http.h"
#include "core/proc.h"
#include "core/proxy.h"
#include "core/sandbox.h"
#include "core/secrets.h"
#include "harness/harness.h"
#include "web/event_queue.h"

using namespace saga;
namespace fs = std::filesystem;

TEST_CASE("private learning and critiques do not cross users") {
  auto reg = agents::Registry::load("/nonexistent-saga-test-config");
  memwal::Store store(nullptr, false);
  harness::Harness h(reg, store, {});
  h.boot();
  auto& alice = h.prompts("alice");
  auto& bob = h.prompts("bob");
  alice.add_critique("synthetic private feedback from Alice");
  alice.credit("b1", false); alice.credit("b1", false);
  alice.score(0, -1);
  CHECK(bob.pending_critiques() == 0);
  CHECK_FALSE(bob.credit_of("b1").muted());
  CHECK(bob.summary()["versions"][0]["losses"] == 0);
  CHECK(h.memory_view("bob", "")["prompts"] == bob.summary());
  CHECK(harness::ns_lessons("codex", "alice") != harness::ns_lessons("codex", "bob"));
  CHECK(harness::memory_protocol("alice", "codex", false, "saga").find("u:alice:lessons:codex") != std::string::npos);
}

TEST_CASE("credential cleanup withstands concurrent parent directory replacement") {
  const auto root = fs::temp_directory_path() / ("saga-race-" + crypto::random_hex(4));
  const auto home = root / "home", outside = root / "outside";
  fs::create_directories(home / ".codex"); fs::create_directories(outside);
  { std::ofstream(home / ".codex/auth.json") << "own fixture"; }
  { std::ofstream(outside / "auth.json") << "outside fixture"; }
  fs::create_directory_symlink(outside, home / "flip");
  const std::string a = (home / ".codex").string(), b = (home / "flip").string();
  std::jthread swap([&](std::stop_token stop) {
    while (!stop.stop_requested()) ::syscall(SYS_renameat2, AT_FDCWD, a.c_str(), AT_FDCWD, b.c_str(), 2);
  });
  for (int i = 0; i < 5000; ++i) secrets::erase_file(home.string(), ".codex/auth.json");
  swap.request_stop(); swap.join();
  std::string text; { std::ifstream in(outside / "auth.json"); std::getline(in, text); }
  CHECK(text == "outside fixture");
  fs::remove_all(root);
}

TEST_CASE("private writes reject parent symlinks and credential cleanup leaves hardlink targets alone") {
  const auto root = fs::temp_directory_path() / ("saga-links-" + crypto::random_hex(4));
  const auto home = root / "home", outside = root / "outside";
  fs::create_directories(home); fs::create_directories(outside);
  { std::ofstream(outside / "auth.json") << "outside fixture"; }
  fs::create_directory_symlink(outside, home / ".saga");
  CHECK_THROWS(secrets::write_private_file(home.string(), ".saga/context.md", "private context"));
  CHECK_FALSE(fs::exists(outside / "context.md"));
  fs::create_directories(home / ".codex");
  fs::create_hard_link(outside / "auth.json", home / ".codex/auth.json");
  CHECK_FALSE(secrets::read_private_file(home.string(), ".codex/auth.json").has_value());
  CHECK(secrets::erase_file(home.string(), ".codex/auth.json"));
  std::string text; { std::ifstream in(outside / "auth.json"); std::getline(in, text); }
  CHECK(text == "outside fixture");
  fs::remove_all(root);
}

TEST_CASE("process deadlines and cancellation remain active after output closes") {
  proc::Options options; options.timeout_s = 1;
  const auto start = std::chrono::steady_clock::now();
  const auto result = proc::run({"sh", "-c", "exec 1>&- 2>&-; sleep 5"}, options);
  CHECK(result.timed_out);
  CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(3));
  std::atomic<bool> cancel{false}; options.timeout_s = 10; options.cancel = &cancel;
  std::jthread trigger([&] { std::this_thread::sleep_for(std::chrono::milliseconds(200)); cancel = true; });
  const auto cancelled = proc::run({"sh", "-c", "exec 1>&- 2>&-; sleep 5"}, options);
  CHECK(cancelled.cancelled);
}

TEST_CASE("process output limits bound both capture and unfinished stream lines") {
  proc::Options options; options.max_output_bytes = 1024;
  auto result = proc::run({"sh", "-c", "head -c 65536 /dev/zero"}, options);
  CHECK(result.output_limited);
  CHECK(result.out.size() + result.err.size() <= options.max_output_bytes);
  options.max_output_bytes = 65536; options.max_line_bytes = 1024;
  options.on_stdout_line = [](const std::string&) {};
  result = proc::run({"sh", "-c", "head -c 65536 /dev/zero"}, options);
  CHECK(result.output_limited);
}

TEST_CASE("subprocesses cannot inherit a server private file descriptor") {
  const auto path = fs::temp_directory_path() / ("saga-fd-" + crypto::random_hex(4));
  { std::ofstream(path) << "synthetic server data"; }
  const int fd = ::open(path.c_str(), O_RDONLY);  // deliberately lacks CLOEXEC
  REQUIRE(fd >= 3);
  const auto result = proc::run({"sh", "-c", "test ! -e /proc/self/fd/" + std::to_string(fd)});
  ::close(fd); fs::remove(path);
  CHECK(result.exit_code == 0);
}

TEST_CASE("a slow browser retains a bounded event queue and draining restores capacity") {
  web::EventQueue queue(1024);
  for (int i = 0; i < 4; ++i) REQUIRE(queue.push(std::string(256, 'x')));
  CHECK_FALSE(queue.push("one more event"));
  CHECK(queue.bytes() == 1024);
  CHECK(queue.pop().size() == 256);
  CHECK(queue.push("small event"));
  queue.clear(); CHECK(queue.empty()); CHECK(queue.bytes() == 0);
}

TEST_CASE("remote provider URLs require HTTPS and forbid embedded credentials") {
  for (const char* url : {"http://example.com/v1", "https://", "https://user:pass@example.com/v1",
                          "https://example.com/v1?key=secret", "https://example.com/v1#fragment"})
    CHECK_FALSE(http::is_https_url(url));
  CHECK(http::is_https_url("https://example.com/v1"));
  CHECK(http::is_https_url("https://example.com:8443/v1"));
}

TEST_CASE("network broker only accepts well formed HTTPS CONNECT requests") {
  CHECK(proxy::connect_host("CONNECT api.example.com:443 HTTP/1.1") == "api.example.com");
  CHECK(proxy::connect_host("CONNECT [2606:4700::1111]:443 HTTP/1.1") == "[2606:4700::1111]");
  for (const char* request : {"GET http://example.com/ HTTP/1.1", "CONNECT example.com:80 HTTP/1.1",
       "CONNECT user@example.com:443 HTTP/1.1", "CONNECT example.com:443 HTTP/1.1\r\nInjected: yes",
       "CONNECT example.com:443/path HTTP/1.1", "CONNECT ::1:443 HTTP/1.1"})
    CHECK(proxy::connect_host(request).empty());
  CHECK(http::connect_public("127.0.0.1") == -1);
  CHECK(http::connect_public("[::1]") == -1);
  CHECK(http::connect_public("169.254.169.254") == -1);
}

TEST_CASE("sandbox wraps commands in a network namespace without binding the host root") {
  sandbox::Sandbox sb{"/tmp/home", "/tmp/work", {}, {}};
  const auto command = sandbox::wrap(sb, {"sh", "-c", "true"});
  CHECK(std::find(command.begin(), command.end(), "--unshare-net") != command.end());
  CHECK(std::find(command.begin(), command.end(), "--disable-userns") != command.end());
  for (size_t i = 0; i + 2 < command.size(); ++i)
    CHECK_FALSE((command[i] == "--ro-bind" && command[i + 1] == "/" && command[i + 2] == "/"));
}

TEST_CASE("HTTP response limits stop oversized streaming providers before consumers receive excess") {
  httplib::Server server;
  server.Get("/large", [](const httplib::Request&, httplib::Response& response) {
    response.set_content(std::string(65536, 'x'), "text/plain");
  });
  const int port = server.bind_to_any_port("127.0.0.1"); REQUIRE(port > 0);
  std::thread serving([&] { server.listen_after_bind(); });
  size_t consumed = 0;
  const auto response = http::request("GET", "http://127.0.0.1:" + std::to_string(port) + "/large", {}, "", 5,
      [&](std::string_view chunk) { consumed += chunk.size(); return true; }, false, 1024);
  server.stop(); serving.join();
  CHECK_FALSE(response.ok()); CHECK(response.body.size() <= 1024); CHECK(consumed <= 1024);
  CHECK(response.error.find("byte limit") != std::string::npos);
}

TEST_CASE("HTTP dependency preserves header octets instead of decoding encoded controls") {
  const std::string line = "X-Probe: benign%0D%0Aextra";
  std::string value;
  const bool ok = httplib::detail::parse_header(line.data(), line.data() + line.size(),
    [&](const std::string&, const std::string& v) { value = v; });
  REQUIRE(ok); CHECK(value == "benign%0D%0Aextra");
}

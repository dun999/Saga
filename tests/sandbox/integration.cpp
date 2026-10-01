#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include "core/crypto.h"
#include "core/sandbox.h"

namespace fs = std::filesystem;
using namespace saga;
namespace {
std::string runner, cgroups;
struct Fixture {
  fs::path root = fs::temp_directory_path() / ("saga-isolation-" + crypto::random_hex(4));
  sandbox::Sandbox sb;
  Fixture() {
    fs::create_directories(root / "home");
    fs::create_directories(root / "work");
    sb = {(root / "home").string(), (root / "work").string(), {}, {}, runner};
  }
  ~Fixture() { std::error_code ec; fs::remove_all(root, ec); }
};
struct Fd { int n; ~Fd() { if (n >= 0) ::close(n); } };
std::string read(const fs::path& path) {
  std::ifstream in(path); std::string line; std::getline(in, line); return line;
}
}

TEST_CASE("real sandbox hides host files and sockets and blocks direct internal networking") {
  Fixture f;
  { std::ofstream(f.root / "server-secret") << "synthetic host fixture"; }
  Fd unix_socket{::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)};
  REQUIRE(unix_socket.n >= 0);
  sockaddr_un un{}; un.sun_family = AF_UNIX;
  const std::string socket_path = (f.root / "runtime.sock").string();
  REQUIRE(socket_path.size() < sizeof(un.sun_path));
  std::memcpy(un.sun_path, socket_path.c_str(), socket_path.size() + 1);
  REQUIRE(::bind(unix_socket.n, reinterpret_cast<sockaddr*>(&un), sizeof(un)) == 0);
  Fd host_service{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
  REQUIRE(host_service.n >= 0);
  sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  REQUIRE(::bind(host_service.n, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
  REQUIRE(::listen(host_service.n, 1) == 0);
  socklen_t length = sizeof(address);
  REQUIRE(::getsockname(host_service.n, reinterpret_cast<sockaddr*>(&address), &length) == 0);
  f.sb.env["SAGA_TEST_PROVIDER_TOKEN"] = "synthetic-provider-fixture";
  ::setenv("MEMWAL_PRIVATE_KEY", "synthetic-host-fixture", 1);
  const std::string script =
    "set -eu\n"
    "test ! -e '" + (f.root / "server-secret").string() + "'\n"
    "test ! -e '" + socket_path + "'\n"
    "test ! -e /run/docker.sock\n"
    "test ! -e /run/containerd/containerd.sock\n"
    "test ! -d /sys/fs/cgroup\n"
    "test \"$SAGA_TEST_PROVIDER_TOKEN\" = synthetic-provider-fixture\n"
    "test -z \"${MEMWAL_PRIVATE_KEY-}\"\n"
    "test -n \"$HTTPS_PROXY\"\n"
    "if curl --noproxy '*' -fsS --connect-timeout 2 --max-time 3 http://127.0.0.1:" +
      std::to_string(ntohs(address.sin_port)) + "/; then exit 1; fi\n"
    "if curl -fkSs --connect-timeout 2 --max-time 4 https://127.0.0.1/; then exit 1; fi\n"
    "printf 'isolated\\n'\n";
  proc::Options options; options.timeout_s = 15;
  const auto result = sandbox::run(f.sb, {"sh", "-c", script}, options);
  ::unsetenv("MEMWAL_PRIVATE_KEY");
  INFO(result.err);
  CHECK(result.exit_code == 0);
  CHECK(result.out == "isolated\n");
  CHECK(result.err.find("403") != std::string::npos);
}

TEST_CASE("real sandbox retains HTTPS access through its public address broker") {
  Fixture f;
  proc::Options options; options.timeout_s = 40;
  const auto result = sandbox::run(f.sb,
    {"curl", "-fSs", "--connect-timeout", "10", "--max-time", "30", "-o", "/dev/null",
     "-w", "%{http_code}", "https://github.com/"}, options);
  INFO(result.err);
  CHECK(result.exit_code == 0);
  CHECK(result.out == "200");
  CHECK_FALSE(result.timed_out);
}

TEST_CASE("real sandbox enters enforced resource groups and leaves no descendants") {
  Fixture f;
  proc::Options options; options.timeout_s = 10;
  std::atomic<bool> ready{false};
  options.on_stdout_line = [&](const std::string& line) { if (line == "ready") ready = true; };
  proc::Result result;
  std::jthread child([&] { result = sandbox::run(f.sb, {"sh", "-c", "echo ready; sleep 3"}, options); });
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (!ready && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  CHECK(ready.load());
  size_t active = 0;
  for (const auto& entry : fs::directory_iterator(cgroups)) {
    if (!entry.is_directory()) continue;
    ++active;
    CHECK(read(entry.path() / "memory.max") == "2147483648");
    CHECK(read(entry.path() / "pids.max") == "64");
    CHECK(read(entry.path() / "cpu.max") == "200000 100000");
    CHECK_FALSE(read(entry.path() / "cgroup.procs").empty());
  }
  CHECK(active == 1);
  child.join(); INFO(result.err);
  CHECK(result.exit_code == 0);
  for (const auto& entry : fs::directory_iterator(cgroups)) CHECK_FALSE(entry.is_directory());
}

int main(int argc, char** argv) {
  const char* executable = std::getenv("SAGA_TEST_RUNNER");
  const char* resource_root = std::getenv("SAGA_TEST_CGROUPS");
  if (!executable || !resource_root) {
    std::cerr << "SAGA_TEST_RUNNER and SAGA_TEST_CGROUPS are required; these tests must exercise real isolation.\n";
    return 1;
  }
  runner = fs::canonical(executable).string(); cgroups = resource_root;
  try {
    sandbox::set_cgroup_root(cgroups);
    sandbox::verify(runner);
    const int result = doctest::Context(argc, argv).run();
    if (!fs::remove(cgroups)) return 1;
    return result;
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}

#include <chrono>
#include <csignal>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "agents/registry.h"
#include "core/compat.h"
#include "core/crypto.h"
#include "core/env.h"
#include "core/sandbox.h"
#include "core/proxy.h"
#include "harness/harness.h"
#include "memwal/client.h"
#include "memwal/gate.h"
#include "memwal/mcp.h"
#include "memwal/store.h"
#include "web/server.h"

using namespace saga;
using json = nlohmann::json;

namespace {

struct Args {
  std::string cmd;
  std::vector<std::string> pos;
  std::map<std::string, std::string> flags;
  std::string get(const std::string& k, const std::string& def = "") const {
    auto it = flags.find(k);
    return it == flags.end() ? def : it->second;
  }
  bool has(const std::string& k) const { return flags.contains(k); }
};

Args parse_args(int argc, char** argv) {
  Args a;
  for (int i = 1; i < argc; ++i) {
    std::string s = argv[i];
    if (s.starts_with("--")) {
      const auto eq = s.find('=');
      if (eq != std::string::npos) a.flags[s.substr(2, eq - 2)] = s.substr(eq + 1);
      else if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) a.flags[s.substr(2)] = argv[++i];
      else a.flags[s.substr(2)] = "1";
    } else if (a.cmd.empty()) {
      a.cmd = s;
    } else {
      a.pos.push_back(s);
    }
  }
  return a;
}

memwal::Config memwal_config() {
  memwal::Config c;
  c.private_key = env::get("MEMWAL_PRIVATE_KEY");
  c.account_id = env::get("MEMWAL_ACCOUNT_ID");
  c.server_url = env::get("MEMWAL_SERVER_URL", c.server_url);
  if (c.private_key.empty() || c.account_id.empty())
    throw std::runtime_error("MEMWAL_PRIVATE_KEY and MEMWAL_ACCOUNT_ID must be set (see .env.example)");
  return c;
}

harness::Options harness_options(const Args& a) {
  harness::Options o;
  o.workspaces_dir = a.get("workspaces", o.workspaces_dir);
  o.trace = a.has("trace");
  o.saga_bin = compat::self_exe();
  o.workspaces_dir = std::filesystem::absolute(o.workspaces_dir).string();
  o.keys_path = env::get("HOME", ".") + "/.config/saga/keys.json";
  o.homes_dir = std::filesystem::absolute("agent-homes").string();
  o.github_client_id = env::get("SAGA_GITHUB_CLIENT_ID");
  o.github_client_secret = env::get("SAGA_GITHUB_CLIENT_SECRET");
  return o;
}

// ---- doctor ----------------------------------------------------------------------
int cmd_doctor(const Args& a) {
  memwal::Client mw(memwal_config());
  auto step = [](const char* name, auto&& fn) {
    std::printf("• %-30s", name);
    std::fflush(stdout);
    try {
      std::printf("ok  %s\n", fn().c_str());
      return true;
    } catch (const std::exception& e) {
      std::printf("FAIL  %s\n", e.what());
      return false;
    }
  };
  bool ok = step("relayer /health", [&] {
    auto h = mw.health();
    return h.value("status", "?") + " writes=" + h.value("writes", "?") + " api=" + h.value("apiVersion", "?");
  });
  ok &= step("network", [&] { return mw.server_config().value("network", "?"); });
  ok &= step("delegate key → account", [&] {
    auto w = mw.whoami();
    return "owner " + w.value("owner", "?") + " account " + w.value("account_id", "?");
  });

  auto reg = agents::Registry::load(a.get("config", "saga.json"));
  for (auto* ag : reg.all()) {
    const std::string why = ag->unavailable_reason();
    std::printf("• agent @%-22s%s\n", ag->name().c_str(), why.empty() ? "configured" : ("unavailable: " + why).c_str());
  }
  if (!ok) return 1;

  const std::string probe = "saga doctor probe " + crypto::uuid4().substr(0, 8) + ": the harness is alive";
  std::string blob;
  ok &= step("remember → Walrus blob", [&] {
    auto s = mw.wait(mw.remember(probe, "saga:doctor"));
    if (!s.done()) throw std::runtime_error("job " + s.status + " " + s.error);
    blob = s.blob_id;
    return blob;
  });
  ok &= step("recall (SEAL decrypt)", [&] {
    auto hits = mw.recall(probe, "saga:doctor", {.limit = 3});
    if (hits.empty()) throw std::runtime_error("no results");
    return "distance " + std::to_string(hits[0].distance) + " \"" + hits[0].text.substr(0, 44) + "\"";
  });
  if (!blob.empty()) std::printf("\n  https://walruscan.com/mainnet/blob/%s\n", blob.c_str());
  return ok ? 0 : 1;
}

// ---- stats: evidence for "≥10 blobs written by the agent" --------------------------
int cmd_stats(const Args& a) {
  memwal::Client mw(memwal_config());
  auto reg = agents::Registry::load(a.get("config", "saga.json"));
  std::vector<std::string> nss;
  try {
    for (auto& n : mw.namespaces().value("namespaces", json::array()))
      nss.push_back(n.is_string() ? n.get<std::string>() : n.value("namespace", n.value("name", "")));
  } catch (const std::exception& e) {
    std::fprintf(stderr, "(namespace listing unavailable: %s — using known namespaces)\n", e.what());
  }
  if (nss.empty()) {
    nss = {"harness:prompts", "harness:scores", "harness:skills", "harness:improvements", "saga:doctor"};
    for (auto* ag : reg.all()) nss.push_back("agent:" + ag->name() + ":lessons");
    for (auto& u : a.pos) {
      for (const char* k : {"facts", "episodes", "chat", "checkpoints", "cases", "skills", "improvements",
                            "learning:prompts", "learning:scores"}) nss.push_back(harness::ns_user(u, k));
      for (auto* ag : reg.all()) nss.push_back(harness::ns_lessons(ag->name(), u));
    }
  }
  long total = 0, bytes = 0;
  std::printf("%-40s %8s %10s\n", "namespace", "memories", "bytes");
  for (auto& ns : nss) {
    if (ns.empty()) continue;
    try {
      auto s = mw.stats(ns);
      const long n = s.value("memory_count", 0L), b = s.value("storage_bytes", 0L);
      if (!n) continue;
      total += n;
      bytes += b;
      std::printf("%-40s %8ld %10ld\n", ns.c_str(), n, b);
    } catch (const std::exception& e) {
      std::printf("%-40s  error: %s\n", ns.c_str(), e.what());
    }
  }
  std::printf("%-40s %8ld %10ld\n", "TOTAL", total, bytes);
  std::printf("\naccount %s  (view blobs: https://walruscan.com/mainnet/account/%s)\n", mw.account_id().c_str(),
              mw.whoami().value("owner", "").c_str());
  return 0;
}

int cmd_restore(const Args& a) {
  memwal::Client mw(memwal_config());
  for (auto& ns : a.pos) {
    auto r = mw.restore(ns, std::stoi(a.get("limit", "50")));
    std::printf("%s: %s\n", ns.c_str(), r.dump().c_str());
  }
  return a.pos.empty() ? 2 : 0;
}

// ---- terminal chat -------------------------------------------------------------------
void print_event(const json& e) {
  const std::string t = e.value("type", "");
  if (t == "recall") {
    const bool failed = e.value("status", "") == "unavailable";
    if (e["items"].empty() && !failed) return;
    std::printf("\033[34m🧠 %s%s\033[0m\n", e["ns"].get<std::string>().c_str(), failed ? " (recall unavailable)" : "");
    for (auto& m : e["items"]) {
      std::printf("\033[34m   · %s\033[0m\n", m.value("text", "").c_str());
      if (const auto id = m.value("blob_id", ""); !id.empty())
        std::printf("\033[2m     blob: %s\033[0m\n", id.c_str());
    }
  } else if (t == "step") {
    std::printf("\n\033[1m@%s\033[0m ← %s\n", e.value("agent", "").c_str(), e.value("instruction", "").c_str());
  } else if (t == "fallback") {
    std::printf("\033[33m   @%s unavailable → @%s\033[0m\n", e.value("from", "").c_str(), e.value("to", "").c_str());
  } else if (t == "agent" && e.value("kind", "") == "tool") {
    std::printf("\033[2m   ▸ %s\033[0m\n", e.value("text", "").c_str());
  } else if (t == "step_done") {
    if (e.value("ok", false)) std::printf("%s\n", e.value("output", "").c_str());
    else std::printf("\033[31m   failed: %s\033[0m\n", e.value("error", "").c_str());
  } else if (t == "log") {
    std::printf("\033[2m%s\033[0m\n", e.value("text", "").c_str());
  }
  std::fflush(stdout);
}

// Host-mode agents call `saga mem` and `saga mcp` through this socket. The delegate key stays in
// `mw`. Declare the store first: the gate's queued writes go through it.
std::unique_ptr<memwal::Gate> open_gate(memwal::Client* mw, memwal::Store& store, harness::Options& o) {
  if (!mw || o.user_accounts) return nullptr;
  auto gate = std::make_unique<memwal::Gate>(*mw, &store);
  o.mem_sock = gate->path();
  return gate;
}

int cmd_chat(const Args& a) {
  std::unique_ptr<memwal::Client> mw;
  if (!a.has("no-memory")) mw = std::make_unique<memwal::Client>(memwal_config());
  harness::Options ho = harness_options(a);
  memwal::Store store(mw.get(), mw != nullptr);
  auto gate = open_gate(mw.get(), store, ho);
  auto reg = agents::Registry::load(a.get("config", "saga.json"));
  harness::Harness h(reg, store, ho);
  h.boot(print_event);
  (void)gate;
  const std::string uid = a.get("user", "cli");
  const std::string session = uid + "-" + crypto::uuid4().substr(0, 6);
  std::printf("saga chat as '%s' (memory %s). /good, /bad <why>, /quit\n", uid.c_str(), mw ? "on" : "off");
  std::string last_turn;
  for (std::string line; std::printf("\n› "), std::fflush(stdout), std::getline(std::cin, line);) {
    if (line.empty()) continue;
    if (line == "/quit") break;
    if (line.starts_with("/good") || line.starts_with("/bad")) {
      const bool good = line.starts_with("/good");
      auto r = h.feedback(uid, last_turn, good ? 1 : -1, line.substr(good ? 5 : 4));
      std::printf("%s\n", r.dump(2).c_str());
      continue;
    }
    last_turn = h.chat(uid, session, line, print_event);
  }
  store.flush(std::chrono::seconds(60));
  return 0;
}

// ---- A/B: the same two-session script with and without Walrus Memory -----------------
int cmd_ab(const Args& a) {
  std::vector<std::string> teach = {
      "Hi! I'm Dana. I'm vegetarian, I live in Lisbon, and I'm training for the Porto half marathon on "
      "November 8th.",
      "Please keep answers short: a bullet list, max 5 bullets, no preamble.",
  };
  std::vector<std::string> probe = {
      "Plan my dinners for the next three days.",
      "What am I training for, and how many weeks do I have left?",
  };
  auto reg = agents::Registry::load(a.get("config", "saga.json"));
  agents::Agent* brain = reg.brain();
  std::string report = "# Saga A/B: without vs with Walrus Memory\n\n"
                       "Session 1 teaches facts; session 2 is a *new process-level session* that only has "
                       "whatever the memory layer can recall.\n\n";
  json scores = json::object();
  for (bool with_memory : {false, true}) {
    std::unique_ptr<memwal::Client> mw;
    if (with_memory) mw = std::make_unique<memwal::Client>(memwal_config());
    harness::Options ho = harness_options(a);
    memwal::Store store(mw.get(), with_memory);
    auto gate = open_gate(mw.get(), store, ho);
    harness::Harness h(reg, store, ho);
    (void)gate;
    h.boot();
    const std::string uid = "ab-" + crypto::uuid4().substr(0, 8);
    const std::string label = with_memory ? "WITH Walrus Memory" : "WITHOUT memory";
    std::fprintf(stderr, "== %s (user %s)\n", label.c_str(), uid.c_str());
    for (auto& m : teach) h.chat(uid, uid + "-s1", m, nullptr);
    store.flush(std::chrono::seconds(180));  // facts must land on Walrus before session 2
    report += "## " + label + "\n\n";
    int total = 0;
    for (auto& m : probe) {
      std::string answer;
      h.chat(uid, uid + "-s2", m, [&](const json& e) {
        if (e.value("type", "") == "done") answer = e.value("final", "");
      });
      auto j = brain->complete(
          "You grade personalization. Ground truth about the user: vegetarian; lives in Lisbon; training for the "
          "Porto half marathon on November 8th; wants short bullet lists (max 5), no preamble. Score 0-10 how "
          "well the answer uses these facts. Reply with JSON only: {\"score\": n, \"why\": \"...\"}",
          "QUESTION: " + m + "\n\nANSWER:\n" + answer);
      int score = 0;
      std::string why;
      if (auto l = j.text.find('{'); j.ok && l != std::string::npos) {
        auto g = json::parse(j.text.substr(l, j.text.rfind('}') - l + 1), nullptr, false);
        if (g.is_object()) score = g.value("score", 0), why = g.value("why", "");
      }
      total += score;
      report += "**Q:** " + m + "\n\n" + answer + "\n\n*judge: " + std::to_string(score) + "/10 — " + why + "*\n\n";
    }
    scores[label] = total;
    store.flush(std::chrono::seconds(60));
  }
  report += "## Scores\n\n";
  for (auto& [k, v] : scores.items()) report += "- " + k + ": **" + std::to_string(v.get<int>()) + "/20**\n";
  const std::string out = a.get("out", "ab_report.md");
  std::ofstream(out) << report;
  std::printf("%s\nwrote %s\n", report.c_str(), out.c_str());
  return 0;
}

// ---- evolve: one playbook evolution now, gated by replay on a user's rated turns ------
int cmd_evolve(const Args& a) {
  if (a.pos.empty()) {
    std::puts("usage: saga evolve \"<critique>\" [\"<critique>\"…] [--user NAME]");
    return 2;
  }
  memwal::Client mw(memwal_config());
  auto reg = agents::Registry::load(a.get("config", "saga.json"));
  harness::Options ho = harness_options(a);
  memwal::Store store(&mw, true);
  auto gate = open_gate(&mw, store, ho);
  harness::Harness h(reg, store, ho);
  h.boot();
  const json r = h.evolve_now(a.get("user", "cli"), a.pos);
  std::printf("%s\n", r.dump(2).c_str());
  store.flush(std::chrono::seconds(90));
  return r.contains("error") ? 1 : 0;
}

// ---- mem: the memory API agents call from their shell ----------------------------------
int cmd_mem(const Args& a) {
  if (a.pos.size() < 2) {
    std::puts("usage: saga mem recall \"<query>\" [--ns NS] [--limit N] [--recent]\n       saga mem remember \"<text>\" [--ns NS]");
    return 2;
  }
  const std::string uid = env::get("SAGA_UID", "cli");
  const std::string ns = a.get("ns", harness::ns_user(uid, "facts"));
  const std::string& op = a.pos[0];
  if (const std::string sock = env::get("SAGA_MEM_SOCK"); !sock.empty()) {
    const json res = memwal::gate_transact(sock, {{"op", op}, {"text", a.pos[1]}, {"ns", ns}, {"limit", std::stoi(a.get("limit", "8"))}});
    if (!res.value("ok", false)) {
      const std::string err = res.value("error", "failed");
      std::fprintf(stderr, "saga mem: %s\n", err.c_str());
      return err.find("harness:") != std::string::npos || (op != "recall" && op != "remember") ? 2 : 1;
    }
    if (op == "recall") {
      auto hits = res.value("hits", json::array());
      if (!hits.is_array() || hits.empty()) std::printf("(no memories in %s match)\n", ns.c_str());
      for (auto& m : hits)
        std::printf("- %s  [distance %.2f, blob %s]\n", m.value("text", "").c_str(), m.value("distance", 0.0),
                    m.value("blob_id", "").c_str());
      return 0;
    }
    if (op == "remember") {
      std::printf("%s %s blob=%s\n", res.value("status", "").c_str(), ns.c_str(), res.value("blob_id", "").c_str());
      return res.value("status", "") == "done" ? 0 : 1;
    }
    std::fprintf(stderr, "saga mem: unknown op %s\n", op.c_str());
    return 2;
  }
  memwal::Client mw(memwal_config());
  if (op == "recall") {
    auto hits = mw.recall(a.pos[1], ns, {.limit = std::stoi(a.get("limit", "8")), .recent = a.has("recent")});
    if (hits.empty()) std::printf("(no memories in %s match)\n", ns.c_str());
    for (auto& m : hits) std::printf("- %s  [distance %.2f, blob %s]\n", m.text.c_str(), m.distance, m.blob_id.c_str());
    return 0;
  }
  if (op == "remember") {
    if (ns.starts_with("harness:")) {
      std::fprintf(stderr, "saga mem: harness:* namespaces are written by the harness only\n");
      return 2;
    }
    auto st = mw.wait(mw.remember(a.pos[1], ns), std::chrono::seconds(90));
    std::printf("%s %s blob=%s\n", st.status.c_str(), ns.c_str(), st.blob_id.c_str());
    return st.done() ? 0 : 1;
  }
  std::fprintf(stderr, "saga mem: unknown op %s\n", op.c_str());
  return 2;
}

// ---- mcp: Walrus memory as native tools for agents (MCP over stdio) -----------------------
int cmd_mcp(const Args&) {
  const std::string uid = env::get("SAGA_UID", "cli"), sock = env::get("SAGA_MEM_SOCK");
  for (std::string line; std::getline(std::cin, line);)
    if (const auto reply = memwal::mcp_reply(line, uid, sock)) std::cout << reply->dump() << "\n" << std::flush;
  return 0;
}

bool loopback_host(const std::string& host) {
  return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]";
}

// "https://saga.example" or "https://saga.example:8443". One trailing slash is dropped.
// A path, query, or userinfo is rejected: this string is the only host baked into challenges.
std::string canonical_origin(std::string s) {
  if (!s.empty() && s.back() == '/') s.pop_back();
  const bool http = s.starts_with("http://");
  const bool https = s.starts_with("https://");
  if (!http && !https) throw std::runtime_error("--public-origin must start with http:// or https://");
  const std::string host = s.substr(https ? 8 : 7);
  if (host.empty() || host.find('/') != std::string::npos || host.find('?') != std::string::npos ||
      host.find('#') != std::string::npos || host.find('@') != std::string::npos ||
      host.find(' ') != std::string::npos)
    throw std::runtime_error("--public-origin must be a scheme and host, with no path or user info");
  return s;
}

int cmd_serve(const Args& a) {
  web::ServerOptions o;
  o.host = a.get("host", o.host);
  const bool local = loopback_host(o.host);

  // Whose provider accounts run the agents: the operator's own logins (local default) or each
  // user's own, sandboxed per user (default when serving other people).
  harness::Options ho = harness_options(a);
  const std::string accounts = a.get("accounts", local ? "host" : "user");
  ho.user_accounts = accounts == "user";
  o.port = std::stoi(a.get("port", std::to_string(o.port)));
  if (a.has("public-origin")) o.public_origin = canonical_origin(a.get("public-origin"));
  o.trust_proxy = a.has("trust-proxy");
  o.secure_cookies = a.has("secure-cookies") || o.public_origin.starts_with("https://");
  // A loopback bind is not a private deployment once a reverse proxy or a public origin is configured.
  const bool exposed = !local || !o.public_origin.empty() || o.trust_proxy;
  o.rate_limit = exposed;
  // Sign in with a Sui wallet or a username. Served to other people, every request needs a signed-in
  // session, so a username comes with a password; on this machine a bare guest username works too.
  // --wallet-only allows wallets only.
  o.auth.passwords = !a.has("wallet-only");
  o.auth.required = (a.has("wallet-only") || exposed) && !a.has("no-auth");
  for (std::stringstream ss(a.get("allow")); ss.good();) {
    std::string addr;
    std::getline(ss, addr, ',');
    if (auto n = web::normalize_address(addr); !n.empty()) o.auth.allowed.insert(n);
  }
  // An allowlist only means something if every request has to prove a wallet: it implies wallet-only.
  if (!o.auth.allowed.empty() && !a.has("no-auth")) {
    o.auth.required = true;
    o.auth.passwords = false;
  }
  if (exposed && (!ho.user_accounts || !o.auth.required || !o.public_origin.starts_with("https://"))) {
    std::fprintf(stderr,
                 "saga: a public bind or a reverse proxy needs --accounts user --public-origin https://… and sign-in "
                 "(no --no-auth) — guest mode is only for this machine, with no public origin and no --trust-proxy.\n");
    return 1;
  }
  if (exposed && a.get("agent-cgroups").empty()) {
    std::fprintf(stderr, "saga: public serving requires --agent-cgroups PATH to an empty delegated cgroup v2 subtree\n");
    return 1;
  }
  sandbox::set_cgroup_root(a.get("agent-cgroups"));
  if (a.has("operator-budget")) {
    ho.operator_daily_runs = std::stoi(a.get("operator-budget"));
    if (ho.operator_daily_runs < 0) throw std::runtime_error("--operator-budget must be 0 or greater");
  }
  if (ho.user_accounts) {
    if (!sandbox::available()) {
      std::fprintf(stderr, "saga: --accounts user runs each user's agents in a bubblewrap sandbox — install bwrap\n");
      return 1;
    }
    std::error_code ec;
    std::filesystem::create_directories(ho.homes_dir, ec);
    std::filesystem::create_directories(ho.workspaces_dir, ec);
    // Nothing of the operator's, Saga's data, or other users may be visible from inside a sandbox.
    sandbox::set_hidden({env::get("HOME"), std::filesystem::current_path().string(), ho.workspaces_dir, ho.homes_dir,
                         std::filesystem::path(ho.keys_path).parent_path().string()});
    sandbox::verify(ho.saga_bin);
  }

  std::unique_ptr<memwal::Client> mw;
  if (!a.has("no-memory")) mw = std::make_unique<memwal::Client>(memwal_config());
  memwal::Store store(mw.get(), mw != nullptr);
  auto gate = open_gate(mw.get(), store, ho);
  auto reg = agents::Registry::load(a.get("config", "saga.json"));
  harness::Harness h(reg, store, ho);
  (void)gate;
  h.boot(print_event);
  return web::serve(h, o);
}

void usage() {
  std::puts(
      "saga — self-improving multi-agent harness with native Walrus Memory\n\n"
      "usage: saga <command> [flags]\n"
      "  serve   [--host H --port P] [--no-memory]  web UI (default http://127.0.0.1:8080)\n"
      "          [--accounts host|user] [--wallet-only] [--allow 0x…,0x…] [--trace]\n"
      "          (served publicly, sign-in is a wallet or a username with a password; --wallet-only: wallets)\n"
      "          [--public-origin URL] [--trust-proxy] [--secure-cookies] [--operator-budget N]\n"
      "          [--agent-cgroups PATH]  delegated cgroup v2 subtree (required for public serving)\n"
      "  chat    [--user NAME] [--no-memory]         terminal chat\n"
      "  doctor                                      check credentials, agents, Walrus round-trip\n"
      "  stats   [user…]                             memories/blobs per namespace\n"
      "  restore <namespace…> [--limit N]            rebuild relayer index from Walrus\n"
      "  ab      [--out FILE]                        before/after memory experiment\n"
      "  evolve  \"critique\"… [--user NAME]          evolve the playbook now, replay-gated\n"
      "  mem     recall|remember \"text\" [--ns NS]    memory API used by agents from their shell\n"
      "  mcp                                         the same memory as MCP tools (stdio), for agents\n\n"
      "common: --config saga.json  --workspaces DIR");
}

}  // namespace

int main(int argc, char** argv) {
  // A browser or agent that hangs up mid-write must cost an EPIPE, never the server.
  std::signal(SIGPIPE, SIG_IGN);
  if (argc > 3 && std::string_view(argv[1]) == "sandbox-exec")
    return proxy::exec(argv[2], std::vector<std::string>(argv + 3, argv + argc));
  env::load_dotenv();
  const Args a = parse_args(argc, argv);
  try {
    if (a.cmd == "doctor") return cmd_doctor(a);
    if (a.cmd == "serve") return cmd_serve(a);
    if (a.cmd == "chat") return cmd_chat(a);
    if (a.cmd == "stats") return cmd_stats(a);
    if (a.cmd == "restore") return cmd_restore(a);
    if (a.cmd == "ab") return cmd_ab(a);
    if (a.cmd == "evolve") return cmd_evolve(a);
    if (a.cmd == "mem") return cmd_mem(a);
    if (a.cmd == "mcp") return cmd_mcp(a);
    usage();
    return a.cmd.empty() || a.cmd == "help" ? 0 : 2;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "saga: %s\n", e.what());
    return 1;
  }
}

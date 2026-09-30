#pragma once
// Request boundary for the HTTP API: body size, cross-site mutations, host checks, and shared caps.
#include <chrono>
#include <map>
#include <mutex>
#include <string>
#include <string_view>

namespace saga::web {

inline constexpr size_t kMaxHttpBody = 256 * 1024;
inline constexpr size_t kMaxFeedback = 4096;
inline constexpr size_t kMaxChatMessage = 20000;

struct Mutation {
  std::string method;
  std::string content_type;
  std::string origin;           // Origin header, may be empty
  std::string fetch_site;       // Sec-Fetch-Site, may be empty
  std::string body;
  std::string csrf_cookie;
  std::string csrf_header;
  std::string expected_origin;  // canonical public origin; empty on a local server
  std::string request_origin;   // scheme://host derived from the request when no public origin is set
};

struct Decision {
  int status = 0;  // 0 = allow
  std::string error;
  bool ok() const { return status == 0; }
};

// JSON mutations must be application/json. Browsers must send a same-origin Fetch metadata / Origin
// pair and a CSRF token that matches the cookie issued with the page. A client that sends neither
// Origin nor Sec-Fetch-Site (curl, the terminal) is allowed: those headers are not attacker-settable
// from a page, and a browser always sends them on a cross-site POST.
Decision check_mutation(const Mutation& m);

bool content_type_json(std::string_view content_type);

// True when `host_header` is the configured public host or the process's own bind host (a reverse
// proxy on loopback often forwards Host as 127.0.0.1). Unexpected hosts are rejected so a request
// cannot choose the name baked into a wallet challenge or an OAuth redirect.
bool host_allowed(std::string_view host_header, std::string_view public_origin, std::string_view bind_host);

// "https://saga.example:8443" → "saga.example:8443". Empty if `origin` is not scheme://host.
std::string origin_host(std::string_view origin);

// Document pages need a CSP the UI can run under (inline styles, Google Fonts, the wallet module).
// Everything else gets a policy that cannot execute script or be framed.
std::string security_csp(std::string_view nonce, bool document);
std::string inject_nonce(std::string html, std::string_view nonce);

// Per-identity and process-wide caps for long-lived requests. One guest can mint many uids, so the
// per-user numbers alone are not a budget.
struct Slots {
  // 0 = taken, 1 = this identity is at its cap, 2 = the process is at its cap.
  int take(const std::string& uid, int per_user, int global_max);
  void give(const std::string& uid);

 private:
  std::mutex mu;
  std::map<std::string, int> used;
  int total = 0;
};

// Fixed one-minute windows. `per_key` applies to each caller key; `global_max` applies to the process.
class RateLimiter {
 public:
  RateLimiter(int per_key, int global_max);
  bool allow(const std::string& key);

 private:
  struct Window {
    int n = 0;
    std::chrono::steady_clock::time_point start{};
  };
  void reopen(Window& w, std::chrono::steady_clock::time_point now);
  std::mutex mu_;
  int per_;
  int global_max_;
  Window global_;
  std::map<std::string, Window> keys_;
};

}  // namespace saga::web

#pragma once
// Thin libcurl wrapper. Thread-safe after global init; idle handles are pooled so connections are reused.
#include <functional>
#include <cstddef>
#include <map>
#include <string>

namespace saga::http {

struct Response {
  long status = 0;
  std::string body;
  std::map<std::string, std::string> headers;  // lower-cased names
  std::string error;                           // transport error, if any
  bool ok() const { return error.empty() && status >= 200 && status < 300; }
};

using Headers = std::map<std::string, std::string>;
// Called with each chunk of body as it arrives; return false to abort.
using ChunkFn = std::function<bool(std::string_view)>;
using CancelFn = std::function<bool()>;

// public_only: refuse to connect to loopback, private, link-local or other non-routable addresses. It
// is checked on each address curl is about to connect to, so DNS tricks can't get around it, and
// redirects aren't followed.
Response request(const std::string& method, const std::string& url, const Headers& headers = {},
                 const std::string& body = "", long timeout_s = 60, const ChunkFn& on_chunk = nullptr,
                 bool public_only = false, size_t max_response_bytes = 8 * 1024 * 1024,
                 const CancelFn& cancelled = nullptr);

// A globally routable unicast IPv4/IPv6 address (text form)?
bool is_public_address(const std::string& ip);
// Remote provider URLs require TLS, a host, and no embedded credentials, query or fragment.
bool is_https_url(const std::string& url);
// Connect a raw TCP tunnel to a public HTTPS peer. DNS and the connected IP are both checked.
// The caller owns the returned nonblocking descriptor; -1 means refused/failed.
int connect_public(const std::string& host, int port = 443);

inline Response get(const std::string& url, const Headers& h = {}, long timeout_s = 30) {
  return request("GET", url, h, "", timeout_s);
}
inline Response post_json(const std::string& url, const std::string& json, Headers h = {},
                          long timeout_s = 60) {
  h.emplace("Content-Type", "application/json");
  return request("POST", url, h, json, timeout_s);
}

}  // namespace saga::http

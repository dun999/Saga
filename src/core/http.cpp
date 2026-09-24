#include "core/http.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace saga::http {
namespace {

struct Ctx {
  Response* resp;
  const ChunkFn* on_chunk;
  std::string blocked;  // the non-public address a public_only request tried to reach
};

// Runs before every connect (redirects and happy-eyeballs attempts included), so a refused address
// is never connected to — not even to learn whether a port is open.
curl_socket_t open_public(void* ud, curlsocktype, curl_sockaddr* a) {
  auto* ctx = static_cast<Ctx*>(ud);
  char ip[INET6_ADDRSTRLEN] = "";
  if (a->family == AF_INET)
    inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(&a->addr)->sin_addr, ip, sizeof ip);
  else if (a->family == AF_INET6)
    inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(&a->addr)->sin6_addr, ip, sizeof ip);
  if (!is_public_address(ip)) {
    ctx->blocked = *ip ? ip : "?";
    return CURL_SOCKET_BAD;
  }
  return ::socket(a->family, a->socktype, a->protocol);
}

bool public_v4(const uint8_t* a) {
  const uint32_t ip = (uint32_t(a[0]) << 24) | (uint32_t(a[1]) << 16) | (uint32_t(a[2]) << 8) | a[3];
  auto in = [&](uint32_t net, int bits) { return (ip >> (32 - bits)) == (net >> (32 - bits)); };
  return !(in(0x00000000, 8) || in(0x0A000000, 8) || in(0x64400000, 10) || in(0x7F000000, 8) ||
           in(0xA9FE0000, 16) || in(0xAC100000, 12) || in(0xC0000000, 24) || in(0xC0A80000, 16) ||
           in(0xC6120000, 15) || in(0xE0000000, 3));  // …, multicast and 240/4 reserved
}

size_t on_body(char* p, size_t sz, size_t n, void* ud) {
  auto* ctx = static_cast<Ctx*>(ud);
  const size_t len = sz * n;
  if (ctx->on_chunk && *ctx->on_chunk) {
    if (!(*ctx->on_chunk)(std::string_view(p, len))) return 0;
  }
  ctx->resp->body.append(p, len);
  return len;
}

size_t on_header(char* p, size_t sz, size_t n, void* ud) {
  auto* resp = static_cast<Response*>(ud);
  std::string line(p, sz * n);
  const auto colon = line.find(':');
  if (colon != std::string::npos) {
    std::string k = line.substr(0, colon), v = line.substr(colon + 1);
    std::transform(k.begin(), k.end(), k.begin(), [](unsigned char c) { return std::tolower(c); });
    v.erase(0, v.find_first_not_of(" \t"));
    while (!v.empty() && (v.back() == '\r' || v.back() == '\n')) v.pop_back();
    resp->headers[k] = v;
  }
  return sz * n;
}

struct GlobalInit {
  GlobalInit() { curl_global_init(CURL_GLOBAL_DEFAULT); }
  ~GlobalInit() { curl_global_cleanup(); }
};

}  // namespace

bool is_public_address(const std::string& ip) {
  uint8_t a[16];
  if (inet_pton(AF_INET, ip.c_str(), a) == 1) return public_v4(a);
  if (inet_pton(AF_INET6, ip.c_str(), a) != 1) return false;
  static const uint8_t kMapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
  static const uint8_t kNat64[12] = {0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0};
  if (std::memcmp(a, kMapped, 12) == 0 || std::memcmp(a, kNat64, 12) == 0) return public_v4(a + 12);
  if (std::all_of(a, a + 15, [](uint8_t b) { return b == 0; })) return false;  // :: and ::1
  if ((a[0] & 0xfe) == 0xfc) return false;                                     // fc00::/7 unique local
  if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return false;                     // fe80::/10 link-local
  if (a[0] == 0xff) return false;                                              // multicast
  return true;
}

Response request(const std::string& method, const std::string& url, const Headers& headers,
                 const std::string& body, long timeout_s, const ChunkFn& on_chunk, bool public_only) {
  static GlobalInit g;
  Response resp;
  CURL* c = curl_easy_init();
  if (!c) {
    resp.error = "curl_easy_init failed";
    return resp;
  }
  Ctx ctx{&resp, &on_chunk, ""};
  curl_slist* hl = nullptr;
  for (const auto& [k, v] : headers) hl = curl_slist_append(hl, (k + ": " + v).c_str());

  curl_easy_setopt(c, CURLOPT_URL, url.c_str());
  curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method.c_str());
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, hl);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, on_body);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &ctx);
  curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, on_header);
  curl_easy_setopt(c, CURLOPT_HEADERDATA, &resp);
  curl_easy_setopt(c, CURLOPT_TIMEOUT, timeout_s);
  curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
  curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, public_only ? 0L : 1L);
  if (public_only) {
    curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(c, CURLOPT_NOPROXY, "*");  // the checked address must be the real peer
    curl_easy_setopt(c, CURLOPT_OPENSOCKETFUNCTION, open_public);
    curl_easy_setopt(c, CURLOPT_OPENSOCKETDATA, &ctx);
  }
  curl_easy_setopt(c, CURLOPT_USERAGENT, "saga/0.1 (+walrus-memory)");
  if (method != "GET") {
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
  }

  const CURLcode rc = curl_easy_perform(c);
  if (rc != CURLE_OK) resp.error = curl_easy_strerror(rc);
  if (!ctx.blocked.empty()) resp.error = "refused: " + ctx.blocked + " is not a public address";
  curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &resp.status);
  curl_slist_free_all(hl);
  curl_easy_cleanup(c);
  return resp;
}

}  // namespace saga::http

#include "core/http.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <mutex>
#include <vector>
#include <unistd.h>
#include <fcntl.h>

namespace saga::http {
namespace {

struct Ctx {
  Response* resp;
  const ChunkFn* on_chunk;
  std::string blocked;  // the non-public address a public_only request tried to reach
  size_t limit, received = 0, header_bytes = 0;
  std::string error;
};

int on_progress(void* data, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
  const auto& cancelled = *static_cast<const CancelFn*>(data);
  try { return cancelled && cancelled() ? 1 : 0; } catch (...) { return 1; }
}

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
  if (len > ctx->limit - std::min(ctx->received, ctx->limit)) {
    ctx->error = "HTTP response exceeded its byte limit";
    return 0;
  }
  ctx->received += len;
  if (ctx->on_chunk && *ctx->on_chunk) {
    try { if (!(*ctx->on_chunk)(std::string_view(p, len))) return 0; }
    catch (...) { ctx->error = "HTTP stream exceeded its limit or was rejected"; return 0; }
  }
  ctx->resp->body.append(p, len);
  return len;
}

size_t on_header(char* p, size_t sz, size_t n, void* ud) {
  auto* ctx = static_cast<Ctx*>(ud);
  auto* resp = ctx->resp;
  if (sz * n > 64 * 1024 - std::min<size_t>(ctx->header_bytes, 64 * 1024)) {
    ctx->error = "HTTP headers exceeded their byte limit";
    return 0;
  }
  ctx->header_bytes += sz * n;
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

// Idle easy handles. A handle keeps its connections, TLS sessions and DNS answers across
// curl_easy_reset, so the next request to the same host skips the TCP and TLS handshakes
// (100-400 ms to the MemWal relayer, against ~25 ms on a warm connection). Each handle serves one
// request at a time: libcurl does not support one connection cache shared by concurrent threads.
class HandlePool {
 public:
  ~HandlePool() {
    for (CURL* c : idle_) curl_easy_cleanup(c);
  }
  CURL* take() {
    {
      std::lock_guard lk(mu_);
      if (!idle_.empty()) {
        CURL* c = idle_.back();
        idle_.pop_back();
        return c;
      }
    }
    return curl_easy_init();
  }
  void give(CURL* c) {
    curl_easy_reset(c);
    {
      std::lock_guard lk(mu_);
      if (idle_.size() < kMaxIdle) {
        idle_.push_back(c);
        return;
      }
    }
    curl_easy_cleanup(c);
  }

 private:
  static constexpr size_t kMaxIdle = 32;
  std::mutex mu_;
  std::vector<CURL*> idle_;
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

bool is_https_url(const std::string& url) {
  if (!url.starts_with("https://")) return false;
  CURLU* u = curl_url();
  if (!u) return false;
  bool ok = curl_url_set(u, CURLUPART_URL, url.c_str(), 0) == CURLUE_OK;
  char* value = nullptr;
  if (ok) {
    ok = curl_url_get(u, CURLUPART_HOST, &value, 0) == CURLUE_OK && value && *value;
    curl_free(value);
  }
  for (auto part : {CURLUPART_USER, CURLUPART_PASSWORD, CURLUPART_QUERY, CURLUPART_FRAGMENT}) {
    value = nullptr;
    if (curl_url_get(u, part, &value, 0) == CURLUE_OK) ok = false;
    curl_free(value);
  }
  curl_url_cleanup(u);
  return ok;
}

int connect_public(const std::string& host, int port) {
  if (port != 443 || host.empty() || host.size() > 255 ||
      host.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:[]") != std::string::npos)
    return -1;
  static GlobalInit g;
  CURL* c = curl_easy_init();
  if (!c) return -1;
  Response response;
  Ctx ctx{&response, nullptr, "", 0};
  const std::string url = "http://" + host + ":" + std::to_string(port);
  curl_easy_setopt(c, CURLOPT_URL, url.c_str());
  curl_easy_setopt(c, CURLOPT_CONNECT_ONLY, 1L);
  curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(c, CURLOPT_NOPROXY, "*");
  curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "http");
  curl_easy_setopt(c, CURLOPT_OPENSOCKETFUNCTION, open_public);
  curl_easy_setopt(c, CURLOPT_OPENSOCKETDATA, &ctx);
  curl_socket_t socket = CURL_SOCKET_BAD;
  if (curl_easy_perform(c) == CURLE_OK) curl_easy_getinfo(c, CURLINFO_ACTIVESOCKET, &socket);
  const int fd = socket == CURL_SOCKET_BAD ? -1 : ::fcntl(socket, F_DUPFD_CLOEXEC, 3);
  curl_easy_cleanup(c);
  return fd;
}

Response request(const std::string& method, const std::string& url, const Headers& headers,
                 const std::string& body, long timeout_s, const ChunkFn& on_chunk, bool public_only,
                 size_t max_response_bytes, const CancelFn& cancelled, long stall_s) {
  static GlobalInit g;
  static HandlePool pool;  // after g, so it is destroyed before curl_global_cleanup
  Response resp;
  // A public_only request never reuses a connection: its peer must pass open_public on this call.
  CURL* c = public_only ? curl_easy_init() : pool.take();
  if (!c) {
    resp.error = "curl_easy_init failed";
    return resp;
  }
  Ctx ctx{&resp, &on_chunk, "", max_response_bytes};
  curl_slist* hl = nullptr;
  for (const auto& [k, v] : headers) hl = curl_slist_append(hl, (k + ": " + v).c_str());

  curl_easy_setopt(c, CURLOPT_URL, url.c_str());
  curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method.c_str());
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, hl);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, on_body);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &ctx);
  curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, on_header);
  curl_easy_setopt(c, CURLOPT_HEADERDATA, &ctx);
  curl_easy_setopt(c, CURLOPT_TIMEOUT, timeout_s);
  curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
  if (stall_s > 0) {  // a peer that sends nothing at all for stall_s seconds has hung
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, stall_s);
  }
  curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
  if (cancelled) {
    curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, on_progress);
    curl_easy_setopt(c, CURLOPT_XFERINFODATA, &cancelled);
  }
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
  if (!ctx.error.empty()) resp.error = ctx.error;
  if (!ctx.blocked.empty()) resp.error = "refused: " + ctx.blocked + " is not a public address";
  curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &resp.status);
  curl_slist_free_all(hl);
  if (public_only) curl_easy_cleanup(c);
  else pool.give(c);
  return resp;
}

}  // namespace saga::http

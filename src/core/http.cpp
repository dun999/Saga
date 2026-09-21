#include "core/http.h"

#include <curl/curl.h>

#include <algorithm>
#include <cctype>

namespace saga::http {
namespace {

struct Ctx {
  Response* resp;
  const ChunkFn* on_chunk;
};

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

Response request(const std::string& method, const std::string& url, const Headers& headers,
                 const std::string& body, long timeout_s, const ChunkFn& on_chunk) {
  static GlobalInit g;
  Response resp;
  CURL* c = curl_easy_init();
  if (!c) {
    resp.error = "curl_easy_init failed";
    return resp;
  }
  Ctx ctx{&resp, &on_chunk};
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
  curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(c, CURLOPT_USERAGENT, "saga/0.1 (+walrus-memory)");
  if (method != "GET") {
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
  }

  const CURLcode rc = curl_easy_perform(c);
  if (rc != CURLE_OK) resp.error = curl_easy_strerror(rc);
  curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &resp.status);
  curl_slist_free_all(hl);
  curl_easy_cleanup(c);
  return resp;
}

}  // namespace saga::http

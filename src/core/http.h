#pragma once
// Thin libcurl wrapper. One easy handle per call; thread-safe after global init.
#include <functional>
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

Response request(const std::string& method, const std::string& url, const Headers& headers = {},
                 const std::string& body = "", long timeout_s = 60, const ChunkFn& on_chunk = nullptr);

inline Response get(const std::string& url, const Headers& h = {}, long timeout_s = 30) {
  return request("GET", url, h, "", timeout_s);
}
inline Response post_json(const std::string& url, const std::string& json, Headers h = {},
                          long timeout_s = 60) {
  h.emplace("Content-Type", "application/json");
  return request("POST", url, h, json, timeout_s);
}

}  // namespace saga::http

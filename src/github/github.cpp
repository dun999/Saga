#include <cctype>
#include "github/github.h"

#include "core/crypto.h"
#include "core/http.h"

namespace saga::github {
namespace {

constexpr const char* kApi = "https://api.github.com";

http::Headers headers(const std::string& token) {
  return {{"Accept", "application/vnd.github+json"},
          {"X-GitHub-Api-Version", "2022-11-28"},
          {"Authorization", "Bearer " + token}};
}

}  // namespace

json api(const std::string& token, const std::string& method, const std::string& path, const json& body) {
  auto h = headers(token);
  if (!body.is_null()) h["Content-Type"] = "application/json";
  auto r = http::request(method, std::string(kApi) + path, h, body.is_null() ? "" : body.dump(), 30);
  auto j = json::parse(r.body.empty() ? "null" : r.body, nullptr, false);
  if (!r.ok()) {
    std::string msg = r.error.empty() ? "GitHub " + std::to_string(r.status) : r.error;
    if (j.is_object() && j.contains("message")) msg += ": " + j.value("message", "");
    if (j.is_object() && j.contains("errors") && j["errors"].is_array() && !j["errors"].empty())
      msg += " (" + j["errors"][0].value("message", j["errors"][0].dump()) + ")";
    throw Error(msg);
  }
  return j;
}

json user(const std::string& token) { return api(token, "GET", "/user"); }

json repos(const std::string& token) {
  json out = json::array();
  for (int page = 1; page <= 3; ++page) {  // up to 300, newest first
    auto list = api(token, "GET",
                    "/user/repos?per_page=100&sort=pushed&affiliation=owner,collaborator,organization_member&page=" +
                        std::to_string(page));
    if (!list.is_array() || list.empty()) break;
    for (auto& r : list) {
      if (!r.value("permissions", json::object()).value("push", false)) continue;
      out.push_back({{"full_name", r.value("full_name", "")},
                     {"private", r.value("private", false)},
                     {"default_branch", r.value("default_branch", "main")},
                     {"description", r.value("description", json()).is_string() ? r["description"] : ""},
                     {"pushed_at", r.value("pushed_at", json()).is_string() ? r["pushed_at"] : ""}});
    }
    if (list.size() < 100) break;
  }
  return out;
}

json find_pr(const std::string& token, const std::string& full_name, const std::string& owner,
             const std::string& branch) {
  auto list = api(token, "GET", "/repos/" + full_name + "/pulls?state=open&head=" + owner + ":" + branch);
  return list.is_array() && !list.empty() ? list[0] : json();
}

json create_pr(const std::string& token, const std::string& full_name, const std::string& head,
               const std::string& base, const std::string& title, const std::string& body) {
  return api(token, "POST", "/repos/" + full_name + "/pulls",
             {{"title", title}, {"head", head}, {"base", base}, {"body", body}});
}

std::map<std::string, std::string> git_env(const std::string& token) {
  // Equivalent to `git -c http.https://github.com/.extraheader=…`, but kept out of argv and .git/config.
  const std::string basic = crypto::b64_encode("x-access-token:" + token);
  return {{"GIT_CONFIG_COUNT", "1"},
          {"GIT_CONFIG_KEY_0", "http.https://github.com/.extraheader"},
          {"GIT_CONFIG_VALUE_0", "AUTHORIZATION: basic " + basic},
          {"GIT_TERMINAL_PROMPT", "0"}};
}

json device_start(const std::string& client_id) {
  auto r = http::post_json("https://github.com/login/device/code",
                           json{{"client_id", client_id}, {"scope", "repo"}}.dump(), {{"Accept", "application/json"}});
  auto j = json::parse(r.body, nullptr, false);
  if (!r.ok() || !j.is_object() || !j.contains("device_code"))
    throw Error("GitHub device sign-in failed: " + (j.is_object() ? j.value("error_description", r.body.substr(0, 160)) : r.body.substr(0, 160)));
  return j;
}

json device_poll(const std::string& client_id, const std::string& device_code) {
  auto r = http::post_json("https://github.com/login/oauth/access_token",
                           json{{"client_id", client_id},
                                {"device_code", device_code},
                                {"grant_type", "urn:ietf:params:oauth:grant-type:device_code"}}
                               .dump(),
                           {{"Accept", "application/json"}});
  auto j = json::parse(r.body, nullptr, false);
  return j.is_object() ? j : json{{"error", "bad_response"}};
}

namespace {
std::string url_escape(const std::string& s) {
  static const char* hex = "0123456789ABCDEF";
  std::string out;
  for (unsigned char c : s) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out += static_cast<char>(c);
    else out += {'%', hex[c >> 4], hex[c & 15]};
  }
  return out;
}
}  // namespace

std::string authorize_url(const std::string& client_id, const std::string& redirect_uri, const std::string& state) {
  return "https://github.com/login/oauth/authorize?client_id=" + url_escape(client_id) + "&redirect_uri=" +
         url_escape(redirect_uri) + "&scope=repo&state=" + url_escape(state) + "&allow_signup=true";
}

json exchange_code(const std::string& client_id, const std::string& client_secret, const std::string& code,
                   const std::string& redirect_uri) {
  auto r = http::post_json("https://github.com/login/oauth/access_token",
                           json{{"client_id", client_id},
                                {"client_secret", client_secret},
                                {"code", code},
                                {"redirect_uri", redirect_uri}}
                               .dump(),
                           {{"Accept", "application/json"}});
  auto j = json::parse(r.body, nullptr, false);
  return j.is_object() ? j : json{{"error", "bad_response"}};
}

}  // namespace saga::github

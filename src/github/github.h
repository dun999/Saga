#pragma once
// Minimal GitHub REST client: who am I, my repos, pull requests, and the OAuth device flow.
// Git itself runs as the `git` CLI (in the user's sandbox when they bring their own accounts);
// the token is handed to git per command through GIT_CONFIG_* env, never written to .git/config.
#include <map>
#include <string>

#include <nlohmann/json.hpp>

namespace saga::github {

using json = nlohmann::json;

struct Error : std::runtime_error {
  using std::runtime_error::runtime_error;
};

json api(const std::string& token, const std::string& method, const std::string& path, const json& body = nullptr);
json user(const std::string& token);               // {login, id, name, …}; throws on a bad token
json repos(const std::string& token);              // repos the token can push to, newest first
json find_pr(const std::string& token, const std::string& full_name, const std::string& owner,
             const std::string& branch);           // open PR for owner:branch, or null
json create_pr(const std::string& token, const std::string& full_name, const std::string& head,
               const std::string& base, const std::string& title, const std::string& body);

// Environment that authenticates git to github.com for one command.
std::map<std::string, std::string> git_env(const std::string& token);

// OAuth device flow (needs an OAuth App client id with device flow enabled).
json device_start(const std::string& client_id);   // {device_code, user_code, verification_uri, interval}
json device_poll(const std::string& client_id, const std::string& device_code);  // {access_token} | {error}

}  // namespace saga::github

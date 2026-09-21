#pragma once
#include <string>

#include "harness/harness.h"
#include "web/auth.h"

namespace saga::web {

struct ServerOptions {
  std::string host = "127.0.0.1";
  int port = 8080;
  std::string access_code;  // if set, required from every browser (public deployments)
  AuthConfig auth;          // Sign-in with Sui (wallet / Google via zkLogin)
};

int serve(harness::Harness& h, const ServerOptions& opt);

}  // namespace saga::web

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
  // Worker threads. A live feed or a streaming chat holds one for as long as it is open, so the
  // per-user caps below keep one user (or a pile of tabs) from starving everyone else.
  int threads = 256;
  int feeds_per_user = 4;
  int chats_per_user = 3;
};

int serve(harness::Harness& h, const ServerOptions& opt);

}  // namespace saga::web

#pragma once
#include <string>

#include "harness/harness.h"
#include "web/auth.h"

namespace saga::web {

struct ServerOptions {
  std::string host = "127.0.0.1";
  int port = 8080;
  AuthConfig auth;          // Sign-in with Sui (wallet / Google via zkLogin)
  // Worker threads. A live feed or a streaming chat holds one for as long as it is open, so the
  // per-user caps below keep one user (or a pile of tabs) from starving everyone else.
  int threads = 256;
  int feeds_per_user = 4;
  int chats_per_user = 3;
  int feeds_global = 64;
  int chats_global = 24;
  // Canonical origin (https://host[:port], no path). Empty means this process is local: guest mode,
  // and the request Host is used for wallet challenges. Set whenever a proxy or public bind is in front.
  std::string public_origin;
  bool trust_proxy = false;     // read X-Forwarded-For only from a loopback peer
  bool secure_cookies = false;  // also implied by an https public origin
  bool rate_limit = false;
  int rate_per_ip = 240;        // per minute, when rate_limit is on
  int rate_global = 2000;
};

int serve(harness::Harness& h, const ServerOptions& opt);

}  // namespace saga::web

#pragma once
// Sign-in with Sui: a Wallet Standard wallet signs a one-time challenge as a Sui personal message;
// the verified address becomes the user's Saga identity. Wallet-side Google accounts (e.g. Slush's
// zkLogin) work too — their signatures verify like any other. Sessions are stateless HMAC-signed
// cookies, so nothing is stored.
#include <chrono>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>

namespace saga::web {

struct AuthConfig {
  bool required = true;
  std::string secret;          // HMAC key for session cookies (random per process if unset)
  std::string graphql_url = "https://graphql.mainnet.sui.io/graphql";
  std::set<std::string> allowed;  // optional address allowlist (lower-case 0x…)
  int session_days = 14;
};

// "0x" + 64 lower-case hex, or "" if not a Sui address.
std::string normalize_address(const std::string& a);

// Result of checking one serialized Sui signature against `address`.
struct Verified {
  bool ok = false;
  std::string scheme;  // ed25519 | secp256k1 | secp256r1 | multisig | zklogin | passkey
  std::string error;
};
// Ed25519 is checked locally; every other scheme (incl. zkLogin) via Sui GraphQL verifySignature.
Verified verify_personal_message(const std::string& message, const std::string& signature_b64,
                                 const std::string& address, const std::string& graphql_url);

class Auth {
 public:
  explicit Auth(AuthConfig cfg);
  const AuthConfig& config() const { return cfg_; }

  // Issues the exact text the wallet must sign for `address`.
  std::string challenge(const std::string& address, const std::string& host);
  // Verifies the signature over the outstanding challenge; returns a session token or error.
  std::string verify(const std::string& address, const std::string& signature_b64, std::string* error);
  // Address for a valid session token, else "".
  std::string session_address(const std::string& token) const;

 private:
  struct Pending {
    std::string message;
    std::chrono::steady_clock::time_point expires;
  };
  AuthConfig cfg_;
  std::mutex mu_;
  std::map<std::string, Pending> pending_;  // address -> challenge (one outstanding per address)
};

}  // namespace saga::web

#pragma once
// Sign-in with Sui: a Wallet Standard wallet signs a one-time challenge as a Sui personal message;
// the verified address becomes the user's Saga identity. Wallet-side Google accounts (e.g. Slush's
// zkLogin) work too. An opaque, short-lived cookie identifies a revocable in-memory session;
// the vault key is held only in that session after a second wallet signature.
#include <chrono>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "core/secrets.h"

namespace saga::web {

struct AuthConfig {
  bool required = true;
  std::string graphql_url = "https://graphql.mainnet.sui.io/graphql";
  std::set<std::string> allowed;  // optional address allowlist (lower-case 0x…)
  int session_ttl_s = 3600;
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
std::string vault_message(const std::string& address);

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
  // The unlock signature is checked against the address in this session before deriving its key.
  bool unlock(const std::string& token, const std::string& signature_b64, std::string* error);
  secrets::Key vault_key(const std::string& token) const;
  // Revoke immediately, clear the resident vault key and return the address for job cancellation.
  std::string logout(const std::string& token);
  // Also drains expirations discovered by request handlers, so no cancellation is lost.
  std::vector<std::string> expired_sessions();

 private:
  struct Pending {
    std::string message;
    std::chrono::steady_clock::time_point expires;
  };
  struct Session {
    std::string address;
    std::chrono::steady_clock::time_point expires;
    secrets::Key vault;
  };
  void prune_locked() const;
  AuthConfig cfg_;
  mutable std::mutex mu_;
  std::map<std::string, Pending> pending_;  // address -> challenge (one outstanding per address)
  mutable std::map<std::string, Session> sessions_;
  mutable std::set<std::string> expired_;
};

}  // namespace saga::web

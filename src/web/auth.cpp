#include "web/auth.h"

#include <algorithm>
#include <cctype>
#include <ctime>

#include <nlohmann/json.hpp>

#include "core/crypto.h"
#include "core/http.h"

namespace saga::web {

using json = nlohmann::json;

std::string normalize_address(const std::string& a) {
  std::string s = a;
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  if (s.starts_with("0x")) s.erase(0, 2);
  if (s.empty() || s.size() > 64 || !std::all_of(s.begin(), s.end(), [](char c) { return std::isxdigit((unsigned char)c); }))
    return "";
  return "0x" + std::string(64 - s.size(), '0') + s;
}

Verified verify_personal_message(const std::string& message, const std::string& signature_b64,
                                 const std::string& address, const std::string& graphql_url) {
  Verified v;
  crypto::Bytes sig;
  try {
    sig = crypto::b64_decode(signature_b64);
  } catch (const std::exception&) {
    v.error = "signature is not base64";
    return v;
  }
  if (sig.empty()) {
    v.error = "empty signature";
    return v;
  }
  static const char* kSchemes[] = {"ed25519", "secp256k1", "secp256r1", "multisig", "bls12381", "zklogin", "passkey"};
  v.scheme = sig[0] < 7 ? kSchemes[sig[0]] : "unknown";

  // Fast path: Ed25519 (flag 0x00 || sig[64] || pubkey[32]) verified here with libsodium.
  if (sig[0] == 0x00 && sig.size() == 97) {
    const crypto::Bytes digest = crypto::sui_personal_message_digest(message);
    if (!crypto::ed25519_verify(sig.data() + 1, digest.data(), digest.size(), sig.data() + 65)) {
      v.error = "bad signature";
      return v;
    }
    crypto::Bytes flag_pk{0x00};
    flag_pk.insert(flag_pk.end(), sig.begin() + 65, sig.end());
    if ("0x" + crypto::to_hex(crypto::blake2b256(flag_pk)) != address) {
      v.error = "signature is from a different address";
      return v;
    }
    v.ok = true;
    return v;
  }

  // Everything else — secp256k1/r1, multisig, passkey and zkLogin (a wallet's Google account) — is checked by
  // a Sui full node, which also validates zkLogin proofs against the current JWKs and epoch.
  const json body = {
      {"query",
       "query($m: Base64!, $s: Base64!, $a: SuiAddress!) { verifySignature(message: $m, signature: $s, "
       "intentScope: PERSONAL_MESSAGE, author: $a) { success } }"},
      {"variables", {{"m", crypto::b64_encode(message)}, {"s", signature_b64}, {"a", address}}}};
  auto r = http::post_json(graphql_url, body.dump(), {}, 20);
  auto j = json::parse(r.body, nullptr, false);
  if (!r.ok() || !j.is_object()) {
    v.error = "could not reach Sui to verify the signature";
    return v;
  }
  const json res = j.contains("data") && j["data"].is_object() ? j["data"].value("verifySignature", json()) : json();
  if (res.is_object() && res.value("success", false)) {
    v.ok = true;
    return v;
  }
  v.error = "signature rejected by Sui";
  if (j.contains("errors") && j["errors"].is_array() && !j["errors"].empty())
    v.error += ": " + j["errors"][0].value("message", "").substr(0, 160);
  return v;
}

Auth::Auth(AuthConfig cfg) : cfg_(std::move(cfg)) {
  if (cfg_.secret.empty()) cfg_.secret = crypto::random_hex(32);  // sessions end when the process does
}

std::string Auth::challenge(const std::string& address, const std::string& host) {
  const std::time_t now = std::time(nullptr);
  char when[32];
  std::tm tm{};
  gmtime_r(&now, &tm);
  std::strftime(when, sizeof when, "%Y-%m-%dT%H:%M:%SZ", &tm);
  const std::string msg = "Sign in to Saga\n\n" + host +
                          " wants you to sign in with your Sui account. Your memory on Walrus is keyed to this "
                          "address. This does not send a transaction or cost gas.\n\nAddress: " +
                          address + "\nNonce: " + crypto::random_hex(16) + "\nIssued at: " + when;
  std::lock_guard lk(mu_);
  const auto now_s = std::chrono::steady_clock::now();
  std::erase_if(pending_, [&](auto& kv) { return kv.second.expires < now_s; });
  pending_[address] = {msg, now_s + std::chrono::minutes(5)};
  return msg;
}

std::string Auth::verify(const std::string& address, const std::string& signature_b64, std::string* error) {
  std::string message;
  {
    std::lock_guard lk(mu_);
    auto it = pending_.find(address);
    if (it == pending_.end() || it->second.expires < std::chrono::steady_clock::now()) {
      if (error) *error = "challenge expired — try again";
      return "";
    }
    message = it->second.message;
    pending_.erase(it);  // single use, even if verification fails
  }
  if (!cfg_.allowed.empty() && !cfg_.allowed.contains(address)) {
    if (error) *error = "this address is not on this Saga's allowlist";
    return "";
  }
  const Verified v = verify_personal_message(message, signature_b64, address, cfg_.graphql_url);
  if (!v.ok) {
    if (error) *error = v.error;
    return "";
  }
  const long expires = std::time(nullptr) + cfg_.session_days * 86400L;
  const std::string payload = "v1." + address + "." + std::to_string(expires);
  return payload + "." + crypto::hmac_sha256_hex(cfg_.secret, payload);
}

std::string Auth::session_address(const std::string& token) const {
  const auto last = token.rfind('.');
  if (last == std::string::npos) return "";
  const std::string payload = token.substr(0, last), mac = token.substr(last + 1);
  if (!crypto::constant_time_equal(mac, crypto::hmac_sha256_hex(cfg_.secret, payload))) return "";
  // payload = v1.<address>.<expires>
  const auto a = payload.find('.'), b = payload.rfind('.');
  if (a == std::string::npos || b == a || payload.substr(0, a) != "v1") return "";
  long expires = 0;
  try {
    expires = std::stol(payload.substr(b + 1));
  } catch (...) {
    return "";
  }
  if (expires < std::time(nullptr)) return "";
  const std::string address = payload.substr(a + 1, b - a - 1);
  if (!cfg_.allowed.empty() && !cfg_.allowed.contains(address)) return "";
  return address;
}

}  // namespace saga::web

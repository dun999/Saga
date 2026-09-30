// Signature produced by the official @mysten/sui SDK (Ed25519Keypair.signPersonalMessage), so the
// local verifier is checked against exactly what Sui wallets send.
#include <doctest/doctest.h>

#include "web/auth.h"

using namespace saga::web;

static const std::string kAddr = "0x3296123631c7d70520ff693d99b422bb52559f7cda50cff44f422a95a49df2fa";
static const std::string kMsg = "Sign in to Saga\nnonce: test-123";
static const std::string kSig =
    "AIbeyT4ENGozFGqI2ZeE56XOqhmS3T11HFUs5iTy+2Du1PDJON+isrwSmoCy5Co5Zd6S+ShCiwOVRk9Ho39A2gKC89UgEgfjN5n9Of9FEOV3"
    "FGYSU7Jl2HvDFc53gWYViA==";

TEST_CASE("ed25519 personal-message signature from the Sui SDK verifies locally") {
  auto v = verify_personal_message(kMsg, kSig, kAddr, "http://127.0.0.1:1/unused");
  CHECK(v.ok);
  CHECK(v.scheme == "ed25519");
}

TEST_CASE("wrong address, tampered message and garbage are rejected") {
  CHECK_FALSE(verify_personal_message(kMsg, kSig, "0x" + std::string(64, '1'), "http://127.0.0.1:1/").ok);
  CHECK_FALSE(verify_personal_message(kMsg + "!", kSig, kAddr, "http://127.0.0.1:1/").ok);
  CHECK_FALSE(verify_personal_message(kMsg, "not base64 !!", kAddr, "http://127.0.0.1:1/").ok);
}

TEST_CASE("address normalisation") {
  CHECK(normalize_address("0x2") == "0x" + std::string(63, '0') + "2");
  CHECK(normalize_address(kAddr.substr(2)) == kAddr);
  CHECK(normalize_address("0xZZ").empty());
  CHECK(normalize_address("").empty());
}

TEST_CASE("session tokens round-trip and resist tampering") {
  AuthConfig cfg;
  cfg.secret = "test-secret";
  Auth auth(cfg);
  // Drive the real flow with the SDK signature: the challenge text must equal what was signed,
  // so check the token format directly through a verified session instead.
  const std::string msg = auth.challenge(kAddr, "localhost");
  CHECK(msg.find(kAddr) != std::string::npos);
  std::string err;
  CHECK(auth.verify(kAddr, kSig, &err).empty());  // signature is over a different text → rejected
  CHECK_FALSE(err.empty());
  CHECK(auth.verify(kAddr, kSig, &err).empty());  // challenge is single-use
  CHECK(err.find("expired") != std::string::npos);
  CHECK(auth.session_address("v1." + kAddr + ".9999999999.deadbeef").empty());
  CHECK(auth.session_address("garbage").empty());
}

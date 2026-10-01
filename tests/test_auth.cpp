// Signature produced by the official @mysten/sui SDK (Ed25519Keypair.signPersonalMessage), so the
// local verifier is checked against exactly what Sui wallets send.
#include <doctest/doctest.h>

#include "core/crypto.h"
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

TEST_CASE("short opaque sessions unlock a vault only with the owning wallet and revoke on logout") {
  AuthConfig cfg;
  Auth auth(cfg);
  const auto wallet = saga::crypto::Ed25519Key::from_seed(saga::crypto::Bytes(32, 7));
  const std::string address = wallet.sui_address();
  const std::string msg = auth.challenge(address, "localhost");
  CHECK(msg.find(address) != std::string::npos);
  std::string err;
  CHECK(auth.verify(address, kSig, &err).empty());  // another wallet's signature is rejected
  CHECK(auth.verify(address, kSig, &err).empty());  // challenge is single-use
  CHECK(err.find("expired") != std::string::npos);
  const std::string challenge = auth.challenge(address, "localhost");
  const std::string token = auth.verify(address, wallet.sign_personal_message(challenge), &err);
  REQUIRE(token.size() == 64);
  CHECK(token.find(address) == std::string::npos);
  CHECK(auth.session_address(token) == address);
  CHECK(auth.vault_key(token).empty());
  CHECK_FALSE(auth.unlock(token, kSig, &err));
  CHECK(auth.vault_key(token).empty());
  REQUIRE(auth.unlock(token, wallet.sign_personal_message(vault_message(address)), &err));
  CHECK(auth.vault_key(token).size() == 32);
  CHECK(auth.logout(token) == address);
  CHECK(auth.session_address(token).empty());
  CHECK(auth.vault_key(token).empty());
  CHECK(auth.session_address("garbage").empty());
}

// Vectors generated from the official MemWal Python SDK (packages/python-sdk-memwal/memwal/utils.py)
// with seed = 0xaa * 32, so the C++ signer is byte-compatible with the relayer.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "core/crypto.h"
#include "memwal/client.h"

using namespace saga::crypto;

static const std::string kSeed(64, 'a');

TEST_CASE("ed25519 key derivation matches Sui SDK") {
  auto k = Ed25519Key::parse(kSeed);
  CHECK(k.pub_hex() == "e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58");
  CHECK(k.sui_address() == "0x3c786461f5d9bb2d02a90718d219bb6a5ce598e4c79e61ff0062c820790ec2f9");
  CHECK(k.sui_private_key() == "suiprivkey1qz424242424242424242424242424242424242424242424242425mhc86p");
}

TEST_CASE("suiprivkey round-trips") {
  auto k = Ed25519Key::parse("suiprivkey1qz424242424242424242424242424242424242424242424242425mhc86p");
  CHECK(to_hex(k.seed.data(), 32) == kSeed);
  CHECK(Ed25519Key::parse("0x" + kSeed).pub_hex() == k.pub_hex());
  CHECK_THROWS(Ed25519Key::parse("suiprivkey1qz424242424242424242424242424242424242424242424242425mhc86q"));
}

TEST_CASE("request signature matches relayer canonical form") {
  auto k = Ed25519Key::parse(kSeed);
  const std::string msg = saga::memwal::canonical_message(
      "1700000000", "POST", "/api/recall", sha256_hex(R"({"query":"hi"})"),
      "11111111-2222-4333-8444-555555555555", "0xabc");
  CHECK(msg ==
        "1700000000.POST./api/recall.a43337f2c2aecb3709c60fcd7b28f6a555362fffa9e89588a63f34fdad8fe8ad."
        "11111111-2222-4333-8444-555555555555.0xabc");
  auto sig = k.sign(msg);
  CHECK(to_hex(sig.data(), sig.size()) ==
        "13fe5c4bd05477a5208b6692a3014c20249f81184eed30d0e74792cf05ca8c62"
        "a6fdcc694d5dbc7b10831cb3cb8e0ed6c191028978e33965b383d596b9f81900");
}

TEST_CASE("seal session personal message + signature") {
  auto k = Ed25519Key::parse(kSeed);
  const std::string pm =
      saga::memwal::seal_personal_message("0xe7c1", 5, 1700000000123, {k.pub.begin(), k.pub.end()});
  CHECK(pm ==
        "Accessing keys of package 0xe7c1 for 5 mins from 2023-11-14 22:13:20 UTC, "
        "session key 5zTqbCtiV95yNV5HKqBaTEh+a0Y8Ap7TBt8vAbVja1g=");
  CHECK(k.sign_personal_message(pm) ==
        "AAPqkPYtxgcnkRO6D3QpgFcv1VW7/8rhpejx5vnt4ede5WTFhqrt1Eucyt0LN4jz1OypfXx7jJAeGFScxm74lgLnNOpsK2JX3nI1"
        "XkcqoFpMSH5rRjwCntMG3y8BtWNrWA==");
}

TEST_CASE("misc encoders") {
  CHECK(to_hex(uleb128(300)) == "ac02");
  CHECK(to_hex(uleb128(0)) == "00");
  CHECK(sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  auto u = uuid4();
  CHECK(u.size() == 36);
  CHECK(u[14] == '4');
  CHECK_THROWS(from_hex("abc"));
  CHECK_THROWS(from_hex("zz"));
}

#pragma once
// Minimal crypto toolkit for MemWal / Sui, built on libsodium.
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace saga::crypto {

using Bytes = std::vector<uint8_t>;

void init();  // sodium_init; safe to call repeatedly

std::string to_hex(const uint8_t* p, size_t n);
inline std::string to_hex(const Bytes& b) { return to_hex(b.data(), b.size()); }
Bytes from_hex(std::string_view hex);  // accepts optional 0x prefix; throws on bad input

std::string b64_encode(const uint8_t* p, size_t n);
inline std::string b64_encode(const Bytes& b) { return b64_encode(b.data(), b.size()); }
inline std::string b64_encode(std::string_view s) {
  return b64_encode(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

Bytes b64_decode(std::string_view s);  // standard alphabet, padding optional; throws on bad input

std::string sha256_hex(std::string_view data);
std::string hmac_sha256_hex(std::string_view key, std::string_view data);
bool constant_time_equal(std::string_view a, std::string_view b);
std::string random_hex(size_t bytes);
// Verify an Ed25519 signature over `msg` with a raw 32-byte public key.
bool ed25519_verify(const uint8_t sig[64], const uint8_t* msg, size_t n, const uint8_t pub[32]);
// Sui personal-message digest: blake2b256(0x03 0x00 0x00 || uleb128(len) || msg).
Bytes sui_personal_message_digest(std::string_view msg);
Bytes blake2b256(const Bytes& data);
// Authenticated symmetric encryption (XSalsa20-Poly1305, libsodium secretbox). `key` is 32 bytes.
// seal() returns nonce||ciphertext; open() throws on a wrong key or any tampering.
Bytes secretbox_seal(const Bytes& key, std::string_view plaintext);
std::string secretbox_open(const Bytes& key, const Bytes& sealed);

Bytes uleb128(uint64_t v);
std::string uuid4();

// Bech32 (BIP-173) with 8->5 bit conversion, as used by Sui `suiprivkey1…`.
std::string bech32_encode_bytes(std::string_view hrp, const Bytes& payload);
Bytes bech32_decode_bytes(std::string_view s, std::string_view expected_hrp);

// Ed25519 key from a 32-byte seed.
struct Ed25519Key {
  std::array<uint8_t, 32> seed{};
  std::array<uint8_t, 32> pub{};
  std::array<uint8_t, 64> sk{};  // libsodium seed||pub form

  static Ed25519Key from_seed(const Bytes& seed32);
  static Ed25519Key generate();
  // Accepts hex seed (optionally 0x) or `suiprivkey1…`.
  static Ed25519Key parse(std::string_view key);

  std::array<uint8_t, 64> sign(const uint8_t* msg, size_t n) const;
  std::array<uint8_t, 64> sign(std::string_view msg) const {
    return sign(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
  }
  std::string pub_hex() const { return to_hex(pub.data(), pub.size()); }
  std::string sui_address() const;       // 0x + blake2b256(0x00 || pub)
  std::string sui_private_key() const;   // suiprivkey1…
  // Sui PersonalMessage signature: b64(0x00 || sig(blake2b(03 00 00 || bcs(msg))) || pub)
  std::string sign_personal_message(std::string_view msg) const;
};

}  // namespace saga::crypto

#include "core/crypto.h"

#include <sodium.h>

#include <cctype>
#include <cstring>
#include <stdexcept>

namespace saga::crypto {

void init() {
  static const bool ok = sodium_init() >= 0;
  if (!ok) throw std::runtime_error("sodium_init failed");
}

std::string to_hex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string out(n * 2, '0');
  for (size_t i = 0; i < n; ++i) {
    out[2 * i] = d[p[i] >> 4];
    out[2 * i + 1] = d[p[i] & 15];
  }
  return out;
}

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

Bytes from_hex(std::string_view hex) {
  if (hex.starts_with("0x") || hex.starts_with("0X")) hex.remove_prefix(2);
  if (hex.empty()) throw std::invalid_argument("empty hex string");
  if (hex.size() % 2) throw std::invalid_argument("odd-length hex string");
  Bytes out(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) throw std::invalid_argument("non-hex character");
    out[i] = static_cast<uint8_t>(hi << 4 | lo);
  }
  return out;
}

std::string b64_encode(const uint8_t* p, size_t n) {
  init();
  const size_t len = sodium_base64_ENCODED_LEN(n, sodium_base64_VARIANT_ORIGINAL);
  std::string out(len, '\0');
  sodium_bin2base64(out.data(), len, p, n, sodium_base64_VARIANT_ORIGINAL);
  out.resize(len - 1);  // drop NUL
  return out;
}

Bytes b64_decode(std::string_view s) {
  init();
  Bytes out(s.size() * 3 / 4 + 3);
  size_t len = 0;
  if (sodium_base642bin(out.data(), out.size(), s.data(), s.size(), " \t\r\n", &len, nullptr,
                        sodium_base64_VARIANT_ORIGINAL) != 0 &&
      sodium_base642bin(out.data(), out.size(), s.data(), s.size(), " \t\r\n", &len, nullptr,
                        sodium_base64_VARIANT_ORIGINAL_NO_PADDING) != 0)
    throw std::invalid_argument("invalid base64");
  out.resize(len);
  return out;
}

std::string hmac_sha256_hex(std::string_view key, std::string_view data) {
  init();
  uint8_t mac[crypto_auth_hmacsha256_BYTES];
  crypto_auth_hmacsha256_state st;
  crypto_auth_hmacsha256_init(&st, reinterpret_cast<const uint8_t*>(key.data()), key.size());
  crypto_auth_hmacsha256_update(&st, reinterpret_cast<const uint8_t*>(data.data()), data.size());
  crypto_auth_hmacsha256_final(&st, mac);
  return to_hex(mac, sizeof mac);
}

bool constant_time_equal(std::string_view a, std::string_view b) {
  return a.size() == b.size() && sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string random_hex(size_t bytes) {
  init();
  Bytes b(bytes);
  randombytes_buf(b.data(), b.size());
  return to_hex(b);
}

bool ed25519_verify(const uint8_t sig[64], const uint8_t* msg, size_t n, const uint8_t pub[32]) {
  init();
  return crypto_sign_verify_detached(sig, msg, n, pub) == 0;
}

Bytes sui_personal_message_digest(std::string_view msg) {
  Bytes intent{0x03, 0x00, 0x00};
  const Bytes len = uleb128(msg.size());
  intent.insert(intent.end(), len.begin(), len.end());
  intent.insert(intent.end(), msg.begin(), msg.end());
  return blake2b256(intent);
}

std::string sha256_hex(std::string_view data) {
  uint8_t h[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(h, reinterpret_cast<const uint8_t*>(data.data()), data.size());
  return to_hex(h, sizeof h);
}

Bytes blake2b256(const Bytes& data) {
  Bytes out(32);
  crypto_generichash(out.data(), out.size(), data.data(), data.size(), nullptr, 0);
  return out;
}

Bytes secretbox_seal(const Bytes& key, std::string_view plaintext) {
  init();
  if (key.size() != crypto_secretbox_KEYBYTES) throw std::invalid_argument("secretbox key must be 32 bytes");
  Bytes out(crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + plaintext.size());
  randombytes_buf(out.data(), crypto_secretbox_NONCEBYTES);
  crypto_secretbox_easy(out.data() + crypto_secretbox_NONCEBYTES, reinterpret_cast<const uint8_t*>(plaintext.data()),
                        plaintext.size(), out.data(), key.data());
  return out;
}

std::string secretbox_open(const Bytes& key, const Bytes& sealed) {
  init();
  if (key.size() != crypto_secretbox_KEYBYTES) throw std::invalid_argument("secretbox key must be 32 bytes");
  if (sealed.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
    throw std::runtime_error("sealed data is truncated");
  std::string out(sealed.size() - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES, '\0');
  if (crypto_secretbox_open_easy(reinterpret_cast<uint8_t*>(out.data()), sealed.data() + crypto_secretbox_NONCEBYTES,
                                 sealed.size() - crypto_secretbox_NONCEBYTES, sealed.data(), key.data()) != 0)
    throw std::runtime_error("cannot decrypt: wrong key or tampered data");
  return out;
}

Bytes uleb128(uint64_t v) {
  Bytes out;
  do {
    uint8_t b = v & 0x7f;
    v >>= 7;
    out.push_back(v ? (b | 0x80) : b);
  } while (v);
  return out;
}

std::string uuid4() {
  init();
  uint8_t b[16];
  randombytes_buf(b, sizeof b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const std::string h = to_hex(b, sizeof b);
  return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" + h.substr(16, 4) + "-" +
         h.substr(20);
}

// ---- bech32 -------------------------------------------------------------
namespace {
constexpr const char* kCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

uint32_t polymod(const Bytes& values) {
  static const uint32_t gen[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
  uint32_t chk = 1;
  for (uint8_t v : values) {
    uint32_t top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (int i = 0; i < 5; ++i)
      if ((top >> i) & 1) chk ^= gen[i];
  }
  return chk;
}

Bytes hrp_expand(std::string_view hrp) {
  Bytes r;
  for (char c : hrp) r.push_back(static_cast<uint8_t>(c) >> 5);
  r.push_back(0);
  for (char c : hrp) r.push_back(static_cast<uint8_t>(c) & 31);
  return r;
}

Bytes convertbits(const Bytes& data, int from, int to, bool pad) {
  uint32_t acc = 0;
  int bits = 0;
  Bytes ret;
  const uint32_t maxv = (1u << to) - 1, max_acc = (1u << (from + to - 1)) - 1;
  for (uint8_t v : data) {
    if (v >> from) throw std::invalid_argument("convertbits: bad value");
    acc = ((acc << from) | v) & max_acc;
    bits += from;
    while (bits >= to) {
      bits -= to;
      ret.push_back((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits) ret.push_back((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    throw std::invalid_argument("convertbits: incomplete group");
  }
  return ret;
}
}  // namespace

std::string bech32_encode_bytes(std::string_view hrp, const Bytes& payload) {
  Bytes data = convertbits(payload, 8, 5, true);
  Bytes values = hrp_expand(hrp);
  values.insert(values.end(), data.begin(), data.end());
  values.insert(values.end(), 6, 0);
  const uint32_t pm = polymod(values) ^ 1;
  for (int i = 0; i < 6; ++i) data.push_back((pm >> (5 * (5 - i))) & 31);
  std::string out(hrp);
  out += '1';
  for (uint8_t d : data) out += kCharset[d];
  return out;
}

Bytes bech32_decode_bytes(std::string_view s, std::string_view expected_hrp) {
  std::string lower(s);
  for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  const auto pos = lower.rfind('1');
  if (pos == std::string::npos || pos < 1 || pos + 7 > lower.size())
    throw std::invalid_argument("bech32: no separator");
  const std::string hrp = lower.substr(0, pos);
  if (hrp != expected_hrp) throw std::invalid_argument("bech32: unexpected prefix " + hrp);
  Bytes data;
  for (char c : lower.substr(pos + 1)) {
    const char* p = std::strchr(kCharset, c);
    if (!p || !c) throw std::invalid_argument("bech32: bad character");
    data.push_back(static_cast<uint8_t>(p - kCharset));
  }
  Bytes values = hrp_expand(hrp);
  values.insert(values.end(), data.begin(), data.end());
  if (polymod(values) != 1) throw std::invalid_argument("bech32: checksum mismatch");
  data.resize(data.size() - 6);
  return convertbits(data, 5, 8, false);
}

// ---- Ed25519 ------------------------------------------------------------
Ed25519Key Ed25519Key::from_seed(const Bytes& seed32) {
  init();
  if (seed32.size() != 32) throw std::invalid_argument("Ed25519 seed must be 32 bytes");
  Ed25519Key k;
  std::memcpy(k.seed.data(), seed32.data(), 32);
  crypto_sign_seed_keypair(k.pub.data(), k.sk.data(), k.seed.data());
  return k;
}

Ed25519Key Ed25519Key::generate() {
  init();
  Bytes seed(32);
  randombytes_buf(seed.data(), seed.size());
  return from_seed(seed);
}

Ed25519Key Ed25519Key::parse(std::string_view key) {
  while (!key.empty() && std::isspace(static_cast<unsigned char>(key.front()))) key.remove_prefix(1);
  while (!key.empty() && std::isspace(static_cast<unsigned char>(key.back()))) key.remove_suffix(1);
  if (key.size() > 11 && (key.starts_with("suiprivkey1") || key.starts_with("SUIPRIVKEY1"))) {
    Bytes payload = bech32_decode_bytes(key, "suiprivkey");
    if (payload.empty() || payload[0] != 0x00) throw std::invalid_argument("only Ed25519 keys supported");
    return from_seed(Bytes(payload.begin() + 1, payload.end()));
  }
  return from_seed(from_hex(key));
}

std::array<uint8_t, 64> Ed25519Key::sign(const uint8_t* msg, size_t n) const {
  std::array<uint8_t, 64> sig{};
  crypto_sign_detached(sig.data(), nullptr, msg, n, sk.data());
  return sig;
}

std::string Ed25519Key::sui_address() const {
  Bytes in{0x00};
  in.insert(in.end(), pub.begin(), pub.end());
  return "0x" + to_hex(blake2b256(in));
}

std::string Ed25519Key::sui_private_key() const {
  Bytes payload{0x00};
  payload.insert(payload.end(), seed.begin(), seed.end());
  return bech32_encode_bytes("suiprivkey", payload);
}

std::string Ed25519Key::sign_personal_message(std::string_view msg) const {
  const Bytes digest = sui_personal_message_digest(msg);
  const auto sig = sign(digest.data(), digest.size());
  Bytes serialized{0x00};
  serialized.insert(serialized.end(), sig.begin(), sig.end());
  serialized.insert(serialized.end(), pub.begin(), pub.end());
  return b64_encode(serialized);
}

}  // namespace saga::crypto

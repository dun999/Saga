#include "memwal/redact.h"

#include <cctype>
#include <nlohmann/json.hpp>

namespace saga::memwal {
namespace {

using std::string;
using std::string_view;

constexpr size_t kMarkerLen = 17;  // strlen("[redacted secret]")

bool is_word(unsigned char c) { return std::isalnum(c) || c == '_'; }
bool is_hex(unsigned char c) { return std::isxdigit(c); }

bool left_boundary(string_view s, size_t i) { return i == 0 || !is_word(static_cast<unsigned char>(s[i - 1])); }
bool right_boundary(string_view s, size_t i) { return i >= s.size() || !is_word(static_cast<unsigned char>(s[i])); }

bool starts_ci(string_view s, size_t i, string_view lit) {
  if (i + lit.size() > s.size()) return false;
  for (size_t k = 0; k < lit.size(); ++k)
    if (std::tolower(static_cast<unsigned char>(s[i + k])) != static_cast<unsigned char>(lit[k])) return false;
  return true;
}

bool at_marker(string_view s, size_t i) { return s.substr(i, kMarkerLen) == kRedacted; }

void skip_marker(string& out, size_t& i) {
  out.append(kRedacted);
  i += kMarkerLen;
}

// Grow `j` over `pred`, then shrink until the match ends on a word boundary and is at least `min`.
// That is what a trailing `\b` does to a class that also contains non-word characters such as '-'.
template <class Pred>
size_t take_body(string_view s, size_t i, size_t min, bool exact, Pred pred) {
  size_t j = i;
  if (exact) {
    if (i + min > s.size()) return string::npos;
    for (size_t k = 0; k < min; ++k)
      if (!pred(static_cast<unsigned char>(s[i + k]))) return string::npos;
    j = i + min;
  } else {
    while (j < s.size() && pred(static_cast<unsigned char>(s[j]))) ++j;
  }
  while (j >= i + min) {
    const bool boundary = is_word(static_cast<unsigned char>(s[j - 1])) && right_boundary(s, j);
    if (boundary) return j;
    if (exact) return string::npos;
    --j;
  }
  return string::npos;
}

bool cls_token(unsigned char c) { return std::isalnum(c) || c == '_' || c == '-'; }
bool cls_alnum(unsigned char c) { return std::isalnum(c); }
bool cls_slack(unsigned char c) { return std::isalnum(c) || c == '-'; }
bool cls_akia(unsigned char c) { return std::isdigit(c) || (c >= 'A' && c <= 'Z'); }
bool cls_b64(unsigned char c) { return std::isalnum(c) || c == '_' || c == '-'; }
bool cls_sui(unsigned char c) { return std::islower(c) || std::isdigit(c); }

size_t match_prefixed(string_view s, size_t i, string_view prefix, size_t min, bool exact, auto pred) {
  if (!s.substr(i).starts_with(prefix)) return string::npos;
  return take_body(s, i + prefix.size(), min, exact, pred);
}

size_t match_jwt(string_view s, size_t i) {
  auto part = [&](size_t p, size_t min) { return take_body(s, p, min, false, cls_b64); };
  if (!s.substr(i).starts_with("eyJ")) return string::npos;
  size_t a = part(i + 3, 8);
  if (a == string::npos || a >= s.size() || s[a] != '.') return string::npos;
  if (!s.substr(a + 1).starts_with("eyJ")) return string::npos;
  size_t b = part(a + 4, 8);
  if (b == string::npos || b >= s.size() || s[b] != '.') return string::npos;
  return part(b + 1, 8);
}

// Provider tokens, tried in the same order as the alternation they replace.
size_t match_token(string_view s, size_t i) {
  if (!left_boundary(s, i)) return string::npos;
  if (auto e = match_prefixed(s, i, "sk-ant-", 16, false, cls_token); e != string::npos) return e;
  if (auto e = match_prefixed(s, i, "sk-proj-", 20, false, cls_token); e != string::npos) return e;
  if (auto e = match_prefixed(s, i, "sk-live-", 20, false, cls_token); e != string::npos) return e;
  if (auto e = match_prefixed(s, i, "sk-test-", 20, false, cls_token); e != string::npos) return e;
  if (auto e = match_prefixed(s, i, "sk-", 20, false, cls_token); e != string::npos) return e;
  if (s.size() >= i + 4 && s[i] == 'g' && s[i + 1] == 'h' && s[i + 3] == '_' &&
      (s[i + 2] == 'p' || s[i + 2] == 'o' || s[i + 2] == 'u' || s[i + 2] == 's' || s[i + 2] == 'r')) {
    if (auto e = take_body(s, i + 4, 30, false, cls_alnum); e != string::npos) return e;
  }
  if (auto e = match_prefixed(s, i, "github_pat_", 30, false, [](unsigned char c) { return std::isalnum(c) || c == '_'; });
      e != string::npos)
    return e;
  if (auto e = match_prefixed(s, i, "glpat-", 16, false, cls_token); e != string::npos) return e;
  if (auto e = match_prefixed(s, i, "xai-", 24, false, cls_alnum); e != string::npos) return e;
  if (s.size() >= i + 5 && s.substr(i, 3) == "xox" && s[i + 4] == '-' &&
      (s[i + 3] == 'a' || s[i + 3] == 'b' || s[i + 3] == 'p' || s[i + 3] == 'r' || s[i + 3] == 's')) {
    if (auto e = take_body(s, i + 5, 10, false, cls_slack); e != string::npos) return e;
  }
  if (auto e = match_prefixed(s, i, "AKIA", 16, true, cls_akia); e != string::npos) return e;
  if (auto e = match_prefixed(s, i, "AIza", 30, false, cls_token); e != string::npos) return e;
  if (auto e = match_prefixed(s, i, "suiprivkey1", 40, false, cls_sui); e != string::npos) return e;
  if (auto e = match_jwt(s, i); e != string::npos) return e;
  return string::npos;
}

size_t match_hex(string_view s, size_t i) {
  if (!left_boundary(s, i)) return string::npos;
  size_t hex = i;
  if (i + 2 < s.size() && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X')) hex = i + 2;
  if (hex + 64 > s.size()) return string::npos;
  for (size_t k = 0; k < 64; ++k)
    if (!is_hex(static_cast<unsigned char>(s[hex + k]))) return string::npos;
  if (hex + 64 < s.size() && is_hex(static_cast<unsigned char>(s[hex + 64]))) return string::npos;
  return hex + 64;
}

// [A-Z ]* is greedy in front of "PRIVATE KEY-----", so the type ("OPENSSH ", "RSA ") has to be
// given back until the kind still matches. A certificate block does not.
size_t after_private_key(string_view s, size_t p) {
  constexpr string_view kKind = "PRIVATE KEY-----";
  for (size_t q = p; q < s.size() && q - p <= 64; ++q) {
    if (s.substr(q).starts_with(kKind)) return q + kKind.size();
    const unsigned char c = static_cast<unsigned char>(s[q]);
    if (!(std::isupper(c) || s[q] == ' ')) return string::npos;
  }
  return string::npos;
}

size_t pem_end(string_view s, size_t begin) {
  constexpr string_view kBegin = "-----BEGIN ";
  constexpr string_view kEnd = "-----END ";
  if (!s.substr(begin).starts_with(kBegin)) return string::npos;
  const size_t head = after_private_key(s, begin + kBegin.size());
  if (head == string::npos) return string::npos;
  const auto end = s.find(kEnd, head);
  if (end == string::npos) return string::npos;
  return after_private_key(s, end + kEnd.size());
}

// Longest first, so "secret key" wins over "secret" and "pin code" wins over "pin".
constexpr string_view kLabels[] = {
    "client secret", "client-secret", "client_secret", "access token", "access-token", "access_token",
    "private key",   "private-key",   "private_key",   "passphrase",    "secret key",   "secret-key",
    "secret_key",    "access key",    "access-key",    "access_key",    "auth token",   "auth-token",
    "auth_token",    "passcode",      "password",      "pin code",      "api key",      "api-key",
    "api_key",       "pincode",       "passwd",        "secret",        "token",        "pin",
};
constexpr string_view kSeeds[] = {"recovery", "mnemonic", "secret", "seed"};

size_t keyword_end(string_view s, size_t i, const string_view* kws, size_t n) {
  for (size_t k = 0; k < n; ++k) {
    const auto kw = kws[k];
    if (starts_ci(s, i, kw) && right_boundary(s, i + kw.size())) return i + kw.size();
  }
  return string::npos;
}

// `(?:\w*_)?` then a keyword. The prefix, when present, ends in '_' and is otherwise a word.
size_t label_end(string_view s, size_t i) {
  size_t best = string::npos;
  auto consider = [&](size_t at) {
    const size_t e = keyword_end(s, at, kLabels, std::size(kLabels));
    if (e != string::npos) best = e;
  };
  consider(i);
  size_t p = i;
  while (p < s.size() && p < i + 64 && is_word(static_cast<unsigned char>(s[p]))) {
    if (s[p] == '_') consider(p + 1);
    ++p;
  }
  return best;
}

// Optional " for <host>" between the keyword and the separator.
size_t extend_for(string_view s, size_t k) {
  size_t i = k;
  while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
  if (i == k || !starts_ci(s, i, "for") || !right_boundary(s, i + 3)) return k;
  size_t h = i + 3;
  while (h < s.size() && std::isspace(static_cast<unsigned char>(s[h]))) ++h;
  if (h == i + 3) return k;
  size_t host = h;
  while (host < s.size()) {
    const unsigned char c = static_cast<unsigned char>(s[host]);
    if (!(is_word(c) || c == '.' || c == '@' || c == '-')) break;
    ++host;
  }
  return host > h ? host : k;
}

// `\s*(?:is|=|:)\s*`. Returns the index of the value, or npos.
size_t separator_end(string_view s, size_t p) {
  size_t i = p;
  while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
  if (i >= s.size()) return string::npos;
  if (starts_ci(s, i, "is") && right_boundary(s, i + 2)) i += 2;
  else if (s[i] == '=' || s[i] == ':') i += 1;
  else return string::npos;
  while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
  return i;
}

bool marker_span(string_view v) {
  size_t a = 0, b = v.size();
  while (a < b && std::isspace(static_cast<unsigned char>(v[a]))) ++a;
  while (b > a && std::isspace(static_cast<unsigned char>(v[b - 1]))) --b;
  return v.substr(a, b - a) == kRedacted;
}

struct Hit {
  size_t keep = 0;    // copy [from, keep) then the marker
  size_t resume = 0;  // continue here
  bool already = false;
};

// Seed / recovery / secret / mnemonic phrases: the rest of the line is the value.
bool match_seed(string_view s, size_t i, Hit& hit) {
  if (!left_boundary(s, i)) return false;
  size_t k = keyword_end(s, i, kSeeds, std::size(kSeeds));
  if (k == string::npos) return false;
  size_t phrase = k;
  while (phrase < s.size() && std::isspace(static_cast<unsigned char>(s[phrase])) && s[phrase] != '\n') ++phrase;
  if (phrase > k && starts_ci(s, phrase, "phrase") && right_boundary(s, phrase + 6)) k = phrase + 6;
  const size_t val = separator_end(s, k);
  if (val == string::npos) return false;
  const size_t line = s.find('\n', val);
  const size_t end = line == string::npos ? s.size() : line;
  const string_view body = s.substr(val, end - val);
  if (marker_span(body)) {
    hit = {i, end, true};
    return true;
  }
  if (body.size() < 8) return false;
  hit = {val, end, false};
  return true;
}

// `password is value`, `DB_PASSWORD=value`, `api key: value`.
bool match_label(string_view s, size_t i, Hit& hit) {
  if (!left_boundary(s, i)) return false;
  const size_t kw = label_end(s, i);
  if (kw == string::npos) return false;
  const size_t labeled = extend_for(s, kw);
  const size_t val = separator_end(s, labeled);
  if (val == string::npos) return false;
  size_t v = val;
  char quote = 0;
  if (v < s.size() && (s[v] == '"' || s[v] == '\'')) quote = s[v++];
  if (at_marker(s, v)) {
    size_t end = v + kMarkerLen;
    if (quote && end < s.size() && s[end] == quote) ++end;
    hit = {i, end, true};
    return true;
  }
  size_t e = v;
  while (e < s.size()) {
    const unsigned char c = static_cast<unsigned char>(s[e]);
    if (std::isspace(c) || c == '"' || c == '\'' || c == '`' || c == ',' || c == ';') break;
    ++e;
  }
  if (e - v < 4) return false;
  if (quote) {
    if (e >= s.size() || s[e] != quote) return false;
    ++e;
  }
  // Quotes are not part of the kept label. The value, quotes included, is replaced.
  hit = {val, e, false};
  return true;
}

bool match_bearer(string_view s, size_t i, Hit& hit) {
  if (!left_boundary(s, i) || !s.substr(i).starts_with("Bearer")) return false;
  size_t p = i + 6;
  if (p >= s.size() || !std::isspace(static_cast<unsigned char>(s[p]))) return false;
  while (p < s.size() && std::isspace(static_cast<unsigned char>(s[p]))) ++p;
  if (at_marker(s, p)) {
    hit = {i, p + kMarkerLen, true};
    return true;
  }
  size_t e = p;
  while (e < s.size()) {
    const unsigned char c = static_cast<unsigned char>(s[e]);
    if (!(std::isalnum(c) || c == '.' || c == '_' || c == '~' || c == '+' || c == '/' || c == '-')) break;
    ++e;
  }
  if (e - p < 16) return false;
  while (e < s.size() && s[e] == '=') ++e;
  hit = {p, e, false};
  return true;
}

string apply_pem(string_view in, int& n) {
  string out;
  size_t i = 0;
  while (i < in.size()) {
    const auto b = in.find("-----BEGIN ", i);
    if (b == string::npos) {
      out.append(in.substr(i));
      break;
    }
    const size_t e = pem_end(in, b);
    if (e == string::npos) {
      out.append(in.substr(i, b + 1 - i));
      i = b + 1;
      continue;
    }
    out.append(in.substr(i, b - i));
    out.append(kRedacted);
    ++n;
    i = e;
  }
  return out;
}

template <class Match>
string apply_at(string_view in, int& n, Match match) {
  string out;
  for (size_t i = 0; i < in.size();) {
    if (at_marker(in, i)) {
      skip_marker(out, i);
      continue;
    }
    Hit hit;
    if (match(in, i, hit)) {
      if (hit.already) out.append(in.substr(i, hit.resume - i));
      else {
        out.append(in.substr(i, hit.keep - i));
        out.append(kRedacted);
        ++n;
      }
      i = hit.resume;
      continue;
    }
    out.push_back(in[i]);
    ++i;
  }
  return out;
}

string apply_tokens(string_view in, int& n) {
  string out;
  for (size_t i = 0; i < in.size();) {
    if (at_marker(in, i)) {
      skip_marker(out, i);
      continue;
    }
    if (const size_t e = match_token(in, i); e != string::npos) {
      out.append(kRedacted);
      ++n;
      i = e;
      continue;
    }
    out.push_back(in[i]);
    ++i;
  }
  return out;
}

string apply_hex(string_view in, int& n) {
  string out;
  for (size_t i = 0; i < in.size();) {
    if (at_marker(in, i)) {
      skip_marker(out, i);
      continue;
    }
    if (const size_t e = match_hex(in, i); e != string::npos) {
      out.append(kRedacted);
      ++n;
      i = e;
      continue;
    }
    out.push_back(in[i]);
    ++i;
  }
  return out;
}

bool public_id_key(string_view key) {
  return key == "sha256" || key == "uid" || key == "address" || key == "owner" || key == "wallet" ||
         key == "blob_id" || key == "job_id";
}

string redact_text(string_view text, int* found, bool keep_ids) {
  int n = 0;
  string out = apply_pem(text, n);
  out = apply_tokens(out, n);
  if (!keep_ids) out = apply_hex(out, n);
  out = apply_at(out, n, match_seed);
  out = apply_at(out, n, match_label);
  out = apply_at(out, n, match_bearer);
  if (found) *found += n;
  return out;
}

bool redact_json(nlohmann::json& j, int* found, const string& key, int depth) {
  if (depth > kMaxJsonDepth) return false;
  if (j.is_string()) {
    j = redact_text(j.get<string>(), found, public_id_key(key));
  } else if (j.is_object()) {
    for (auto& [k, v] : j.items())
      if (!redact_json(v, found, k, depth + 1)) return false;
  } else if (j.is_array()) {
    for (auto& v : j)
      if (!redact_json(v, found, "", depth + 1)) return false;
  }
  return true;
}

StorageText refuse(const string& error) { return {false, kNotStored, error, 0}; }

}  // namespace

int json_nesting(string_view text, int limit) {
  int depth = 0, max_depth = 0;
  bool in_string = false, escaped = false;
  for (unsigned char c : text) {
    if (in_string) {
      if (escaped) escaped = false;
      else if (c == '\\') escaped = true;
      else if (c == '"') in_string = false;
      continue;
    }
    if (c == '"') {
      in_string = true;
      continue;
    }
    if (c == '{' || c == '[') {
      if (++depth > max_depth) max_depth = depth;
      if (limit > 0 && depth > limit) return depth;
    } else if ((c == '}' || c == ']') && depth > 0) {
      --depth;
    }
  }
  return max_depth;
}

StorageText prepare_for_storage(const string& text) {
  if (text.size() > kMaxStoredBytes) return refuse("memory record exceeds 256 KiB");
  const auto sp = text.find(' ');
  if (text.starts_with("SAGA:") && sp != string::npos) {
    const string body = text.substr(sp + 1);
    if (json_nesting(body, kMaxJsonDepth) > kMaxJsonDepth)
      return refuse("memory record is nested too deeply");
    auto j = nlohmann::json::parse(body, nullptr, false);
    if (!j.is_discarded()) {
      int n = 0;
      if (!redact_json(j, &n, "", 0)) return refuse("memory record is nested too deeply");
      return {true, text.substr(0, sp + 1) + j.dump(), "", n};
    }
  }
  int n = 0;
  return {true, redact_text(text, &n, false), "", n};
}

string redact_secrets(const string& text, int* found) {
  const StorageText r = prepare_for_storage(text);
  if (found) *found = r.ok ? r.found : 1;
  return r.ok ? r.text : string(kNotStored);
}

}  // namespace saga::memwal

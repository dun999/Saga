#include "memwal/redact.h"

#include <nlohmann/json.hpp>
#include <regex>
#include <vector>

namespace saga::memwal {
namespace {

struct Rule {
  std::regex re;
  std::string keep;  // replacement prefix: the captured label that stays readable ("password: ")
};

const std::vector<Rule>& rules() {
  using std::regex;
  const auto icase = regex::ECMAScript | regex::icase;
  static const std::vector<Rule> r = [&] {
    std::vector<Rule> v;
    // Whole PEM private keys.
    v.push_back({regex(R"(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)"), ""});
    // Provider token formats: recognisable on their own, wherever they appear.
    v.push_back({regex(
        R"(\b(?:sk-ant-[A-Za-z0-9_\-]{16,}|sk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_\-]{16,}|xai-[A-Za-z0-9]{24,}|xox[abprs]-[A-Za-z0-9\-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{30,}|suiprivkey1[a-z0-9]{40,}|eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b)"), ""});
    // Seed / recovery phrases: everything after the label up to the end of the line.
    v.push_back({regex(R"((\b(?:seed|recovery|secret|mnemonic)(?:\s+phrase)?)(\s*(?:is|=|:)\s*)(?!\[redacted)[^\n]{8,})", icase), "$1$2"});
    // `NAME=value`, `password: value`, "my password is value", "api key is value".
    v.push_back({regex(
        R"(\b((?:\w*_)?(?:password|passwd|passcode|passphrase|pin(?:\s*code)?|secret(?:[_ -]?key)?|api[_ -]?key|access[_ -]?(?:key|token)|auth[_ -]?token|private[_ -]?key|client[_ -]?secret|token)(?:\s+for\s+[\w.@-]+)?)(\s*(?:is|=|:)\s*)(?!\[redacted)(["']?)[^\s"'`,;]{4,}\3)", icase), "$1$2"});
    v.push_back({regex(R"(\b(Bearer\s+)[A-Za-z0-9._~+/\-]{16,}=*)"), "$1"});
    return v;
  }();
  return r;
}

std::string redact_text(const std::string& text, int* found) {
  std::string out = text;
  int n = 0;
  for (const auto& rule : rules()) {
    std::string next;
    auto begin = std::sregex_iterator(out.begin(), out.end(), rule.re);
    size_t last = 0;
    for (auto it = begin; it != std::sregex_iterator(); ++it) {
      const auto& m = *it;
      next.append(out, last, m.position() - last);
      next += m.format(rule.keep) + kRedacted;
      last = m.position() + m.length();
      ++n;
    }
    next.append(out, last, std::string::npos);
    out = std::move(next);
  }
  if (found) *found += n;
  return out;
}

void redact_json(nlohmann::json& j, int* found) {
  if (j.is_string()) j = redact_text(j.get<std::string>(), found);
  else if (j.is_structured())
    for (auto& v : j) redact_json(v, found);
}

}  // namespace

// A "SAGA:<kind> {json}" record is redacted value by value: a pattern run over the serialized JSON
// could swallow its quotes and braces ("secret: …" eats to the end of the line) and leave it unreadable.
std::string redact_secrets(const std::string& text, int* found) {
  int n = 0;
  std::string out;
  const auto sp = text.find(' ');
  auto j = text.starts_with("SAGA:") && sp != std::string::npos
               ? nlohmann::json::parse(text.substr(sp + 1), nullptr, false)
               : nlohmann::json(nlohmann::json::value_t::discarded);
  if (!j.is_discarded()) {
    redact_json(j, &n);
    out = text.substr(0, sp + 1) + j.dump();
  } else {
    out = redact_text(text, &n);
  }
  if (found) *found = n;
  return out;
}

}  // namespace saga::memwal

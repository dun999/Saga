#include "router/mentions.h"

#include <algorithm>
#include <cctype>
#include <initializer_list>
#include <sstream>

namespace saga::router {
namespace {

bool is_handle_char(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_'; }

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  return s;
}

bool one_of(const std::string& s, std::initializer_list<const char*> words) {
  const std::string l = lower(s);
  return std::any_of(words.begin(), words.end(), [&](const char* w) { return l == w; });
}

// Trim whitespace plus connective filler left over at segment edges ("…, then", "and"). Text that is
// nothing but a connective ("@claude and @codex") is empty: it joins mentions, it isn't a task.
std::string tidy(std::string s) {
  auto trim = [](std::string& x) {
    const char* ws = " \t\r\n,;:.-";
    x.erase(0, x.find_first_not_of(ws));
    const auto e = x.find_last_not_of(" \t\r\n,;:-");
    x.erase(e == std::string::npos ? 0 : e + 1);
    if (x.size() > 1 && x.back() == '.' && x[x.size() - 2] != '.') x.pop_back();  // sentence stop
  };
  trim(s);
  for (bool changed = true; changed;) {
    changed = false;
    for (const char* w : {" then", " and", " also", " and then", " after that"}) {
      const std::string suf(w);
      if (s.size() > suf.size() && lower(s.substr(s.size() - suf.size())) == suf) {
        s.erase(s.size() - suf.size());
        trim(s);
        changed = true;
      }
    }
    for (const char* w : {"and then ", "and ", "then ", "also ", "plus "}) {
      const std::string pre(w);
      if (s.size() > pre.size() && lower(s.substr(0, pre.size())) == pre) {
        s.erase(0, pre.size());
        trim(s);
        changed = true;
      }
    }
  }
  if (one_of(s, {"and", "then", "also", "and then", "after that", "plus", "&", "or"})) return "";
  return s;
}

// "hey @saga @claude, introduce yourselves": the greeting addresses the agents, it isn't a task.
bool greeting(const std::string& s) {
  return one_of(s, {"hey", "hi", "hello", "yo", "ok", "okay", "please", "so", "all", "team", "guys", "hey all",
                    "hi all", "hey team", "hi team", "hey guys", "hi guys", "hello all", "hello team", "hey everyone",
                    "hi everyone", "hello everyone"});
}

}  // namespace

std::vector<Segment> split_mentions(const std::string& text, const std::vector<std::string>& known) {
  struct Hit { size_t at, end; std::string name; };
  std::vector<Hit> hits;
  for (size_t i = 0; i < text.size(); ++i) {
    if (text[i] != '@') continue;
    if (i > 0 && (is_handle_char(text[i - 1]) || text[i - 1] == '.')) continue;  // emails
    size_t j = i + 1;
    while (j < text.size() && is_handle_char(text[j])) ++j;
    const std::string name = lower(text.substr(i + 1, j - i - 1));
    if (std::find(known.begin(), known.end(), name) != known.end()) hits.push_back({i, j, name});
  }

  std::vector<Segment> out;
  std::string head = tidy(text.substr(0, hits.empty() ? text.size() : hits.front().at));
  if (!hits.empty() && greeting(head)) head.clear();
  // A mention with no instruction of its own takes the next one ("@codex @grok write a haiku"), or the
  // text before the mentions ("fix the flaky test @codex") — which then belongs to them, not the primary.
  bool head_used = false;
  for (size_t k = 0; k < hits.size(); ++k) {
    const size_t stop = k + 1 < hits.size() ? hits[k + 1].at : text.size();
    std::string instr = tidy(text.substr(hits[k].end, stop - hits[k].end));
    // "@codex @grok build it" → both get the same instruction.
    if (instr.empty() && k + 1 < hits.size()) {
      size_t n = k + 1;
      while (n < hits.size()) {
        const size_t s2 = n + 1 < hits.size() ? hits[n + 1].at : text.size();
        std::string next = tidy(text.substr(hits[n].end, s2 - hits[n].end));
        if (!next.empty()) { instr = next; break; }
        ++n;
      }
    }
    if (instr.empty()) {
      instr = head.empty() ? "Continue the task above." : head;
      head_used |= !head.empty();
    }
    out.push_back({hits[k].name, instr});
  }
  if (!head.empty() && !head_used) out.insert(out.begin(), {"", head});
  return out;
}

std::vector<Segment> find_handoffs(const std::string& output, const std::vector<std::string>& known) {
  std::vector<Segment> out;
  std::istringstream in(output);
  for (std::string line; std::getline(in, line);) {
    size_t p = line.find_first_not_of(" \t>*-");
    if (p == std::string::npos || line[p] != '@') continue;
    size_t j = p + 1;
    while (j < line.size() && is_handle_char(line[j])) ++j;
    const std::string name = lower(line.substr(p + 1, j - p - 1));
    if (std::find(known.begin(), known.end(), name) == known.end()) continue;
    std::string instr = tidy(line.substr(j));
    if (!instr.empty()) out.push_back({name, instr});
  }
  return out;
}

}  // namespace saga::router

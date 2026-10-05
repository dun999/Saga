#include "web/guard.h"

#include <algorithm>
#include <cctype>

#include "core/crypto.h"

namespace saga::web {
namespace {

std::string lower(std::string_view s) {
  std::string o(s);
  std::transform(o.begin(), o.end(), o.begin(), [](unsigned char c) { return std::tolower(c); });
  return o;
}

bool same_host(std::string_view a, std::string_view b) { return lower(a) == lower(b); }

// host, or host:port. IPv6 in brackets is compared whole.
std::string host_without_port(std::string_view host) {
  if (!host.empty() && host.front() == '[') {
    const auto end = host.find(']');
    return end == std::string_view::npos ? std::string(host) : std::string(host.substr(0, end + 1));
  }
  const auto colon = host.rfind(':');
  if (colon == std::string_view::npos) return std::string(host);
  return std::string(host.substr(0, colon));
}

}  // namespace

bool content_type_json(std::string_view content_type) {
  const auto semi = content_type.find(';');
  auto media = content_type.substr(0, semi);
  while (!media.empty() && std::isspace(static_cast<unsigned char>(media.front()))) media.remove_prefix(1);
  while (!media.empty() && std::isspace(static_cast<unsigned char>(media.back()))) media.remove_suffix(1);
  return lower(media) == "application/json";
}

std::string origin_host(std::string_view origin) {
  const auto scheme = origin.find("://");
  if (scheme == std::string_view::npos) return {};
  auto host = origin.substr(scheme + 3);
  if (host.empty() || host.find('/') != std::string_view::npos || host.find('@') != std::string_view::npos ||
      host.find(' ') != std::string_view::npos)
    return {};
  return std::string(host);
}

bool host_allowed(std::string_view host_header, std::string_view public_origin, std::string_view bind_host) {
  if (public_origin.empty()) return true;
  if (host_header.empty() || host_header.find('/') != std::string_view::npos ||
      host_header.find(' ') != std::string_view::npos || host_header.find('@') != std::string_view::npos)
    return false;
  const std::string pub = origin_host(public_origin);
  const std::string bare = host_without_port(host_header);
  if (!pub.empty()) {
    if (same_host(host_header, pub)) return true;
    // "example.com" also matches "example.com:8080". A port in the origin must be present in Host.
    if (host_without_port(pub) == pub && same_host(bare, pub)) return true;
  }
  auto bind = [&](std::string_view name) {
    if (same_host(host_header, name) || same_host(bare, name)) return true;
    return name == "::1" && (same_host(bare, "[::1]") || same_host(host_header, "[::1]"));
  };
  return bind(bind_host) || bind("127.0.0.1") || bind("localhost") || bind("::1");
}

Decision check_mutation(const Mutation& m) {
  if (m.method != "POST" && m.method != "PUT" && m.method != "PATCH" && m.method != "DELETE") return {};
  if (!m.body.empty() && !content_type_json(m.content_type))
    return {415, "Content-Type must be application/json"};
  const std::string site = lower(m.fetch_site);
  const bool browser = !m.origin.empty() || !site.empty();
  if (site == "cross-site" || site == "same-site") return {403, "cross-site request blocked"};
  if (!site.empty() && site != "same-origin" && site != "none")
    return {403, "cross-site request blocked"};
  const std::string& expect = !m.expected_origin.empty() ? m.expected_origin : m.request_origin;
  if (!m.origin.empty()) {
    if (expect.empty() || m.origin != expect) return {403, "origin not allowed"};
  } else if (browser && site != "none" && site != "same-origin") {
    return {403, "origin required"};
  }
  if (browser && (m.csrf_cookie.empty() || m.csrf_header.empty() ||
                  !crypto::constant_time_equal(m.csrf_cookie, m.csrf_header)))
    return {403, "reload the page and try again"};
  return {};
}

std::string security_csp(std::string_view nonce, bool document) {
  if (!document)
    return "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'";
  // 'unsafe-inline' is ignored for scripts once a nonce is present, which is the point: injected
  // script tags do not have this response's nonce. Inline style attributes stay, because the pages
  // are full of them. esm.sh is the wallet-standard module; fonts load from Google.
  return "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; frame-src 'self'; "
         "script-src 'self' 'nonce-" +
         std::string(nonce) +
         "' https://esm.sh; "
         "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src-attr 'unsafe-inline'; "
         "font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; "
         "connect-src 'self' https://esm.sh https://fonts.googleapis.com https://fonts.gstatic.com; "
         "form-action 'self'";
}

std::string inject_nonce(std::string html, std::string_view nonce) {
  const std::string from = "<script";
  const std::string to = "<script nonce=\"" + std::string(nonce) + "\"";
  for (size_t at = 0; (at = html.find(from, at)) != std::string::npos; at += to.size()) html.replace(at, from.size(), to);
  return html;
}

int Slots::take(const std::string& uid, int per_user, int global_max) {
  std::lock_guard lk(mu);
  if (used[uid] >= per_user) return 1;
  if (total >= global_max) return 2;
  ++used[uid];
  ++total;
  return 0;
}

void Slots::give(const std::string& uid) {
  std::lock_guard lk(mu);
  if (--used[uid] <= 0) used.erase(uid);
  if (total > 0) --total;
}

RateLimiter::RateLimiter(int per_key, int global_max) : per_(per_key), global_max_(global_max) {}

void RateLimiter::reopen(Window& w, std::chrono::steady_clock::time_point now) {
  if (w.start.time_since_epoch().count() == 0 || now - w.start >= std::chrono::seconds(60)) w = {0, now};
}

bool RateLimiter::allow(const std::string& key) {
  const auto now = std::chrono::steady_clock::now();
  std::lock_guard lk(mu_);
  reopen(global_, now);
  if (keys_.size() > 10000) keys_.clear();
  auto& mine = keys_[key];
  reopen(mine, now);
  if (global_.n >= global_max_ || mine.n >= per_) return false;
  ++global_.n;
  ++mine.n;
  return true;
}

}  // namespace saga::web

#include <doctest/doctest.h>

#include "web/guard.h"

using namespace saga::web;

namespace {

const char* kTok = "0123456789abcdef0123456789abcdef";

Mutation browser_post() {
  Mutation m;
  m.method = "POST";
  m.content_type = "application/json; charset=utf-8";
  m.origin = "http://127.0.0.1:8080";
  m.fetch_site = "same-origin";
  m.body = "{}";
  m.csrf_cookie = kTok;
  m.csrf_header = kTok;
  m.request_origin = "http://127.0.0.1:8080";
  return m;
}

}  // namespace

TEST_CASE("mutations accept a same-origin JSON post and a headerless client") {
  CHECK(check_mutation(browser_post()).ok());

  Mutation curl;
  curl.method = "POST";
  curl.content_type = "application/json";
  curl.body = "{}";
  CHECK(check_mutation(curl).ok());

  Mutation empty;
  empty.method = "POST";
  CHECK(check_mutation(empty).ok());

  Mutation get;
  get.method = "GET";
  get.fetch_site = "cross-site";
  get.origin = "https://evil.example";
  CHECK(check_mutation(get).ok());
}

TEST_CASE("mutations reject a cross-site post, a bad type, and a missing token") {
  Mutation plain = browser_post();
  plain.content_type = "text/plain";
  plain.fetch_site = "cross-site";
  plain.origin = "https://evil.example";
  CHECK(check_mutation(plain).status == 415);

  Mutation site = browser_post();
  site.fetch_site = "CROSS-SITE";
  CHECK(check_mutation(site).status == 403);
  CHECK(check_mutation(site).error.find("cross-site") != std::string::npos);

  Mutation same_site = browser_post();
  same_site.fetch_site = "same-site";
  CHECK(check_mutation(same_site).status == 403);

  Mutation forged = browser_post();
  forged.origin = "https://evil.example";
  forged.expected_origin = "https://saga.example";
  CHECK(check_mutation(forged).status == 403);
  CHECK(check_mutation(forged).error.find("origin") != std::string::npos);

  Mutation bare = browser_post();
  bare.csrf_header.clear();
  const Decision denied = check_mutation(bare);
  CHECK(denied.status == 403);
  CHECK(denied.error.find("reload") != std::string::npos);

  Mutation nav;
  nav.method = "POST";
  nav.fetch_site = "none";
  CHECK(check_mutation(nav).status == 403);
}

TEST_CASE("the public host is the canonical name, plus this machine's own bind") {
  CHECK(content_type_json(" Application/JSON ; charset=utf-8"));
  CHECK_FALSE(content_type_json("text/plain"));

  CHECK(host_allowed("evil.example", "", "127.0.0.1"));
  CHECK_FALSE(host_allowed("evil.example", "https://saga.example", "127.0.0.1"));
  CHECK(host_allowed("saga.example", "https://saga.example", "127.0.0.1"));
  CHECK(host_allowed("Saga.Example:443", "https://saga.example", "127.0.0.1"));
  CHECK_FALSE(host_allowed("example.com", "https://example.com:8443", "127.0.0.1"));
  CHECK(host_allowed("example.com:8443", "https://example.com:8443", "127.0.0.1"));
  CHECK(host_allowed("127.0.0.1:8080", "https://saga.example", "0.0.0.0"));
  CHECK(host_allowed("localhost", "https://saga.example", "0.0.0.0"));
  CHECK(host_allowed("[::1]:8080", "https://saga.example", "::1"));
  CHECK(host_allowed("::1", "https://saga.example", "127.0.0.1"));
  CHECK_FALSE(host_allowed("saga.example/extra", "https://saga.example", "127.0.0.1"));

  const std::string page = security_csp("abc", true);
  CHECK(page.find("frame-ancestors 'none'") != std::string::npos);
  CHECK(page.find("https://esm.sh") != std::string::npos);
  CHECK(page.find("'nonce-abc'") != std::string::npos);
  CHECK(security_csp("", false).find("default-src 'none'") != std::string::npos);
  const std::string html = inject_nonce("<script src=\"/brand.js\"></script><script>1</script>", "abc");
  CHECK(html.find("<script nonce=\"abc\" src=\"/brand.js\">") != std::string::npos);
  CHECK(html.find("<script nonce=\"abc\">1</script>") != std::string::npos);
}

TEST_CASE("slot and rate caps hold for the whole process") {
  Slots slots;
  CHECK(slots.take("a", 2, 3) == 0);
  CHECK(slots.take("a", 2, 3) == 0);
  CHECK(slots.take("b", 2, 3) == 0);
  CHECK(slots.take("b", 2, 3) == 2);
  CHECK(slots.take("a", 2, 3) == 1);
  slots.give("b");
  CHECK(slots.take("c", 2, 3) == 0);

  RateLimiter lim(2, 3);
  CHECK(lim.allow("a"));
  CHECK(lim.allow("a"));
  CHECK(lim.allow("b"));
  CHECK_FALSE(lim.allow("b"));
  CHECK_FALSE(lim.allow("c"));
  CHECK_FALSE(lim.allow("a"));
}

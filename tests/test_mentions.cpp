#include <doctest/doctest.h>

#include "router/mentions.h"

using saga::router::find_handoffs;
using saga::router::split_mentions;

static const std::vector<std::string> kAgents = {"claude", "codex", "grok"};

TEST_CASE("primary + handoff") {
  auto s = split_mentions("build the landing page frontend, then @codex build the API backend", kAgents);
  REQUIRE(s.size() == 2);
  CHECK(s[0].agent == "");
  CHECK(s[0].instruction == "build the landing page frontend");
  CHECK(s[1].agent == "codex");
  CHECK(s[1].instruction == "build the API backend");
}

TEST_CASE("chain of mentions, case-insensitive") {
  auto s = split_mentions("@Claude write hello.html and @codex add server.py. @grok review both", kAgents);
  REQUIRE(s.size() == 3);
  CHECK(s[0].agent == "claude");
  CHECK(s[0].instruction == "write hello.html");
  CHECK(s[1].instruction == "add server.py");
  CHECK(s[2].agent == "grok");
  CHECK(s[2].instruction == "review both");
}

TEST_CASE("emails and unknown handles are plain text") {
  auto s = split_mentions("mail me at me@codex.dev and ping @bob", kAgents);
  REQUIRE(s.size() == 1);
  CHECK(s[0].agent == "");
}

TEST_CASE("bare mention inherits the head instruction") {
  auto s = split_mentions("fix the flaky test @codex", kAgents);
  REQUIRE(s.size() == 2);
  CHECK(s[1].agent == "codex");
  CHECK(s[1].instruction == "fix the flaky test");
}

TEST_CASE("shared instruction for adjacent mentions") {
  auto s = split_mentions("@codex @grok write a haiku", kAgents);
  REQUIRE(s.size() == 2);
  CHECK(s[0].instruction == "write a haiku");
  CHECK(s[1].instruction == "write a haiku");
}

TEST_CASE("handoffs only on their own line") {
  auto h = find_handoffs("Frontend done in index.html.\n@codex build a REST API for /todos\nthanks @grok", kAgents);
  REQUIRE(h.size() == 1);
  CHECK(h[0].agent == "codex");
  CHECK(h[0].instruction == "build a REST API for /todos");
}

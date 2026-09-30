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

TEST_CASE("bare mention takes the head instruction, and the primary doesn't also run it") {
  auto s = split_mentions("fix the flaky test @codex", kAgents);
  REQUIRE(s.size() == 1);
  CHECK(s[0].agent == "codex");
  CHECK(s[0].instruction == "fix the flaky test");
}

TEST_CASE("a greeting and connectives between mentions are not tasks") {
  const std::vector<std::string> agents = {"saga", "claude", "codex", "grok"};
  auto s = split_mentions("hey @saga @claude and @codex, introduce yourself.", agents);
  REQUIRE(s.size() == 3);
  CHECK(s[0].agent == "saga");
  CHECK(s[1].agent == "claude");
  CHECK(s[2].agent == "codex");
  for (auto& x : s) CHECK(x.instruction == "introduce yourself");

  s = split_mentions("hi team: @claude, @codex & @grok say hello", agents);
  REQUIRE(s.size() == 3);
  for (auto& x : s) CHECK(x.instruction == "say hello");

  s = split_mentions("@codex and add tests", agents);
  REQUIRE(s.size() == 1);
  CHECK(s[0].instruction == "add tests");

  s = split_mentions("hey, what's up", agents);  // no mention: the greeting is the message
  REQUIRE(s.size() == 1);
  CHECK(s[0].instruction == "hey, what's up");
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

TEST_CASE("a mention inside a sentence is who it's about, not a handoff") {
  const std::vector<std::string> agents = {"saga", "claude", "codex", "grok"};
  auto s = split_mentions("@grok say hi to @saga", agents);
  REQUIRE(s.size() == 1);
  CHECK(s[0].agent == "grok");
  CHECK(s[0].instruction == "say hi to @saga");

  s = split_mentions("@codex review what @claude wrote, then @grok summarize it", agents);
  REQUIRE(s.size() == 2);
  CHECK(s[0].instruction == "review what @claude wrote");
  CHECK(s[1].agent == "grok");

  s = split_mentions("compare your answer with @codex", agents);  // no one addressed: the primary
  REQUIRE(s.size() == 1);
  CHECK(s[0].agent == "");
  CHECK(s[0].instruction == "compare your answer with @codex");

  s = split_mentions("@claude write the page.\n@codex add the API", agents);  // a new line addresses
  REQUIRE(s.size() == 2);
  CHECK(s[1].agent == "codex");
}

#include <doctest/doctest.h>

#include "harness/prompts.h"

using namespace saga::harness;
using nlohmann::json;

TEST_CASE("playbook ops edit rules in place instead of rewriting") {
  std::vector<Rule> rules = {{"b1", "Use the user's name"}, {"b2", "Answer in bullets"}};
  int next = 3;
  auto out = apply_ops(rules, json::parse(R"([{"op":"edit","id":"b2","text":"Answer in at most 5 bullets"},
                                               {"op":"remove","id":"b1"},
                                               {"op":"add","text":"Say where files were saved"},
                                               {"op":"remove","id":"b99"},
                                               {"op":"bogus"}])"),
                       next);
  REQUIRE(out.size() == 2);
  CHECK(out[0].id == "b2");
  CHECK(out[0].text == "Answer in at most 5 bullets");
  CHECK(out[1].id == "b3");
  CHECK(next == 4);
}

TEST_CASE("playbook size and rule length are capped") {
  std::vector<Rule> rules;
  int next = 1;
  json ops = json::array();
  for (int i = 0; i < 30; ++i) ops.push_back({{"op", "add"}, {"text", std::string(500, 'x')}});
  auto out = apply_ops(rules, ops, next);
  CHECK(out.size() == 20);
  CHECK(out[0].text.size() == 240);
}

TEST_CASE("rendered prompt is the base plus the playbook") {
  CHECK(render_prompt("Base.", {}) == "Base.");
  const auto p = render_prompt("Base.", {{"b1", "Be brief"}});
  CHECK(p.starts_with("Base.\n\nPlaybook"));
  CHECK(p.find("- Be brief") != std::string::npos);
}

TEST_CASE("a rule or lesson is muted only once it hurts more than it helps") {
  CHECK_FALSE(Credit{0, 1}.muted());
  CHECK(Credit{0, 2}.muted());
  CHECK_FALSE(Credit{2, 2}.muted());
  CHECK(Credit{1, 3}.muted());
}

TEST_CASE("the next message is read as feedback on the last answer") {
  CHECK(followup_signal("no, I meant the other file") == -1);
  CHECK(followup_signal("That's wrong, it's Porto not Lisbon") == -1);
  CHECK(followup_signal("still doesn't compile") == -1);
  CHECK(followup_signal("Thanks! now add tests") == 1);
  CHECK(followup_signal("perfect") == 1);
  CHECK(followup_signal("now add tests") == 0);        // "now" is not "no"
  CHECK(followup_signal("notes for tomorrow?") == 0);  // "notes" is not "no"
  CHECK(followup_signal("Plan my week") == 0);
}

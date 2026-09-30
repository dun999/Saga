#include <doctest/doctest.h>

#include <cstdlib>
#include <string>

#include "core/proc.h"

TEST_CASE("agent subprocesses do not inherit server secrets") {
  const char* home = std::getenv("HOME");
  REQUIRE(home != nullptr);
  setenv("MEMWAL_PRIVATE_KEY", "super-secret-delegate", 1);
  setenv("SAGA_SESSION_SECRET", "session-secret", 1);
  setenv("SAGA_ACCESS_CODE", "access-code", 1);

  saga::proc::Options o;
  o.env["SAGA_UID"] = "alice";
  o.env["MEMWAL_PRIVATE_KEY"] = "explicit-must-also-drop";
  auto r = saga::proc::run(
      {"/bin/sh", "-c",
       "printf '%s|%s|%s|%s|%s' \"$MEMWAL_PRIVATE_KEY\" \"$SAGA_SESSION_SECRET\" \"$SAGA_ACCESS_CODE\" "
       "\"$SAGA_UID\" \"$HOME\""},
      o);
  CHECK(r.exit_code == 0);
  CHECK(r.out == "|||alice|" + std::string(home));

  unsetenv("MEMWAL_PRIVATE_KEY");
  unsetenv("SAGA_SESSION_SECRET");
  unsetenv("SAGA_ACCESS_CODE");
}

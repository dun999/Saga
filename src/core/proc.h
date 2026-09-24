#pragma once
// Subprocess runner with line-streamed stdout, timeout and cooperative cancel.
#include <atomic>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace saga::proc {

struct Options {
  std::string cwd;
  std::map<std::string, std::string> env;  // added to / overriding the parent env
  bool inherit_env = true;                 // false: the child sees only `env`
  std::string stdin_data;                  // written then closed; empty => /dev/null
  int timeout_s = 900;
  const std::atomic<bool>* cancel = nullptr;
  std::function<void(const std::string&)> on_stdout_line;
  bool merge_stderr = false;  // deliver stderr through stdout (CLIs that print prompts on stderr)
};

struct Result {
  int exit_code = -1;
  bool timed_out = false;
  bool cancelled = false;
  std::string out, err;
};

Result run(const std::vector<std::string>& argv, const Options& opt = {});

bool on_path(const std::string& exe);

}  // namespace saga::proc

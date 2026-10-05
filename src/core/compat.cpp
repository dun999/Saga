#include "core/compat.h"

#include <climits>
#include <cstdlib>
#include <filesystem>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

namespace saga::compat {

std::string self_exe() {
  std::error_code ec;
#ifdef __APPLE__
  char buf[PATH_MAX];
  uint32_t size = sizeof buf;
  if (_NSGetExecutablePath(buf, &size) != 0) return "";
  return std::filesystem::canonical(buf, ec).string();
#else
  return std::filesystem::canonical("/proc/self/exe", ec).string();
#endif
}

}  // namespace saga::compat

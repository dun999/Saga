cmake_minimum_required(VERSION 3.24)
project(saga VERSION 0.1.0 LANGUAGES CXX)

# C++23: among other things, a range-for keeps its initializer's temporaries alive (P2718).
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

# -DSAGA_SANITIZE=ON: AddressSanitizer + UndefinedBehaviorSanitizer for tests and smoke runs.
option(SAGA_SANITIZE "Build with ASan and UBSan" OFF)
if(SAGA_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
  add_link_options(-fsanitize=address,undefined)
endif()

include(FetchContent)
FetchContent_Declare(json
  URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
  URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
# Commit pins, not moving tags. A shallow clone cannot fetch an arbitrary commit.
FetchContent_Declare(httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG 4f3f9ef19be83ae97a5d9a059432dc00e445b7ab # v0.58.0
  GIT_SHALLOW OFF)
set(HTTPLIB_REQUIRE_OPENSSL OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZSTD_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(json httplib)

find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
find_package(Threads REQUIRED)

# Embed the web pages into the binary so `saga serve` is a single file.
function(saga_embed NAME SRC)
  set(NAMESPACE saga::web)
  if(ARGC GREATER 2)
    set(NAMESPACE ${ARGV2})
  endif()
  set(OUT ${CMAKE_BINARY_DIR}/embedded_${NAME}.cpp)
  add_custom_command(
    OUTPUT ${OUT}
    COMMAND ${CMAKE_COMMAND} -DIN=${SRC} -DOUT=${OUT} -DNAME=${NAME} -DNAMESPACE=${NAMESPACE} -P ${CMAKE_SOURCE_DIR}/cmake/embed.cmake
    DEPENDS ${SRC} ${CMAKE_SOURCE_DIR}/cmake/embed.cmake)
  set(SAGA_EMBEDDED ${SAGA_EMBEDDED} ${OUT} PARENT_SCOPE)
endfunction()
saga_embed(kIndexHtml ${CMAKE_SOURCE_DIR}/src/web/static/index.html)
saga_embed(kLandingHtml ${CMAKE_SOURCE_DIR}/src/web/static/landing.html)
saga_embed(kPrivacyHtml ${CMAKE_SOURCE_DIR}/src/web/static/privacy.html)
saga_embed(kMascotJs ${CMAKE_SOURCE_DIR}/src/web/static/mascot.js)
saga_embed(kBrandJs ${CMAKE_SOURCE_DIR}/src/web/static/brand.js)
saga_embed(kLogoPng ${CMAKE_SOURCE_DIR}/src/web/static/saga-logo.png)
saga_embed(kLlmsTxt ${CMAKE_SOURCE_DIR}/llms.txt)
saga_embed(kSeedPrompt ${CMAKE_SOURCE_DIR}/PROMPT.md saga::harness)

file(GLOB_RECURSE SAGA_LIB_SOURCES CONFIGURE_DEPENDS src/*.cpp)
list(FILTER SAGA_LIB_SOURCES EXCLUDE REGEX ".*/src/main\\.cpp$")
add_library(saga_core STATIC ${SAGA_LIB_SOURCES} ${SAGA_EMBEDDED})
target_include_directories(saga_core PUBLIC src)
target_link_libraries(saga_core PUBLIC
  nlohmann_json::nlohmann_json httplib::httplib CURL::libcurl PkgConfig::SODIUM Threads::Threads)
target_compile_options(saga_core PRIVATE -Wall -Wextra -Wno-missing-field-initializers)

add_executable(saga src/main.cpp)
target_link_libraries(saga PRIVATE saga_core)

# The suite is part of the build. A checkout without tests/ does not configure.
file(GLOB SAGA_TEST_SOURCES CONFIGURE_DEPENDS tests/*.cpp)
if(NOT SAGA_TEST_SOURCES)
  message(FATAL_ERROR "tests/*.cpp is required; refusing to configure without the suite")
endif()
FetchContent_Declare(doctest
  GIT_REPOSITORY https://github.com/doctest/doctest.git
  GIT_TAG 1da23a3e8119ec5cce4f9388e91b065e20bf06f5 # v2.4.12
  GIT_SHALLOW OFF)
FetchContent_MakeAvailable(doctest)
enable_testing()
add_executable(saga_tests ${SAGA_TEST_SOURCES})
target_link_libraries(saga_tests PRIVATE saga_core doctest::doctest)
add_test(NAME saga_tests COMMAND saga_tests)

# Real namespaces and cgroup delegation are required; CI runs this executable separately.
add_executable(saga_sandbox_tests tests/sandbox/integration.cpp)
target_link_libraries(saga_sandbox_tests PRIVATE saga_core doctest::doctest)

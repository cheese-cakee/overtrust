cmake_minimum_required(VERSION 3.16)
project(sentinel VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

# ── FTXUI ──────────────────────────────────────────────────────────────────────
FetchContent_Declare(
  ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
  GIT_TAG        v5.0.0
  GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(ftxui)

# ── nlohmann/json ──────────────────────────────────────────────────────────────
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json
  GIT_TAG        v3.11.3
  GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

# ── yaml-cpp ──────────────────────────────────────────────────────────────────
FetchContent_Declare(
  yaml-cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp
  GIT_TAG        0.8.0
  GIT_SHALLOW    TRUE
)
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS  OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(yaml-cpp)

# ── Sources ───────────────────────────────────────────────────────────────────
file(GLOB_RECURSE SENTINEL_SOURCES
  "src/*.cpp"
  "src/**/*.cpp"
)

add_executable(sentinel ${SENTINEL_SOURCES})

target_include_directories(sentinel PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(sentinel PRIVATE
  ftxui::screen
  ftxui::dom
  ftxui::component
  nlohmann_json::nlohmann_json
  yaml-cpp::yaml-cpp
  pthread
  stdc++fs
)

target_compile_options(sentinel PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  $<$<CONFIG:Release>:-O2>
  $<$<CONFIG:Debug>:-g -O0 -fsanitize=address>
)

target_link_options(sentinel PRIVATE
  $<$<CONFIG:Debug>:-fsanitize=address>
)

cmake_minimum_required(VERSION 3.16)
project(overtrust VERSION 0.1.0 LANGUAGES CXX)

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


# ── Sources ───────────────────────────────────────────────────────────────────
file(GLOB_RECURSE OVERTRUST_SOURCES
  "src/*.cpp"
  "src/**/*.cpp"
)

add_executable(overtrust ${OVERTRUST_SOURCES})

target_include_directories(overtrust PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(overtrust PRIVATE
  ftxui::screen
  ftxui::dom
  ftxui::component
  nlohmann_json::nlohmann_json
  $<$<NOT:$<PLATFORM_ID:Windows>>:pthread>
  $<$<NOT:$<PLATFORM_ID:Windows>>:stdc++fs>
)

# Windows-specific: process/token APIs
if(WIN32)
  target_link_libraries(overtrust PRIVATE Psapi Advapi32 Kernel32)
endif()

# Compiler flags — GCC/Clang only (not MSVC)
if(NOT MSVC)
  target_compile_options(overtrust PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    $<$<CONFIG:Release>:-O2>
    $<$<CONFIG:Debug>:-g -O0 -fsanitize=address>
  )
  target_link_options(overtrust PRIVATE
    $<$<CONFIG:Debug>:-fsanitize=address>
  )
else()
  # MSVC: use /W4, enable standard conformance
  target_compile_options(overtrust PRIVATE
    /W4
    /permissive-
    $<$<CONFIG:Release>:/O2>
    $<$<CONFIG:Debug>:/Od /Zi>
  )
  # UTF-8 source and execution charset (needed for non-ASCII literals)
  target_compile_options(overtrust PRIVATE /utf-8)
endif()

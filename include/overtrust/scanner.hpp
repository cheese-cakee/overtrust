#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <vector>
#include <atomic>

#include "overtrust/types.hpp"

namespace overtrust {

namespace fs = std::filesystem;

// Callbacks the scanner fires as it runs (called from scanner thread)
struct ScanCallbacks {
    // A new file was classified (path, file_type_tag)
    std::function<void(const fs::path&)> on_file;
    // A finding was produced
    std::function<void(Finding)> on_finding;
    // Progress update
    std::function<void(std::size_t scanned, std::size_t total)> on_progress;
    // Scan finished
    std::function<void(int trust_score)> on_complete;
};

// Directories / patterns to skip during filesystem walk
inline const std::vector<std::string> SKIP_DIRS = {
    "node_modules",
    ".git",
    "build",
    "target",
    ".cache",
    "__pycache__",
    ".npm",
    "dist",
    ".next",
    ".nuxt",
    "vendor",
    "Pods",
    ".stack-work",
    "elm-stuff",
    ".gradle",
};

inline bool should_skip(const fs::path& p) {
    std::string name = p.filename().string();
    for (auto& skip : SKIP_DIRS) {
        if (name == skip) return true;
    }
    return false;
}

// Walk a directory tree and return all file paths, skipping noise dirs.
// Fills `out` and updates `total` atomically.
void walk_directory(const fs::path& root,
                    std::vector<fs::path>& out,
                    std::atomic<std::size_t>& total);

} // namespace overtrust

#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <vector>
#include <set>
#include <atomic>
#include <fstream>

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

// Read .overtrustignore or .trustignore from target root.
// Returns directory/file names and path patterns to skip.
inline std::set<std::string> load_ignore_patterns(const fs::path& target_root) {
    std::set<std::string> patterns;
    auto load = [&](const std::string& fname) {
        fs::path p = target_root / fname;
        std::error_code ec;
        if (!fs::exists(p, ec)) return;
        std::ifstream f(p);
        if (!f) return;
        std::string line;
        while (std::getline(f, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
                line.pop_back();
            if (line.empty() || line[0] == '#') continue;
            // Normalize separator
            for (auto& c : line) if (c == '\\') c = '/';
            patterns.insert(line);
        }
    };
    load(".overtrustignore");
    load(".trustignore");
    return patterns;
}

inline bool should_skip(const fs::path& p,
                         const std::set<std::string>& ignore_patterns = {}) {
    std::string name = p.filename().string();
    for (auto& skip : SKIP_DIRS) {
        if (name == skip) return true;
    }
    if (!ignore_patterns.empty()) {
        std::string pathstr = p.generic_string();
        for (auto& pat : ignore_patterns) {
            if (name == pat) return true;
            if (pathstr.find(pat) != std::string::npos) return true;
        }
    }
    return false;
}

// Walk a directory tree and return all file paths, skipping noise dirs.
// Fills `out` and updates `total` atomically.
void walk_directory(const fs::path& root,
                    std::vector<fs::path>& out,
                    std::atomic<std::size_t>& total,
                    const std::set<std::string>& ignore_patterns = {});

} // namespace overtrust

#include <iostream>
#include <string>
#include <thread>
#include <filesystem>
#include <atomic>

// TTY detection — cross-platform
#ifdef _WIN32
#  include <io.h>
#  define IS_TTY() (_isatty(_fileno(stdout)) != 0)
#else
#  include <unistd.h>
#  define IS_TTY() (isatty(STDOUT_FILENO) != 0)
#endif

#include "overtrust/version.hpp"
#include "overtrust/engine.hpp"
#include "tui/app.hpp"

namespace fs = std::filesystem;

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " [TARGET_DIR] [OPTIONS]\n"
        << "\n"
        << "  TARGET_DIR       Directory to scan (default: $HOME)\n"
        << "\n"
        << "  -h, --help       Show this help\n"
        << "  --version        Print version\n"
        << "  --no-tui         Run headless, print findings to stdout (JSON)\n";
}

// ── Headless / JSON output mode (non-TTY or --no-tui) ─────────────────────────
static int run_headless(const std::string& target) {
    // Collect all findings first, then print — avoids interleaved JSON
    std::vector<overtrust::Finding> findings;
    std::mutex findings_mu;
    int final_score = -1;
    std::atomic<bool> done{false};

    overtrust::ScanCallbacks cbs;
    cbs.on_finding = [&](overtrust::Finding f) {
        std::lock_guard<std::mutex> lk(findings_mu);
        findings.push_back(std::move(f));
    };
    cbs.on_progress = [&](std::size_t s, std::size_t t) {
        std::cerr << "\r  scanning " << s << "/" << t << "   ";
    };
    cbs.on_complete = [&](int score) {
        final_score = score;
    };

    overtrust::ScanEngine engine(target, std::move(cbs));
    engine.start();

    // Wait for engine thread to finish
    while (engine.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    std::cerr << "\n";

    // Print JSON output
    std::cout << "{\n"
              << "  \"target\": \"" << target << "\",\n"
              << "  \"trust_score\": " << final_score << ",\n"
              << "  \"findings\": [\n";

    for (std::size_t i = 0; i < findings.size(); ++i) {
        auto& f = findings[i];
        // Escape quotes in strings
        auto esc = [](std::string s) {
            std::string r;
            for (char c : s) {
                if (c == '"')  r += "\\\"";
                else if (c == '\\') r += "\\\\";
                else if (c == '\n') r += "\\n";
                else r += c;
            }
            return r;
        };
        std::cout << "    {"
                  << "\"id\":\"" << esc(f.id) << "\","
                  << "\"rule\":\"" << esc(f.rule_id) << "\","
                  << "\"severity\":\"" << overtrust::severity_str(f.severity) << "\","
                  << "\"score\":" << f.score << ","
                  << "\"file\":\"" << esc(f.file) << "\","
                  << "\"message\":\"" << esc(f.message) << "\","
                  << "\"evidence\":\"" << esc(f.evidence) << "\""
                  << "}";
        if (i + 1 < findings.size()) std::cout << ",";
        std::cout << "\n";
    }

    std::cout << "  ]\n}\n";
    return 0;
}

int main(int argc, char** argv) {
    std::string target;
    bool force_no_tui = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        if (arg == "--version") {
            std::cout << overtrust::APP_NAME << " " << overtrust::VERSION << "\n";
            return 0;
        }
        if (arg == "--no-tui") {
            force_no_tui = true;
            continue;
        }
        target = arg;
    }

    if (target.empty()) {
        const char* home = std::getenv("HOME");
#ifdef _WIN32
        if (!home) home = std::getenv("USERPROFILE");
#endif
        target = home ? home : ".";
    }

    // ── Validate target path ───────────────────────────────────────────────
    std::error_code ec;
    if (!fs::exists(target, ec) || !fs::is_directory(target, ec)) {
        std::cerr << "overtrust: error: \"" << target
                  << "\" is not a valid directory\n";
        return 1;
    }

    // ── Headless mode if not a TTY or --no-tui ─────────────────────────────
    if (force_no_tui || !IS_TTY()) {
        return run_headless(target);
    }

    // ── TUI mode ────────────────────────────────────────────────────────────
    overtrust::tui::App app(target);

    // Throttle on_file callbacks: only push log every 10 files to prevent
    // mutex contention between scanner thread and TUI renderer thread.
    std::atomic<std::size_t> file_counter{0};

    overtrust::ScanCallbacks cbs;
    cbs.on_file = [&](const std::filesystem::path& p) {
        // Always record in counter
        std::size_t n = file_counter.fetch_add(1, std::memory_order_relaxed);
        // Push to log every 10th file to avoid lock contention with renderer
        if (n % 10 == 0) {
            app.push_log(p.filename().string());
        }
    };
    cbs.on_finding  = [&](overtrust::Finding f)            { app.push_finding(std::move(f)); };
    cbs.on_progress = [&](std::size_t s, std::size_t t)   { app.set_progress(s, t); };
    cbs.on_complete = [&](int score)                       { app.set_complete(score); };

    overtrust::ScanEngine engine(target, std::move(cbs));
    app.start_scanning();
    engine.start();

    return app.run();
}

#include <iostream>
#include <string>
#include <thread>

#include "overtrust/version.hpp"
#include "overtrust/engine.hpp"
#include "tui/app.hpp"

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " [TARGET_DIR]\n"
        << "\n"
        << "  TARGET_DIR   Directory to scan (default: $HOME)\n"
        << "\n"
        << "  -h, --help   Show this help\n"
        << "  --version    Print version\n"
        << "  --no-tui     Print findings to stdout (no TUI)\n";
}

int main(int argc, char** argv) {
    std::string target;
    bool no_tui = false;

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
            no_tui = true;
            continue;
        }
        target = arg;
    }

    if (target.empty()) {
        const char* home = std::getenv("HOME");
        target = home ? home : ".";
    }

    // ── TUI mode ─────────────────────────────────────────────────────────────
    overtrust::tui::App app(target);

    // Build scan callbacks that feed the TUI
    overtrust::ScanCallbacks cbs;

    cbs.on_file = [&](const std::filesystem::path& p) {
        app.push_log(p.filename().string());
    };

    cbs.on_finding = [&](overtrust::Finding f) {
        app.push_finding(std::move(f));
    };

    cbs.on_progress = [&](std::size_t scanned, std::size_t total) {
        app.set_progress(scanned, total);
    };

    cbs.on_complete = [&](int trust_score) {
        app.set_complete(trust_score);
    };

    overtrust::ScanEngine engine(target, std::move(cbs));

    // Start scan right away; TUI will show splash until user presses a key
    app.start_scanning();
    engine.start();

    return app.run();
}

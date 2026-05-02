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
        << "  --version    Print version\n";
}

int main(int argc, char** argv) {
    std::string target;

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
        target = arg;
    }

    if (target.empty()) {
        const char* home = std::getenv("HOME");
        target = home ? home : ".";
    }

    overtrust::tui::App app(target);

    overtrust::ScanCallbacks cbs;
    cbs.on_file     = [&](const std::filesystem::path& p) { app.push_log(p.filename().string()); };
    cbs.on_finding  = [&](overtrust::Finding f)            { app.push_finding(std::move(f)); };
    cbs.on_progress = [&](std::size_t s, std::size_t t)   { app.set_progress(s, t); };
    cbs.on_complete = [&](int score)                       { app.set_complete(score); };

    overtrust::ScanEngine engine(target, std::move(cbs));
    app.start_scanning();
    engine.start();

    return app.run();
}

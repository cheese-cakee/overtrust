#include <iostream>
#include <string>

#include "sentinel/version.hpp"
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
            std::cout << sentinel::APP_NAME << " " << sentinel::VERSION << "\n";
            return 0;
        }
        target = arg;
    }

    if (target.empty()) {
        const char* home = std::getenv("HOME");
        target = home ? home : ".";
    }

    sentinel::tui::App app(target);
    return app.run();
}

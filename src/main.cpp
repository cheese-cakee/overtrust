#include <iostream>
#include <string>
#include <thread>
#include <filesystem>
#include <atomic>
#include <mutex>
#include <vector>
#include <csignal>

// TTY detection — cross-platform
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#  define NOMINMAX
#  endif
#  include <io.h>
#  include <windows.h>
#  define IS_TTY() (_isatty(_fileno(stdout)) != 0)
#else
#  include <unistd.h>
#  define IS_TTY() (isatty(STDOUT_FILENO) != 0)
#endif

#include "overtrust/version.hpp"
#include "overtrust/engine.hpp"
#include "overtrust/report.hpp"
#include "overtrust/graph.hpp"
#include "tui/app.hpp"

namespace fs = std::filesystem;

static std::atomic<bool> g_interrupted{false};

#ifdef _WIN32
static BOOL WINAPI win32_ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT) {
        g_interrupted.store(true);
        return TRUE;
    }
    return FALSE;
}
#else
static void posix_signal_handler(int) {
    g_interrupted.store(true);
}
#endif

static void install_signal_handler() {
#ifdef _WIN32
    SetConsoleCtrlHandler(win32_ctrl_handler, TRUE);
#else
    std::signal(SIGINT, posix_signal_handler);
    std::signal(SIGTERM, posix_signal_handler);
#endif
}

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " [TARGET_DIR] [OPTIONS]\n"
        << "\n"
        << "  TARGET_DIR            Directory to scan (default: $HOME)\n"
        << "\n"
        << "  -h, --help            Show this help\n"
        << "  --version             Print version\n"
        << "  --no-tui              Run headless, print findings to stdout (JSON)\n"
        << "  --report <file.json>  Write full JSON report to file after scan\n"
        << "  --exit-code           Exit with code 1 if any findings are detected\n";
}

// ── Shared scan runner ─────────────────────────────────────────────────────────

struct ScanResult {
    std::vector<overtrust::Finding> findings;
    int trust_score = -1;
};

// ── Headless / JSON output mode ────────────────────────────────────────────────
static int run_headless(const std::string& target, const std::string& report_path,
                        bool exit_code_flag) {
    ScanResult result;
    std::mutex findings_mu;

    overtrust::ScanCallbacks cbs;
    cbs.on_finding = [&](overtrust::Finding f) {
        std::lock_guard<std::mutex> lk(findings_mu);
        result.findings.push_back(std::move(f));
    };
    cbs.on_progress = [&](std::size_t s, std::size_t t) {
        std::cerr << "\r  scanning " << s << "/" << t << "   ";
    };
    cbs.on_complete = [&](int score) {
        result.trust_score = score;
    };

    overtrust::ScanEngine engine(target, std::move(cbs));
    engine.start();

    while (engine.is_running()) {
        if (g_interrupted.load()) {
            engine.stop();
            std::cerr << "\n  interrupted\n";
            return 130;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    std::cerr << "\n";

    // ── stdout JSON ────────────────────────────────────────────────────────
    // Escape all characters that are invalid inside a JSON string.
    // The previous version only handled ", \, \n, \r — leaving tabs and
    // other control characters (0x00-0x1F) unescaped, which produces
    // invalid JSON when file paths or evidence strings contain them.
    auto esc = [](const std::string& s) {
        std::string r;
        r.reserve(s.size());
        for (unsigned char c : s) {
            if      (c == '"')  r += "\\\"";
            else if (c == '\\') r += "\\\\";
            else if (c == '\n') r += "\\n";
            else if (c == '\r') r += "\\r";
            else if (c == '\t') r += "\\t";
            else if (c < 0x20) {
                // Other control characters: \u00XX
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                r += buf;
            } else {
                r += static_cast<char>(c);
            }
        }
        return r;
    };

    std::cout << "{\n"
              << "  \"target\": \""      << esc(target)               << "\",\n"
              << "  \"trust_score\": "   << result.trust_score         << ",\n"
              << "  \"findings\": [\n";

    for (std::size_t i = 0; i < result.findings.size(); ++i) {
        auto& f = result.findings[i];
        std::cout << "    {"
                  << "\"id\":\""       << esc(f.id)                           << "\","
                  << "\"rule\":\""     << esc(f.rule_id)                      << "\","
                  << "\"severity\":\"" << overtrust::severity_str(f.severity) << "\","
                  << "\"score\":"      << f.score                             << ","
                  << "\"file\":\""     << esc(f.file)                         << "\","
                  << "\"message\":\""  << esc(f.message)                      << "\","
                  << "\"evidence\":\"" << esc(f.evidence)                     << "\""
                  << "}";
        if (i + 1 < result.findings.size()) std::cout << ",";
        std::cout << "\n";
    }
    std::cout << "  ]\n}\n";

    // ── optional full report ───────────────────────────────────────────────
    if (!report_path.empty()) {
        auto graph = overtrust::build_trust_graph(result.findings);
        if (overtrust::write_json_report(report_path, result.findings,
                                          graph, result.trust_score, target)) {
            std::cerr << "  report written to " << report_path << "\n";
        } else {
            std::cerr << "  warning: could not write report to " << report_path << "\n";
        }
    }

    if (exit_code_flag && !result.findings.empty()) return 1;
    return 0;
}

int main(int argc, char** argv) {
    install_signal_handler();

    std::string target;
    std::string report_path;
    bool force_no_tui = false;
    bool exit_code_flag = false;

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
        if (arg == "--exit-code") {
            exit_code_flag = true;
            continue;
        }
        if (arg == "--report") {
            if (i + 1 >= argc) {
                std::cerr << "overtrust: error: --report requires a file path argument\n";
                return 1;
            }
            report_path = argv[++i];
            continue;
        }
        if (arg.substr(0, 2) != "--") {
            target = arg;
        } else {
            std::cerr << "overtrust: warning: unknown option '" << arg << "' (ignored)\n";
        }
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
        return run_headless(target, report_path, exit_code_flag);
    }

#ifdef _WIN32
    // Enable VT100/ANSI escape sequence processing on Windows Console.
    // Without this, FTXUI's escape codes print as literal text instead of
    // rendering the TUI. Requires Windows 10 1511+ (build 10586).
    // If it fails (older Windows or redirected handle), fall back to headless.
    {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        HANDLE hIn  = GetStdHandle(STD_INPUT_HANDLE);
        DWORD outMode = 0, inMode = 0;
        bool vt_ok = false;
        if (hOut != INVALID_HANDLE_VALUE && hIn != INVALID_HANDLE_VALUE &&
            GetConsoleMode(hOut, &outMode) && GetConsoleMode(hIn, &inMode))
        {
            outMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            inMode  |= ENABLE_VIRTUAL_TERMINAL_INPUT;
            if (SetConsoleMode(hOut, outMode) && SetConsoleMode(hIn, inMode)) {
                vt_ok = true;
            }
        }
        if (!vt_ok) {
            // Console doesn't support VT — fall back to headless JSON output
            return run_headless(target, report_path, exit_code_flag);
        }
    }
#endif

    // ── TUI mode ────────────────────────────────────────────────────────────
    overtrust::tui::App app(target);
    int final_ret = 0;
    bool first_run = true;

    do {
        if (!first_run) {
            app.reset();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        first_run = false;

        std::atomic<std::size_t> file_counter{0};
        std::vector<overtrust::Finding> collected_findings;
        std::mutex collected_mu;
        int final_score = -1;

        overtrust::ScanCallbacks cbs;
        cbs.on_file = [&](const std::filesystem::path& p) {
            std::size_t n = file_counter.fetch_add(1, std::memory_order_relaxed);
            if (n % 10 == 0) app.push_log(p.filename().string());
        };
        cbs.on_finding = [&](overtrust::Finding f) {
            {
                std::lock_guard<std::mutex> lk(collected_mu);
                collected_findings.push_back(f);
            }
            app.push_finding(std::move(f));
        };
        cbs.on_progress = [&](std::size_t s, std::size_t t) { app.set_progress(s, t); };
        cbs.on_complete = [&](int score) {
            final_score = score;
            app.set_complete(score);
        };

        overtrust::ScanEngine engine(target, std::move(cbs));
        app.start_scanning();
        engine.start();

        app.run();

        // Handle Ctrl+C during TUI
        if (g_interrupted.load()) {
            engine.stop();
            final_ret = 130;
            break;
        }

        // ── Export result on 'e' key ───────────────────────────────────────
        if (app.export_requested()) {
            auto& findings = collected_findings;
            auto graph = overtrust::build_trust_graph(findings);
            int score = final_score >= 0 ? final_score : app.trust_score();
            std::string path = app.export_path();
            if (path.empty()) path = "overtrust-report.json";
            if (overtrust::write_json_report(path, findings, graph, score, target)) {
                std::cerr << "report written to " << path << "\n";
            } else {
                std::cerr << "warning: could not write report to " << path << "\n";
            }
        }

        // ── Write --report file after TUI exits ────────────────────────────
        if (!report_path.empty()) {
            auto graph = overtrust::build_trust_graph(collected_findings);
            if (overtrust::write_json_report(report_path, collected_findings,
                                              graph, final_score, target)) {
                std::cerr << "report written to " << report_path << "\n";
            } else {
                std::cerr << "warning: could not write report to " << report_path << "\n";
            }
        }

        // Set exit code based on findings if --exit-code was passed
        if (exit_code_flag && !collected_findings.empty()) {
            final_ret = 1;
        }

    } while (app.rescan_requested() && !g_interrupted.load());

    return final_ret;
}

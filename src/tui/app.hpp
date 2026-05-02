#pragma once

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

#include "overtrust/types.hpp"
#include "tui/colors.hpp"
#include "tui/splash.hpp"
#include "tui/widgets.hpp"
#include "tui/graph_view.hpp"

namespace overtrust::tui {

using namespace ftxui;

class App {
public:
    explicit App(std::string scan_target)
        : target_(std::move(scan_target)) {}

    // Called by scanner thread to push data in
    void push_log(const std::string& line) {
        std::lock_guard<std::mutex> lk(mu_);
        state_.log_lines.push_back(line);
        if (state_.log_lines.size() > 500)
            state_.log_lines.erase(state_.log_lines.begin());
    }

    void push_finding(Finding f) {
        std::lock_guard<std::mutex> lk(mu_);
        state_.findings.push_back(std::move(f));
    }

    void set_progress(std::size_t scanned, std::size_t total) {
        std::lock_guard<std::mutex> lk(mu_);
        state_.files_scanned = scanned;
        state_.files_total   = total;
    }

    void set_complete(int trust_score) {
        std::lock_guard<std::mutex> lk(mu_);
        state_.trust_score = trust_score;
        state_.complete    = true;
        scanning_.store(false);
    }

    void start_scanning() { scanning_.store(true); }

    int run() {
        auto screen = ScreenInteractive::Fullscreen();
        screen_ = &screen;

        // Refresh loop: update screen every ~100ms so live progress shows
        std::thread refresh_thread([&] {
            while (!exit_flag_.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                screen.PostEvent(Event::Custom);
            }
        });

        bool show_splash    = true;
        bool show_help      = false;
        bool show_graph     = false;
        int  selected_idx   = 0;

        auto component = CatchEvent(Renderer([&]() -> Element {
            std::lock_guard<std::mutex> lk(mu_);

            // ── Splash screen ──────────────────────────────────────────
            if (show_splash) {
                return render_splash() | center;
            }

            // ── Build snapshot of state ────────────────────────────────
            const auto& findings = state_.findings;
            const bool  scanning = scanning_.load();
            const int   score    = state_.trust_score;
            const auto  scanned  = state_.files_scanned;
            const auto  total    = state_.files_total;

            // Clamp selection
            if (!findings.empty() && selected_idx >= (int)findings.size())
                selected_idx = (int)findings.size() - 1;

            // ── Compute summary ────────────────────────────────────────
            ScanSummary summary;
            summary.total_files = total;
            summary.trust_score = score;
            for (auto& f : findings) {
                switch (f.severity) {
                    case Severity::Critical: ++summary.critical; break;
                    case Severity::High:     ++summary.high;     break;
                    case Severity::Medium:   ++summary.medium;   break;
                    case Severity::Low:      ++summary.low;      break;
                    default:                 ++summary.info;     break;
                }
            }

            // ── Top bar ────────────────────────────────────────────────
            auto top_bar = hbox({
                text(" OVERTRUST ") | bold | color(COLOR_ACCENT),
                text("│") | dim,
                trust_score_bar(score, scanning),
                filler(),
                summary_bar(summary),
                text(" │ ") | dim,
                text("? help") | dim,
            }) | border;

            // ── Left panel: scan log ───────────────────────────────────
            std::vector<Element> log_elems;
            // Show most recent lines (last 40)
            std::size_t start = (state_.log_lines.size() > 40)
                              ? state_.log_lines.size() - 40 : 0;
            for (std::size_t i = start; i < state_.log_lines.size(); ++i) {
                log_elems.push_back(
                    text(state_.log_lines[i]) | dim
                );
            }
            if (scanning) {
                std::string progress = std::to_string(scanned);
                if (total > 0) progress += "/" + std::to_string(total);
                log_elems.push_back(
                    hbox({ text("⟳ ") | color(COLOR_ACCENT), text(progress) | bold })
                );
            } else if (state_.complete) {
                log_elems.push_back(text("✓ Scan complete") | color(COLOR_LOW) | bold);
            }
            auto left_panel = window(
                text(" Scan Log "),
                vbox(std::move(log_elems)) | yframe
            );

            // ── Center panel: graph / status ───────────────────────────
            Element center_panel;
            if (show_graph) {
                center_panel = window(
                    text(" Trust Graph [v=toggle] "),
                    render_graph_visual(findings, 80, 30)
                );
            } else {
                center_panel = window(
                    text(" Overview [v=graph] "),
                    vbox({
                        render_overview(findings, score, scanning),
                        separator(),
                        render_graph_compact(findings),
                    })
                );
            }

            // ── Right panel: findings list ────────────────────────────
            std::vector<Element> finding_rows;
            if (findings.empty()) {
                finding_rows.push_back(
                    text("  No findings yet...") | dim | center
                );
            }
            for (int i = 0; i < (int)findings.size(); ++i) {
                finding_rows.push_back(finding_row(findings[i], i == selected_idx));
            }
            auto right_panel = window(
                text(" Findings (" + std::to_string(findings.size()) + ") "),
                vbox(std::move(finding_rows)) | yframe
            );

            // ── Bottom panel: detail ──────────────────────────────────
            Element bottom_panel;
            if (!findings.empty() && selected_idx < (int)findings.size()) {
                bottom_panel = window(
                    text(" Detail "),
                    finding_detail(findings[selected_idx])
                );
            } else {
                bottom_panel = window(
                    text(" Detail "),
                    text("  Select a finding with ↑↓, press Enter to expand") | dim
                );
            }

            // ── Main layout ───────────────────────────────────────────
            auto main_area = hbox({
                left_panel  | flex_shrink | size(WIDTH, EQUAL, 32),
                center_panel | flex,
                right_panel  | flex_shrink | size(WIDTH, EQUAL, 40),
            });

            auto layout = vbox({
                top_bar,
                main_area | flex,
                bottom_panel | size(HEIGHT, EQUAL, 9),
            });

            // ── Help overlay ──────────────────────────────────────────
            if (show_help) {
                return dbox({
                    layout,
                    help_overlay() | center,
                });
            }

            return layout;
        }),
        [&](Event ev) -> bool {
            if (show_splash) {
                if (ev == Event::Character('q')) {
                    exit_flag_.store(true);
                    screen.ExitLoopClosure()();
                    return true;
                }
                // Any other key dismisses splash
                if (ev.is_character() || ev == Event::Return) {
                    show_splash = false;
                    return true;
                }
                return false;
            }

            if (ev == Event::Character('q')) {
                exit_flag_.store(true);
                screen.ExitLoopClosure()();
                return true;
            }
            if (ev == Event::Character('?')) { show_help = !show_help; return true; }
            if (ev == Event::Character('v')) { show_graph = !show_graph; return true; }

            // Navigation
            {
                std::lock_guard<std::mutex> lk(mu_);
                int n = (int)state_.findings.size();
                if (ev == Event::ArrowDown || ev == Event::Character('j')) {
                    if (selected_idx < n - 1) ++selected_idx;
                    return true;
                }
                if (ev == Event::ArrowUp || ev == Event::Character('k')) {
                    if (selected_idx > 0) --selected_idx;
                    return true;
                }
            }

            return false;
        });

        screen.Loop(component);

        exit_flag_.store(true);
        refresh_thread.join();
        return 0;
    }

private:
    // ── Internal renderers ─────────────────────────────────────────────────

    static Element render_overview(const std::vector<Finding>& findings,
                                   int /*score*/, bool scanning) {
        if (scanning && findings.empty()) {
            return vbox({
                filler(),
                text("  Scanning...") | color(COLOR_ACCENT) | bold | center,
                filler(),
            });
        }

        // Count by severity
        int crit=0, high=0, med=0, low=0;
        for (auto& f : findings) {
            switch (f.severity) {
                case Severity::Critical: ++crit; break;
                case Severity::High:     ++high; break;
                case Severity::Medium:   ++med;  break;
                case Severity::Low:      ++low;  break;
                default: break;
            }
        }

        return vbox({
            text("") ,
            hbox({ text("  ● ") | color(COLOR_CRITICAL), text(std::to_string(crit) + " critical") | bold }),
            hbox({ text("  ● ") | color(COLOR_HIGH),     text(std::to_string(high) + " high") | bold }),
            hbox({ text("  ● ") | color(COLOR_MEDIUM),   text(std::to_string(med)  + " medium") | bold }),
            hbox({ text("  ● ") | color(COLOR_LOW),      text(std::to_string(low)  + " low") | bold }),
            separator(),
            text("  Press v for graph view") | dim,
        });
    }

    // ── Members ────────────────────────────────────────────────────────────
    std::string target_;
    ScanState   state_;
    std::mutex  mu_;
    std::atomic<bool> scanning_{false};
    std::atomic<bool> exit_flag_{false};
    ScreenInteractive* screen_ = nullptr;
};

} // namespace overtrust::tui

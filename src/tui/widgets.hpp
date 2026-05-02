#pragma once

#include <ftxui/dom/elements.hpp>
#include <string>
#include <cmath>
#include "overtrust/types.hpp"
#include "tui/colors.hpp"

namespace overtrust::tui {

using namespace ftxui;

// ── Trust score bar ──────────────────────────────────────────────────────────

inline Element trust_score_bar(int score, bool scanning) {
    if (score < 0 || scanning) {
        // Show spinner / "scanning" state
        static int tick = 0;
        ++tick;
        const char* spinners[] = {"⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"};
        std::string spinner = spinners[tick % 10];
        return hbox({
            text(" Trust Score: ") | bold,
            text(" " + spinner + " SCANNING...") | color(COLOR_ACCENT) | bold,
        });
    }

    const int bar_width = 24;
    int filled = (score * bar_width) / 100;
    std::string bar;
    for (int i = 0; i < bar_width; ++i) {
        bar += (i < filled) ? "█" : "░";
    }

    const char* label = score >= 80 ? "TRUSTED"
                      : score >= 50 ? "MODERATE"
                      : score >= 25 ? "HIGH RISK"
                      :               "CRITICAL";

    Color c = score_color(score);

    return hbox({
        text(" Trust Score: ") | bold,
        text(std::to_string(score) + "/100 ") | color(c) | bold,
        text("[") | dim,
        text(bar) | color(c),
        text("] ") | dim,
        text(label) | color(c) | bold,
    });
}

// ── Finding row (for the right panel list) ──────────────────────────────────

inline Element finding_row(const Finding& f, bool selected) {
    Color c = severity_color(f.severity);
    std::string score_str = std::to_string(static_cast<int>(f.score * 10) / 10);

    auto row = hbox({
        text(std::string("[") + severity_str(f.severity) + "] ") | color(c) | bold,
        text(f.message.substr(0, 35)) | (selected ? bold : dim),
        filler(),
        text(" [" + std::to_string((int)f.score) + "] ") | color(c),
    });

    if (selected)
        return row | inverted;
    return row;
}

// ── Detail panel for a finding ───────────────────────────────────────────────

inline Element finding_detail(const Finding& f) {
    Color c = severity_color(f.severity);
    return vbox({
        hbox({ text("Rule: ") | bold, text(f.rule_id) | color(COLOR_ACCENT) }),
        hbox({ text("File: ") | bold, text(f.file) | dim }),
        hbox({ text("Severity: ") | bold, text(severity_str(f.severity)) | color(c) | bold }),
        hbox({ text("Score: ") | bold, text(std::to_string((int)f.score)) | color(c) }),
        separator(),
        text(f.message),
        separator(),
        paragraph(f.evidence) | dim,
    });
}

// ── Summary stats bar ────────────────────────────────────────────────────────

inline Element summary_bar(const ScanSummary& s) {
    return hbox({
        text(" Files: ") | dim,
        text(std::to_string(s.total_files)) | bold,
        text("  "),
        text("CRIT:") | dim,
        text(std::to_string(s.critical)) | color(COLOR_CRITICAL) | bold,
        text(" HIGH:") | dim,
        text(std::to_string(s.high)) | color(COLOR_HIGH) | bold,
        text(" MED:") | dim,
        text(std::to_string(s.medium)) | color(COLOR_MEDIUM) | bold,
        text(" LOW:") | dim,
        text(std::to_string(s.low)) | color(COLOR_LOW) | bold,
    });
}

// ── Help overlay ─────────────────────────────────────────────────────────────

inline Element help_overlay() {
    return vbox({
        text("  Keybindings  ") | bold | center,
        separator(),
        text("  ↑ / k    Previous finding"),
        text("  ↓ / j    Next finding"),
        text("  Enter    Expand detail"),
        text("  v        Toggle graph view"),
        text("  r        Re-scan"),
        text("  e        Export JSON report"),
        text("  ?        Toggle this help"),
        text("  q        Quit"),
    }) | border | color(COLOR_ACCENT);
}

} // namespace overtrust::tui

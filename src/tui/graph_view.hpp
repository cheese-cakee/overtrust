#pragma once

#include <ftxui/dom/elements.hpp>
#include <ftxui/dom/canvas.hpp>
#include <vector>
#include <string>
#include <cmath>
#include <algorithm>

#include "overtrust/types.hpp"
#include "tui/colors.hpp"

namespace overtrust::tui {

using namespace ftxui;

// ── Compact tree-style graph (always visible) ────────────────────────────────

inline Element render_graph_compact(const std::vector<Finding>& findings) {
    if (findings.empty()) {
        return vbox({
            filler(),
            text("  No findings yet") | dim | center,
            filler(),
        });
    }

    std::vector<Element> rows;
    rows.push_back(
        hbox({ text("  [") | dim, text("SYSTEM") | bold | color(COLOR_ACCENT), text("]") | dim })
    );

    // Group by severity for the tree
    auto by_sev = findings; // copy
    std::stable_sort(by_sev.begin(), by_sev.end(), [](const Finding& a, const Finding& b) {
        return static_cast<int>(a.severity) > static_cast<int>(b.severity);
    });

    std::size_t limit = std::min(by_sev.size(), std::size_t(12));
    for (std::size_t i = 0; i < limit; ++i) {
        auto& f = by_sev[i];
        Color c = severity_color(f.severity);
        bool last = (i + 1 == limit);

        std::string prefix = last ? "  └── " : "  ├── ";
        std::string label  = f.message.size() > 30
                           ? f.message.substr(0, 27) + "..."
                           : f.message;

        rows.push_back(
            hbox({
                text(prefix) | dim,
                text("[") | dim,
                text(severity_str(f.severity)) | color(c) | bold,
                text("] ") | dim,
                text(label) | color(c),
            })
        );
    }

    if (by_sev.size() > limit) {
        rows.push_back(
            text("       ... " + std::to_string(by_sev.size() - limit) + " more findings") | dim
        );
    }

    rows.push_back(separator());
    rows.push_back(
        hbox({
            text("  Nodes: ") | dim,
            text(std::to_string(findings.size() + 1)) | bold,
            text("  Press ") | dim,
            text("v") | bold | color(COLOR_ACCENT),
            text(" for visual graph") | dim,
        })
    );

    return vbox(std::move(rows));
}

// ── Visual Canvas graph ──────────────────────────────────────────────────────
// Lays out nodes in a simple spoke layout around a central "system" node.

struct NodePos { float x, y; };

inline Element render_graph_visual(const std::vector<Finding>& findings,
                                    int canvas_w, int canvas_h) {
    auto c = Canvas(canvas_w, canvas_h);

    if (findings.empty()) {
        c.DrawText(canvas_w/2 - 8, canvas_h/2, "No findings to display");
        return canvas(std::move(c));
    }

    // Central node
    int cx = canvas_w / 2;
    int cy = canvas_h / 2;
    c.DrawText(cx - 4, cy, "[SYSTEM]", [](Pixel& p){ p.bold = true; p.foreground_color = Color::Cyan; });

    // Spoke layout — up to 10 outer nodes
    std::size_t limit = std::min(findings.size(), std::size_t(10));
    float radius_x = canvas_w * 0.35f;
    float radius_y = canvas_h * 0.38f;

    for (std::size_t i = 0; i < limit; ++i) {
        auto& f = findings[i];
        float angle = (2.0f * 3.14159f * i) / (float)limit;
        int nx = cx + static_cast<int>(radius_x * std::cos(angle));
        int ny = cy + static_cast<int>(radius_y * std::sin(angle));

        // Draw line from center to node
        c.DrawPointLine(cx, cy, nx, ny, severity_color(f.severity));

        // Node box (truncated label)
        std::string label = f.message.size() > 14
                          ? f.message.substr(0, 11) + "..."
                          : f.message;
        Color col = severity_color(f.severity);
        c.DrawText(std::max(0, nx - (int)label.size()/2), std::max(0, ny), label,
                   [col](Pixel& p){ p.foreground_color = col; p.bold = true; });
    }

    return canvas(std::move(c));
}

} // namespace overtrust::tui

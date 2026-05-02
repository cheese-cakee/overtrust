#pragma once

#include <ftxui/screen/color.hpp>
#include "sentinel/types.hpp"

namespace sentinel::tui {

using ftxui::Color;

// Risk palette (inline const — Color is not a literal type in FTXUI v5)
inline const Color COLOR_CRITICAL = Color::Red;
inline const Color COLOR_HIGH     = Color::RGB(219, 109, 40);  // orange
inline const Color COLOR_MEDIUM   = Color::Yellow;
inline const Color COLOR_LOW      = Color::RGB(63, 185, 80);   // green
inline const Color COLOR_INFO     = Color::GrayLight;
inline const Color COLOR_DIM      = Color::GrayDark;
inline const Color COLOR_ACCENT   = Color::Cyan;

inline Color severity_color(Severity s) {
    switch (s) {
        case Severity::Critical: return COLOR_CRITICAL;
        case Severity::High:     return COLOR_HIGH;
        case Severity::Medium:   return COLOR_MEDIUM;
        case Severity::Low:      return COLOR_LOW;
        case Severity::Info:     return COLOR_INFO;
    }
    return COLOR_INFO;
}

// Trust score → color
inline Color score_color(int score) {
    if (score >= 80) return COLOR_LOW;
    if (score >= 50) return COLOR_MEDIUM;
    if (score >= 25) return COLOR_HIGH;
    return COLOR_CRITICAL;
}

} // namespace sentinel::tui

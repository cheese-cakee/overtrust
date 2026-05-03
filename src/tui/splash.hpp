#pragma once

#include <ftxui/dom/elements.hpp>
#include <string>
#include "overtrust/version.hpp"

namespace overtrust::tui {

// Big ASCII art for the splash / top-bar logo
inline const char* BANNER[] = {
    " ██████╗ ██╗   ██╗███████╗██████╗ ████████╗██████╗ ██╗   ██╗███████╗████████╗",
    "██╔═══██╗██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝",
    "██║   ██║██║   ██║█████╗  ██████╔╝   ██║   ██████╔╝██║   ██║███████╗   ██║   ",
    "██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══██╗██║   ██║╚════██║   ██║   ",
    "╚██████╔╝ ╚████╔╝ ███████╗██║  ██║   ██║   ██║  ██║╚██████╔╝███████║   ██║   ",
    " ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝  ",
};
constexpr std::size_t BANNER_LINES = 6;

inline ftxui::Element render_splash() {
    using namespace ftxui;
    std::vector<Element> lines;
    for (std::size_t i = 0; i < BANNER_LINES; ++i) {
        lines.push_back(text(BANNER[i]) | color(Color::Cyan) | bold);
    }
    lines.push_back(separator());
    lines.push_back(
        text("  AI-era workstation security scanner  ·  v" + std::string(overtrust::VERSION) + "  ·  MIT")
        | color(Color::GrayLight)
    );
    lines.push_back(filler());
    lines.push_back(
        hbox({
            text("  ") ,
            text("Press ") | dim,
            text("any key") | bold,
            text(" to start scanning, or ") | dim,
            text("q") | bold | color(Color::Red),
            text(" to quit") | dim,
        })
    );
    return vbox(std::move(lines)) | border | color(Color::Cyan);
}

} // namespace overtrust::tui

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include "sentinel/version.hpp"

int main() {
    using namespace ftxui;

    auto screen = ScreenInteractive::Fullscreen();

    auto quit_btn = Button("Quit", screen.ExitLoopClosure());

    auto renderer = Renderer(quit_btn, [&] {
        return vbox({
                   text("SENTINEL v" + std::string(sentinel::VERSION)) | bold | color(Color::Cyan),
                   text(sentinel::DESCRIPTION) | dim,
                   separator(),
                   quit_btn->Render() | center,
               }) |
               border | center;
    });

    screen.Loop(renderer);
    return 0;
}

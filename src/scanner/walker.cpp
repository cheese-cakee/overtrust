#include "overtrust/scanner.hpp"

#include <system_error>

namespace overtrust {

void walk_directory(const fs::path& root,
                    std::vector<fs::path>& out,
                    std::atomic<std::size_t>& total,
                    const std::set<std::string>& ignore_patterns)
{
    std::error_code ec;

    // Use recursive_directory_iterator with skip_permission_denied
    fs::recursive_directory_iterator it(
        root,
        fs::directory_options::skip_permission_denied,
        ec
    );
    if (ec) return; // can't open root at all

    fs::recursive_directory_iterator end;

    for (; it != end; it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }

        auto& entry = *it;

        // Skip symlinks to avoid cycles
        if (fs::is_symlink(entry.path(), ec)) {
            it.disable_recursion_pending();
            continue;
        }

        if (fs::is_directory(entry.status(ec))) {
            if (should_skip(entry.path(), ignore_patterns)) {
                it.disable_recursion_pending();
            }
            continue;
        }

        if (fs::is_regular_file(entry.status(ec))) {
            out.push_back(entry.path());
            total.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

} // namespace overtrust

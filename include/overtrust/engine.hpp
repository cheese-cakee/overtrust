#pragma once

#include <string>
#include <thread>
#include <functional>
#include <vector>
#include <atomic>
#include <mutex>

#include "overtrust/types.hpp"
#include "overtrust/scanner.hpp"

namespace overtrust {

// The ScanEngine runs in its own thread, walks the target directory,
// classifies files, detects secrets, scores manifests, scans processes,
// and fires callbacks into the TUI (App).

class ScanEngine {
public:
    explicit ScanEngine(std::string target, ScanCallbacks cbs)
        : target_(std::move(target)), callbacks_(std::move(cbs)) {}

    ~ScanEngine() {
        if (thread_.joinable()) thread_.join();
    }

    // Start scanning in background thread
    void start() {
        running_.store(true);   // set BEFORE spawning thread to avoid is_running() race
        thread_ = std::thread([this] { run(); });
    }

    void stop() { stop_.store(true); }

    bool is_running() const { return running_.load(); }

private:
    void run();

    std::string      target_;
    ScanCallbacks    callbacks_;
    std::thread      thread_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> running_{false};
};

} // namespace overtrust

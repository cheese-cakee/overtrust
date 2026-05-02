#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace sentinel {

// ── Severity ────────────────────────────────────────────────────────────────

enum class Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
};

inline const char* severity_str(Severity s) {
    switch (s) {
        case Severity::Info:     return "INFO";
        case Severity::Low:      return "LOW";
        case Severity::Medium:   return "MED";
        case Severity::High:     return "HIGH";
        case Severity::Critical: return "CRIT";
    }
    return "?";
}

// ── Finding ──────────────────────────────────────────────────────────────────

struct Finding {
    std::string id;
    std::string rule_id;
    Severity    severity = Severity::Info;
    std::string file;
    std::string message;
    double      score    = 0.0;
    std::string evidence; // short snippet
};

// ── Scan State (shared between scanner thread and TUI) ─────────────────────

struct ScanState {
    // live stats
    std::size_t files_total   = 0;
    std::size_t files_scanned = 0;
    bool        complete      = false;

    // findings
    std::vector<Finding> findings;

    // trust score 0-100 (computed after scan)
    int trust_score = -1; // -1 = not yet computed

    // log lines (left panel scroll)
    std::vector<std::string> log_lines;
};

// ── Scan Summary ─────────────────────────────────────────────────────────────

struct ScanSummary {
    std::size_t total_files  = 0;
    int         critical     = 0;
    int         high         = 0;
    int         medium       = 0;
    int         low          = 0;
    int         info         = 0;
    int         trust_score  = 100;
};

} // namespace sentinel

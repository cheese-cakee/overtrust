#pragma once

#include <string>
#include <vector>
#include "sentinel/types.hpp"

namespace sentinel {

// ── Secret match ─────────────────────────────────────────────────────────────

struct SecretMatch {
    std::string pattern_name; // e.g. "AWS Access Key ID"
    std::string rule_id;      // e.g. "SEC-001"
    std::string matched;      // redacted: first 8 chars + "..."
    std::size_t line_number;
    double      score;
    Severity    severity;
};

// ── Main entry points ─────────────────────────────────────────────────────────

// Scan file content for secrets; returns all matches
std::vector<SecretMatch> scan_for_secrets(const std::string& content,
                                           const std::string& filepath);

// Convert SecretMatch → Finding
Finding secret_to_finding(const SecretMatch& m, const std::string& file);

// Shannon entropy of a byte span [0, 8]
double shannon_entropy(const std::string& s);

} // namespace sentinel

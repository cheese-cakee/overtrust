#include "overtrust/secrets.hpp"

#include <regex>
#include <sstream>
#include <cmath>
#include <algorithm>
#include <unordered_set>

namespace overtrust {

// ── Shannon entropy ───────────────────────────────────────────────────────────

double shannon_entropy(const std::string& s) {
    if (s.empty()) return 0.0;

    unsigned char counts[256] = {};
    for (unsigned char c : s) ++counts[c];

    double entropy = 0.0;
    double len = static_cast<double>(s.size());
    for (int i = 0; i < 256; ++i) {
        if (counts[i] == 0) continue;
        double p = counts[i] / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// ── False positive guard ──────────────────────────────────────────────────────

static const std::unordered_set<std::string> FALSE_POSITIVE_TOKENS = {
    "example", "dummy", "test123", "your-key-here", "xxxxxxxxxxx",
    "changeme", "placeholder", "YOUR_KEY", "YOUR_SECRET",
    "AKIAIOSFODNN7EXAMPLE", // AWS docs example
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};

static bool is_false_positive(const std::string& match) {
    for (auto& fp : FALSE_POSITIVE_TOKENS)
        if (match.find(fp) != std::string::npos) return true;
    return false;
}

// ── Pattern registry ──────────────────────────────────────────────────────────

struct Pattern {
    const char* rule_id;
    const char* name;
    const char* keyword;   // Aho-Corasick anchor (fast pre-filter)
    const char* regex_str;
    double      score;
    Severity    severity;
    double      min_entropy; // 0 = no entropy check
};

// clang-format off
static const Pattern PATTERNS[] = {
    // AWS
    { "SEC-001", "AWS Access Key ID",
      "AKIA",
      R"(\bAKIA[0-9A-Z]{16}\b)",
      9.5, Severity::Critical, 3.0 },

    { "SEC-002", "AWS Secret Access Key",
      "aws_secret",
      R"(aws_secret_access_key\s*[=:]\s*[A-Za-z0-9+/]{40})",
      9.5, Severity::Critical, 4.0 },

    // GitHub
    { "SEC-003", "GitHub Personal Access Token (classic)",
      "ghp_",
      R"(ghp_[A-Za-z0-9]{36})",
      9.0, Severity::Critical, 4.0 },

    { "SEC-004", "GitHub OAuth Token",
      "gho_",
      R"(gho_[A-Za-z0-9]{36})",
      8.5, Severity::High, 4.0 },

    { "SEC-005", "GitHub Actions Token",
      "ghs_",
      R"(ghs_[A-Za-z0-9]{36})",
      8.5, Severity::High, 4.0 },

    // Anthropic / OpenAI
    { "SEC-006", "Anthropic API Key",
      "sk-ant-",
      R"(sk-ant-[a-zA-Z0-9\-_]{90,})",
      9.5, Severity::Critical, 4.5 },

    { "SEC-007", "OpenAI API Key",
      "sk-",
      R"(sk-[A-Za-z0-9]{48})",
      9.0, Severity::Critical, 4.0 },

    // Stripe
    { "SEC-008", "Stripe Live Secret Key",
      "sk_live_",
      R"(sk_live_[A-Za-z0-9]{24,})",
      9.5, Severity::Critical, 4.0 },

    { "SEC-009", "Stripe Test Secret Key",
      "sk_test_",
      R"(sk_test_[A-Za-z0-9]{24,})",
      5.0, Severity::Medium, 3.5 },

    // Google
    { "SEC-010", "Google API Key",
      "AIza",
      R"(AIza[0-9A-Za-z\-_]{35})",
      8.0, Severity::High, 3.5 },

    // Slack
    { "SEC-011", "Slack Bot Token",
      "xoxb-",
      R"(xoxb-[0-9A-Za-z\-]{50,})",
      9.0, Severity::Critical, 4.0 },

    // Private key (PEM)
    { "SEC-012", "PEM Private Key",
      "BEGIN",
      R"(-----BEGIN [A-Z ]*PRIVATE KEY-----)",
      9.5, Severity::Critical, 0.0 },

    // Generic high-entropy assignment (catches unlabelled secrets)
    { "SEC-013", "High-entropy secret assignment",
      "secret",
      R"((?:secret|password|passwd|token|api_key|apikey|access_key)\s*[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{20,})['\"]?)",
      6.0, Severity::Medium, 3.8 },
};
// clang-format on

constexpr std::size_t NUM_PATTERNS = sizeof(PATTERNS) / sizeof(PATTERNS[0]);

// ── Scanner ───────────────────────────────────────────────────────────────────

std::vector<SecretMatch> scan_for_secrets(const std::string& content,
                                           const std::string& /*filepath*/) {
    std::vector<SecretMatch> results;

    // Split into lines for line-number tracking
    std::vector<std::string> lines;
    {
        std::istringstream ss(content);
        std::string line;
        while (std::getline(ss, line)) lines.push_back(line);
    }

    for (auto& pat : PATTERNS) {
        // Phase 1: keyword pre-filter (fast, avoids regex overhead on large files)
        if (content.find(pat.keyword) == std::string::npos)
            continue;

        // Phase 2: regex scan
        try {
            std::regex re(pat.regex_str,
                          std::regex::ECMAScript | std::regex::icase);

            for (std::size_t ln = 0; ln < lines.size(); ++ln) {
                auto& line = lines[ln];
                if (line.find(pat.keyword) == std::string::npos) continue;

                std::sregex_iterator it(line.begin(), line.end(), re);
                std::sregex_iterator end;
                for (; it != end; ++it) {
                    std::string matched = (*it)[0].str();

                    // Phase 3: entropy check
                    if (pat.min_entropy > 0.0) {
                        // Use the last "word" token as the high-entropy candidate
                        std::string token = matched.size() > 12
                                          ? matched.substr(matched.size() - 16)
                                          : matched;
                        if (shannon_entropy(token) < pat.min_entropy)
                            continue;
                    }

                    // Phase 4: false positive exclusion
                    if (is_false_positive(matched)) continue;

                    // Build redacted display string
                    std::string display = matched.size() > 8
                                        ? matched.substr(0, 8) + "..."
                                        : matched;

                    SecretMatch m;
                    m.pattern_name = pat.name;
                    m.rule_id      = pat.rule_id;
                    m.matched      = display;
                    m.line_number  = ln + 1;
                    m.score        = pat.score;
                    m.severity     = pat.severity;
                    results.push_back(std::move(m));
                }
            }
        } catch (const std::regex_error&) {
            // malformed regex — skip (shouldn't happen with our patterns)
        }
    }

    return results;
}

// ── Convert to Finding ────────────────────────────────────────────────────────

Finding secret_to_finding(const SecretMatch& m, const std::string& file) {
    static int counter = 1000; // start above manifest finding IDs
    Finding f;
    f.id       = "F-" + std::to_string(++counter);
    f.rule_id  = m.rule_id;
    f.severity = m.severity;
    f.file     = file;
    f.message  = m.pattern_name + " found in " + file.substr(file.rfind('/') + 1);
    f.score    = m.score;
    f.evidence = "Line " + std::to_string(m.line_number) + ": " + m.matched;
    return f;
}

} // namespace overtrust

#include "sentinel/engine.hpp"

#include <fstream>
#include <sstream>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>

#include "sentinel/classifier.hpp"
#include "sentinel/manifest.hpp"
#include "sentinel/secrets.hpp"
#include "sentinel/procscanner.hpp"
#include "sentinel/graph.hpp"

namespace sentinel {

// Read a text file up to max_bytes (default 512KB — skip giant files)
static std::string read_text_file(const fs::path& path,
                                   std::size_t max_bytes = 512 * 1024) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::string content(max_bytes, '\0');
    f.read(content.data(), static_cast<std::streamsize>(max_bytes));
    content.resize(static_cast<std::size_t>(f.gcount()));
    return content;
}

// ── ScanEngine::run ───────────────────────────────────────────────────────────

void ScanEngine::run() {
    running_.store(true);

    std::vector<Finding> all_findings;
    std::mutex findings_mu;
    std::atomic<std::size_t> scanned{0};
    std::atomic<std::size_t> total{0};

    auto emit = [&](Finding f) {
        if (callbacks_.on_finding) callbacks_.on_finding(f);
        std::lock_guard<std::mutex> lk(findings_mu);
        all_findings.push_back(std::move(f));
    };

    auto log = [&](const std::string& msg) {
        if (callbacks_.on_file) {
            // Reuse on_file callback just for logging — pass a dummy path
            // We'll pass the actual path instead
        }
        (void)msg;
    };
    (void)log;

    // ── Phase 1: Walk filesystem ─────────────────────────────────────────────
    std::vector<fs::path> files;
    walk_directory(fs::path(target_), files, total);

    if (callbacks_.on_progress)
        callbacks_.on_progress(0, total.load());

    // ── Phase 2: Classify + scan each file ──────────────────────────────────
    for (auto& path : files) {
        if (stop_.load()) break;

        FileKind kind = classify_file(path);
        std::string path_str = path.string();

        // Log the file
        if (callbacks_.on_file) callbacks_.on_file(path);

        if (!is_interesting(kind)) {
            ++scanned;
            if (scanned % 100 == 0 && callbacks_.on_progress)
                callbacks_.on_progress(scanned.load(), total.load());
            continue;
        }

        // ── Manifest parsing ─────────────────────────────────────────────
        switch (kind) {
            case FileKind::VsCodeExtension: {
                auto m = parse_vscode_manifest(path);
                for (auto& f : score_vscode_ext(m, path_str)) emit(f);
                break;
            }
            case FileKind::NpmPackageJson: {
                auto m = parse_npm_manifest(path);
                for (auto& f : score_npm_pkg(m, path_str)) emit(f);
                break;
            }
            case FileKind::Dockerfile: {
                auto m = parse_dockerfile(path);
                for (auto& f : score_dockerfile(m, path_str)) emit(f);
                break;
            }
            case FileKind::SshKey: {
                // Any accessible SSH private key is immediately a finding
                Finding f;
                f.id       = "F-ssh-" + path_str.substr(path_str.rfind('/') + 1);
                f.rule_id  = "FILE-001";
                f.severity = Severity::High;
                f.file     = path_str;
                f.message  = "SSH private key found: " + path_str.substr(path_str.rfind('/') + 1);
                f.score    = 7.5;
                f.evidence = "File in indexed directory";
                emit(f);
                break;
            }
            case FileKind::AwsCredentials: {
                Finding f;
                f.id       = "F-aws-" + path_str;
                f.rule_id  = "FILE-002";
                f.severity = Severity::Critical;
                f.file     = path_str;
                f.message  = "AWS credentials file found";
                f.score    = 9.0;
                f.evidence = "~/.aws/credentials accessible to all processes in same namespace";
                emit(f);
                break;
            }
            default:
                break;
        }

        // ── Secret detection (text files) ─────────────────────────────────
        if (kind == FileKind::TextFile || kind == FileKind::DotEnv ||
            kind == FileKind::ShellScript || kind == FileKind::SshKey ||
            kind == FileKind::AwsCredentials || kind == FileKind::GitConfig)
        {
            std::string content = read_text_file(path);
            if (!content.empty()) {
                auto secrets = scan_for_secrets(content, path_str);
                for (auto& s : secrets) emit(secret_to_finding(s, path_str));
            }
        }

        ++scanned;
        if (scanned % 50 == 0 && callbacks_.on_progress)
            callbacks_.on_progress(scanned.load(), total.load());
    }

    if (callbacks_.on_progress)
        callbacks_.on_progress(total.load(), total.load());

    // ── Phase 3: Process scan ────────────────────────────────────────────────
    {
        auto proc_findings = scan_processes();
        for (auto& f : proc_findings) emit(f);
    }

    // ── Phase 4: Build trust graph + compute score ────────────────────────────
    int trust_score;
    {
        std::lock_guard<std::mutex> lk(findings_mu);
        auto graph = build_trust_graph(all_findings);
        trust_score = compute_trust_score(graph);
    }

    if (callbacks_.on_complete) callbacks_.on_complete(trust_score);
    running_.store(false);
}

} // namespace sentinel

#include "overtrust/engine.hpp"

#include <fstream>
#include <sstream>
#include <atomic>
#include <thread>
#include <mutex>

#include "overtrust/classifier.hpp"
#include "overtrust/manifest.hpp"
#include "overtrust/secrets.hpp"
#include "overtrust/procscanner.hpp"
#include "overtrust/graph.hpp"

namespace overtrust {

static std::string read_text_file(const fs::path& path,
                                   std::size_t max_bytes = 512 * 1024) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::string content(max_bytes, '\0');
    f.read(content.data(), static_cast<std::streamsize>(max_bytes));
    content.resize(static_cast<std::size_t>(f.gcount()));
    return content;
}

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

    // ── Phase 1: Walk filesystem ──────────────────────────────────────────────
    std::vector<fs::path> files;
    walk_directory(fs::path(target_), files, total);

    if (callbacks_.on_progress)
        callbacks_.on_progress(0, total.load());

    // ── Phase 2: Classify + scan each file ───────────────────────────────────
    for (auto& path : files) {
        if (stop_.load()) break;

        FileKind kind    = classify_file(path);
        std::string pstr = path.string();

        if (callbacks_.on_file) callbacks_.on_file(path);

        if (!is_interesting(kind)) {
            ++scanned;
            if (scanned % 100 == 0 && callbacks_.on_progress)
                callbacks_.on_progress(scanned.load(), total.load());
            continue;
        }

        switch (kind) {
            case FileKind::VsCodeExtension: {
                auto m = parse_vscode_manifest(path);
                for (auto& f : score_vscode_ext(m, pstr)) emit(f);
                break;
            }
            case FileKind::NpmPackageJson: {
                auto m = parse_npm_manifest(path);
                for (auto& f : score_npm_pkg(m, pstr)) emit(f);
                break;
            }
            case FileKind::Dockerfile: {
                auto m = parse_dockerfile(path);
                for (auto& f : score_dockerfile(m, pstr)) emit(f);
                break;
            }
            case FileKind::SshKey: {
                Finding f;
                f.id       = "F-ssh-" + pstr.substr(pstr.rfind('/') + 1);
                f.rule_id  = "FILE-001";
                f.severity = Severity::High;
                f.file     = pstr;
                f.message  = "SSH private key: " + pstr.substr(pstr.rfind('/') + 1);
                f.score    = 7.5;
                f.evidence = "Private key in indexed directory";
                emit(f);
                break;
            }
            case FileKind::AwsCredentials: {
                Finding f;
                f.id       = "F-aws-creds";
                f.rule_id  = "FILE-002";
                f.severity = Severity::Critical;
                f.file     = pstr;
                f.message  = "AWS credentials file found";
                f.score    = 9.0;
                f.evidence = "All processes in this namespace can read this file";
                emit(f);
                break;
            }
            default:
                break;
        }

        // Secret detection on text files
        if (kind == FileKind::TextFile   || kind == FileKind::DotEnv     ||
            kind == FileKind::ShellScript || kind == FileKind::SshKey    ||
            kind == FileKind::AwsCredentials || kind == FileKind::GitConfig)
        {
            std::string content = read_text_file(path);
            if (!content.empty()) {
                auto secrets = scan_for_secrets(content, pstr);
                for (auto& s : secrets) emit(secret_to_finding(s, pstr));
            }
        }

        ++scanned;
        if (scanned % 50 == 0 && callbacks_.on_progress)
            callbacks_.on_progress(scanned.load(), total.load());
    }

    if (callbacks_.on_progress)
        callbacks_.on_progress(total.load(), total.load());

    // ── Phase 3: Process scan ─────────────────────────────────────────────────
    for (auto& f : scan_processes()) emit(f);

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

} // namespace overtrust

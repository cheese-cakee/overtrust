#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "sentinel/types.hpp"

namespace sentinel {

namespace fs = std::filesystem;

// ── VS Code extension manifest parser ────────────────────────────────────────

struct VsCodeExtManifest {
    std::string name;
    std::string publisher;
    std::string version;
    std::string description;

    // Capability flags (from contributes.*)
    bool has_terminal        = false;
    bool has_debugger        = false;
    bool has_webview         = false;
    bool has_auth_provider   = false;
    bool has_task_defs       = false;
    bool has_custom_editors  = false;
    bool has_scm_provider    = false;

    // Activation
    bool always_on           = false; // "*" or "onStartupFinished"

    // Dependencies
    std::vector<std::string> extension_deps;

    // Raw contributes keys (for further scoring)
    std::vector<std::string> contribute_keys;
};

VsCodeExtManifest parse_vscode_manifest(const fs::path& pkg_json);

// ── npm package.json parser ──────────────────────────────────────────────────

struct NpmManifest {
    std::string name;
    std::string version;

    // Lifecycle scripts — preinstall/postinstall are most dangerous
    bool has_preinstall   = false;
    bool has_postinstall  = false;
    bool has_install      = false;

    // Suspicious patterns in scripts (e.g. curl | bash)
    std::vector<std::string> suspicious_scripts;

    // Direct dependencies count
    std::size_t dep_count     = 0;
    std::size_t devdep_count  = 0;
};

NpmManifest parse_npm_manifest(const fs::path& pkg_json);

// ── Dockerfile parser ────────────────────────────────────────────────────────

struct DockerfileManifest {
    std::string base_image;
    bool        runs_as_root = false; // no USER directive or USER root
    bool        has_curl_pipe_bash = false;
    std::vector<std::string> env_vars;  // exposed via ENV directive
    std::vector<std::string> run_cmds;  // raw RUN arguments
};

DockerfileManifest parse_dockerfile(const fs::path& path);

// ── Produce Findings from parsed manifests ────────────────────────────────────

std::vector<Finding> score_vscode_ext(const VsCodeExtManifest& m, const std::string& file);
std::vector<Finding> score_npm_pkg(const NpmManifest& m, const std::string& file);
std::vector<Finding> score_dockerfile(const DockerfileManifest& m, const std::string& file);

} // namespace sentinel

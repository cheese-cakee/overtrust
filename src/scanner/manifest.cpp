#include "overtrust/manifest.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>

#include <nlohmann/json.hpp>

namespace overtrust {

using json = nlohmann::json;

// ── Helpers ───────────────────────────────────────────────────────────────────

static json load_json(const fs::path& path) {
    std::ifstream f(path);
    if (!f) return {};
    try {
        return json::parse(f, nullptr, /*exceptions=*/false);
    } catch (...) {
        return {};
    }
}

static bool script_is_suspicious(const std::string& cmd) {
    static const std::vector<std::string> PATTERNS = {
        "curl", "wget", "bash", "sh -", "exec(",
        "eval(", "node -e", "python -c", "perl -e",
        "base64", "xterm", "nc ", "ncat",
    };
    std::string lower = cmd;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (auto& p : PATTERNS)
        if (lower.find(p) != std::string::npos) return true;
    return false;
}

// ── VS Code extension ─────────────────────────────────────────────────────────

VsCodeExtManifest parse_vscode_manifest(const fs::path& pkg_json) {
    VsCodeExtManifest m;
    json j = load_json(pkg_json);
    if (j.is_discarded() || j.is_null()) return m;

    m.name        = j.value("name",        "");
    m.publisher   = j.value("publisher",   "");
    m.version     = j.value("version",     "");
    m.description = j.value("description", "");

    // contributes
    if (j.contains("contributes") && j["contributes"].is_object()) {
        auto& c = j["contributes"];
        for (auto& [key, _] : c.items()) {
            m.contribute_keys.push_back(key);
        }
        m.has_terminal       = c.contains("terminal");
        m.has_debugger       = c.contains("debuggers");
        m.has_webview        = c.contains("webviews");
        m.has_auth_provider  = c.contains("authentication");
        m.has_task_defs      = c.contains("taskDefinitions");
        m.has_custom_editors = c.contains("customEditors");
        m.has_scm_provider   = c.contains("scmProviders");
    }

    // activationEvents
    if (j.contains("activationEvents") && j["activationEvents"].is_array()) {
        for (auto& ev : j["activationEvents"]) {
            std::string s = ev.get<std::string>();
            if (s == "*" || s == "onStartupFinished") {
                m.always_on = true;
                break;
            }
        }
    }

    // extensionDependencies
    if (j.contains("extensionDependencies") && j["extensionDependencies"].is_array()) {
        for (auto& dep : j["extensionDependencies"])
            if (dep.is_string()) m.extension_deps.push_back(dep.get<std::string>());
    }

    return m;
}

// ── npm package.json ──────────────────────────────────────────────────────────

NpmManifest parse_npm_manifest(const fs::path& pkg_json) {
    NpmManifest m;
    json j = load_json(pkg_json);
    if (j.is_discarded() || j.is_null()) return m;

    m.name    = j.value("name",    "");
    m.version = j.value("version", "");

    if (j.contains("scripts") && j["scripts"].is_object()) {
        auto& s = j["scripts"];
        auto check = [&](const char* key, bool& flag) {
            if (s.contains(key) && s[key].is_string()) {
                flag = true;
                std::string cmd = s[key].get<std::string>();
                if (script_is_suspicious(cmd))
                    m.suspicious_scripts.push_back(key + std::string(": ") + cmd);
            }
        };
        check("preinstall",  m.has_preinstall);
        check("postinstall", m.has_postinstall);
        check("install",     m.has_install);
    }

    if (j.contains("dependencies") && j["dependencies"].is_object())
        m.dep_count = j["dependencies"].size();
    if (j.contains("devDependencies") && j["devDependencies"].is_object())
        m.devdep_count = j["devDependencies"].size();

    return m;
}

// ── Dockerfile ────────────────────────────────────────────────────────────────

DockerfileManifest parse_dockerfile(const fs::path& path) {
    DockerfileManifest m;
    std::ifstream f(path);
    if (!f) return m;

    m.runs_as_root = true; // assume root unless USER is set

    // Join logical lines: a line ending with \ is continued on the next line.
    // We collect raw physical lines, merge continuations, then parse instructions.
    std::vector<std::string> logical_lines;
    {
        std::string raw;
        std::string acc;
        while (std::getline(f, raw)) {
            // Trim trailing whitespace including \r
            while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\t' || raw.back() == '\r'))
                raw.pop_back();
            if (!raw.empty() && raw.back() == '\\') {
                acc += raw.substr(0, raw.size() - 1) + ' ';
            } else {
                acc += raw;
                logical_lines.push_back(acc);
                acc.clear();
            }
        }
        if (!acc.empty()) logical_lines.push_back(acc);
    }

    for (auto& line : logical_lines) {
        // trim leading whitespace
        auto start = line.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        line = line.substr(start);

        if (line.empty() || line[0] == '#') continue;

        std::string upper = line;
        std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

        if (upper.substr(0, 5) == "FROM ") {
            std::string img = line.substr(5);
            // strip tag
            auto colon = img.find(':');
            m.base_image = colon != std::string::npos ? img.substr(0, colon) : img;
        }
        else if (upper.substr(0, 5) == "USER ") {
            std::string user = line.substr(5);
            std::transform(user.begin(), user.end(), user.begin(), ::tolower);
            // Strip optional :gid suffix so "0:0" is treated the same as "0"
            std::string uid = user.substr(0, user.find(':'));
            m.runs_as_root = (user.find("root") != std::string::npos || uid == "0");
        }
        else if (upper.substr(0, 4) == "ENV ") {
            m.env_vars.push_back(line.substr(4));
        }
        else if (upper.substr(0, 4) == "RUN ") {
            std::string cmd = line.substr(4);
            m.run_cmds.push_back(cmd);
            // Check for curl | bash across the now-joined logical line
            if (cmd.find("curl") != std::string::npos &&
                (cmd.find("| bash") != std::string::npos ||
                 cmd.find("|bash")  != std::string::npos ||
                 cmd.find("| sh")   != std::string::npos))
            {
                m.has_curl_pipe_bash = true;
            }
        }
    }

    return m;
}

// ── Scorers ───────────────────────────────────────────────────────────────────

static std::string next_id() { return next_finding_id(); }

std::vector<Finding> score_vscode_ext(const VsCodeExtManifest& m,
                                       const std::string& file) {
    std::vector<Finding> out;

    auto add = [&](const char* rule, Severity sev, double score,
                   const std::string& msg, const std::string& ev = "") {
        Finding f;
        f.id       = next_id();
        f.rule_id  = rule;
        f.severity = sev;
        f.file     = file;
        f.message  = msg;
        f.score    = score;
        f.evidence = ev;
        out.push_back(std::move(f));
    };

    std::string ext_name = m.name.empty() ? "unknown" : m.name;

    if (m.has_terminal)
        add("EXT-001", Severity::High, 8.5,
            "Extension '" + ext_name + "' has terminal access",
            "contributes.terminal declared");

    if (m.has_debugger)
        add("EXT-002", Severity::High, 8.0,
            "Extension '" + ext_name + "' registers a debug adapter",
            "contributes.debuggers declared");

    if (m.has_auth_provider)
        add("EXT-003", Severity::Critical, 9.5,
            "Extension '" + ext_name + "' is an authentication provider",
            "contributes.authentication — can intercept auth tokens");

    if (m.has_webview)
        add("EXT-004", Severity::Medium, 6.0,
            "Extension '" + ext_name + "' uses embedded webviews",
            "contributes.webviews — can render arbitrary HTML/JS");

    if (m.always_on)
        add("EXT-005", Severity::Medium, 5.5,
            "Extension '" + ext_name + "' activates on startup",
            "activationEvents includes '*' or 'onStartupFinished'");

    if (m.has_task_defs)
        add("EXT-006", Severity::Medium, 6.5,
            "Extension '" + ext_name + "' defines task runners",
            "contributes.taskDefinitions — can execute arbitrary commands");

    if (m.has_custom_editors)
        add("EXT-007", Severity::Low, 4.0,
            "Extension '" + ext_name + "' has custom editor providers",
            "contributes.customEditors");

    return out;
}

std::vector<Finding> score_npm_pkg(const NpmManifest& m,
                                    const std::string& file) {
    std::vector<Finding> out;

    auto add = [&](const char* rule, Severity sev, double score,
                   const std::string& msg, const std::string& ev = "") {
        Finding f;
        f.id       = next_id();
        f.rule_id  = rule;
        f.severity = sev;
        f.file     = file;
        f.message  = msg;
        f.score    = score;
        f.evidence = ev;
        out.push_back(std::move(f));
    };

    std::string pkg = m.name.empty() ? "unknown" : m.name;

    for (auto& sus : m.suspicious_scripts) {
        add("NPM-001", Severity::Critical, 9.0,
            "Package '" + pkg + "' has a suspicious install script",
            sus);
    }

    if (m.has_preinstall && m.suspicious_scripts.empty())
        add("NPM-002", Severity::High, 7.0,
            "Package '" + pkg + "' has a preinstall script",
            "Runs before package is fully installed");

    if (m.has_postinstall && m.suspicious_scripts.empty())
        add("NPM-003", Severity::Medium, 6.0,
            "Package '" + pkg + "' has a postinstall script",
            "Runs after package installation");

    return out;
}

std::vector<Finding> score_dockerfile(const DockerfileManifest& m,
                                       const std::string& file) {
    std::vector<Finding> out;

    auto add = [&](const char* rule, Severity sev, double score,
                   const std::string& msg, const std::string& ev = "") {
        Finding f;
        f.id       = next_id();
        f.rule_id  = rule;
        f.severity = sev;
        f.file     = file;
        f.message  = msg;
        f.score    = score;
        f.evidence = ev;
        out.push_back(std::move(f));
    };

    if (m.runs_as_root)
        add("DOCKER-001", Severity::High, 7.5,
            "Dockerfile runs as root (no USER directive)",
            "Container processes will have root UID");

    if (m.has_curl_pipe_bash)
        add("DOCKER-002", Severity::Critical, 9.5,
            "Dockerfile runs curl | bash",
            "RUN curl ... | bash/sh — remote code execution on build");

    return out;
}

} // namespace overtrust

#include "overtrust/classifier.hpp"

#include <fstream>
#include <algorithm>
#include <cctype>
#include <vector>
#include <string>

namespace overtrust {

// ── Magic byte prefixes ──────────────────────────────────────────────────────

static constexpr unsigned char ELF_MAGIC[4] = {0x7f, 'E', 'L', 'F'};
static constexpr unsigned char SHEBANG[2]   = {'#', '!'};

// ── Helpers ──────────────────────────────────────────────────────────────────

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static bool ends_with(const std::string& s, const std::string& suffix) {
    if (suffix.size() > s.size()) return false;
    return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static bool path_contains(const fs::path& p, const std::string& fragment) {
    // Use generic() to normalise to forward slashes on all platforms
    std::string full = p.generic_string();
    return full.find(fragment) != std::string::npos;
}

// ── Implementation ────────────────────────────────────────────────────────────

std::string read_magic(const fs::path& path, std::size_t n) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::string buf(n, '\0');
    f.read(buf.data(), static_cast<std::streamsize>(n));
    buf.resize(static_cast<std::size_t>(f.gcount()));
    return buf;
}

FileKind classify_file(const fs::path& path) {
    std::string name = lower(path.filename().string());
    std::string pathstr = path.string();

    // ── Dockerfile ──────────────────────────────────────────────────────────
    if (name == "dockerfile" || name.substr(0, 11) == "dockerfile.")
        return FileKind::Dockerfile;

    // ── .env files ──────────────────────────────────────────────────────────
    // .env, .env.local, .env.production, prod.env, secrets.env, etc.
    // Exclude template/sample files (.env.example, .env.sample, .env.template,
    // .env.test) — they conventionally contain placeholder values, not real
    // secrets, and scanning them generates false positives.
    static const std::vector<std::string> ENV_PLACEHOLDERS = {
        ".env.example", ".env.sample", ".env.template", ".env.test",
        ".env.dist",    ".env.default",
    };
    for (auto& ph : ENV_PLACEHOLDERS)
        if (name == ph) return FileKind::TextFile;

    if (name == ".env" || (name.size() > 4 && name.substr(0, 4) == ".env") ||
        ends_with(name, ".env"))
        return FileKind::DotEnv;

    // ── Credential dotfiles with no extension ──────────────────────────────────
    // These have no extension and no shebang, so they would fall through to
    // BinaryFile and be silently skipped. List them explicitly as TextFile so
    // the secret scanner runs on them.
    static const std::vector<std::string> CRED_DOTFILES = {
        ".npmrc",   // npm registry auth tokens (_authToken=)
        ".netrc",   // FTP / HTTP credentials (machine/login/password)
        ".pgpass",  // PostgreSQL passwords
        ".boto",    // AWS Python SDK credentials
        ".pypirc",  // PyPI upload tokens
        ".my.cnf",  // MySQL client credentials
    };
    for (auto& fn : CRED_DOTFILES)
        if (name == fn) return FileKind::TextFile;

    // ── AWS credentials ─────────────────────────────────────────────────────
    if (path_contains(pathstr, "/.aws/") &&
        (name == "credentials" || name == "config"))
        return FileKind::AwsCredentials;

    // ── SSH private keys ────────────────────────────────────────────────────
    // Only classify as SshKey when the path or filename strongly indicates a
    // private key.  Broad extension matching (.pem, .key) triggered FILE-001
    // for every TLS certificate (server.pem), dev cert (localhost.key), or
    // unrelated config file (config.key) anywhere in the scan tree.
    // For .pem/.key files outside /.ssh/, return TextFile so the SEC-012
    // "PEM Private Key" pattern detects them if they actually contain a
    // private key header — avoiding the unconditional FILE-001 false positive.
    if (path_contains(pathstr, "/.ssh/") ||
        name == "id_rsa" || name == "id_ed25519" || name == "id_ecdsa" ||
        name == "id_dsa"  || name == "id_xmss")
    {
        if (!ends_with(name, ".pub"))
            return FileKind::SshKey;
    }

    if (ends_with(name, ".pem") || ends_with(name, ".key")) {
        if (!ends_with(name, ".pub"))
            return FileKind::TextFile;  // SEC-012 fires if content has PRIVATE KEY header
    }

    // ── Shell history ────────────────────────────────────────────────────────
    if (name == ".bash_history" || name == ".zsh_history" ||
        name == ".fish_history" || name == ".history")
        return FileKind::ShellHistory;

    // ── Git config ──────────────────────────────────────────────────────────
    if (name == ".gitconfig" || (name == "config" && path_contains(pathstr, "/.git/")))
        return FileKind::GitConfig;

    // ── VS Code extension manifest ──────────────────────────────────────────
    if (name == "package.json" &&
        (path_contains(pathstr, "/.vscode/extensions/") ||
         path_contains(pathstr, "/.cursor/extensions/")))
        return FileKind::VsCodeExtension;

    // ── Generic npm package.json ────────────────────────────────────────────
    if (name == "package.json")
        return FileKind::NpmPackageJson;

    // ── JetBrains plugin descriptor ─────────────────────────────────────────
    if (name == "plugin.xml")
        return FileKind::JetBrainsPlugin;

    // ── pip requirements ────────────────────────────────────────────────────
    if (name == "requirements.txt")
        return FileKind::PipRequirements;

    // ── Magic bytes ─────────────────────────────────────────────────────────
    std::string magic = read_magic(path, 4);
    if (magic.size() >= 4 &&
        static_cast<unsigned char>(magic[0]) == ELF_MAGIC[0] &&
        magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')
        return FileKind::ElfBinary;

    if (magic.size() >= 2 &&
        static_cast<unsigned char>(magic[0]) == SHEBANG[0] &&
        magic[1] == SHEBANG[1])
        return FileKind::ShellScript;

    // ── Kubernetes config ───────────────────────────────────────────────────
    if (path_contains(pathstr, "/.kube/") && name == "config")
        return FileKind::KubeConfig;

    // ── YAML / TOML / JSON / XML config files ──────────────────────────────
    if (ends_with(name, ".yaml") || ends_with(name, ".yml"))
        return FileKind::YamlConfig;
    if (ends_with(name, ".toml"))
        return FileKind::TomlConfig;
    if (ends_with(name, ".json"))
        return FileKind::JsonConfig;
    if (ends_with(name, ".xml"))
        return FileKind::XmlConfig;

    // ── Extension-based text heuristics ────────────────────────────────────
    static const std::vector<std::string> TEXT_EXTS = {
        ".txt", ".md", ".ini", ".cfg", ".conf",
        ".sh", ".bash", ".zsh", ".fish",
        ".py", ".rb", ".pl", ".js", ".ts", ".go", ".rs", ".c", ".cpp",
        ".h", ".hpp", ".java", ".kt", ".swift", ".cs", ".html", ".css",
    };
    for (auto& ext : TEXT_EXTS) {
        if (ends_with(name, ext)) return FileKind::TextFile;
    }

    return FileKind::BinaryFile;
}

const char* file_kind_str(FileKind k) {
    switch (k) {
        case FileKind::VsCodeExtension:  return "vscode-ext";
        case FileKind::NpmPackageJson:   return "npm-pkg";
        case FileKind::Dockerfile:       return "dockerfile";
        case FileKind::JetBrainsPlugin:  return "jetbrains-plugin";
        case FileKind::PipRequirements:  return "pip-req";
        case FileKind::DotEnv:           return "dotenv";
        case FileKind::AwsCredentials:   return "aws-creds";
        case FileKind::SshKey:           return "ssh-key";
        case FileKind::GitConfig:        return "git-config";
        case FileKind::ShellHistory:     return "shell-history";
        case FileKind::YamlConfig:       return "yaml";
        case FileKind::TomlConfig:       return "toml";
        case FileKind::JsonConfig:       return "json";
        case FileKind::XmlConfig:        return "xml";
        case FileKind::KubeConfig:       return "kubeconfig";
        case FileKind::ElfBinary:        return "elf";
        case FileKind::ShellScript:      return "shell-script";
        case FileKind::TextFile:         return "text";
        case FileKind::BinaryFile:       return "binary";
        default:                         return "unknown";
    }
}

bool is_interesting(FileKind k) {
    switch (k) {
        case FileKind::VsCodeExtension:
        case FileKind::NpmPackageJson:
        case FileKind::Dockerfile:
        case FileKind::JetBrainsPlugin:
        case FileKind::PipRequirements:
        case FileKind::DotEnv:
        case FileKind::AwsCredentials:
        case FileKind::SshKey:
        case FileKind::GitConfig:
        case FileKind::ShellScript:
        case FileKind::ShellHistory:
        case FileKind::YamlConfig:
        case FileKind::TomlConfig:
        case FileKind::JsonConfig:
        case FileKind::XmlConfig:
        case FileKind::KubeConfig:
        case FileKind::TextFile:
            return true;
        default:
            return false;
    }
}

} // namespace overtrust

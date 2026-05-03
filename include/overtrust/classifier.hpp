#pragma once

#include <filesystem>
#include <string>
#include <cstdint>

namespace overtrust {

namespace fs = std::filesystem;

// ── File types we care about ─────────────────────────────────────────────────

enum class FileKind {
    Unknown,
    // Manifests
    VsCodeExtension,   // .vscode/extensions/*/package.json
    NpmPackageJson,    // package.json (generic npm)
    Dockerfile,        // Dockerfile / Dockerfile.*
    JetBrainsPlugin,   // plugin.xml
    PipRequirements,   // requirements.txt
    // Secrets / config
    DotEnv,            // .env, .env.*
    AwsCredentials,    // .aws/credentials, .aws/config
    SshKey,            // id_rsa, id_ed25519, *.pem, *.key (private)
    GitConfig,         // .gitconfig, .git/config
    ShellHistory,      // .bash_history, .zsh_history
    // Config formats (may embed secrets)
    YamlConfig,        // *.yml, *.yaml
    TomlConfig,        // *.toml
    JsonConfig,        // *.json (non-manifest)
    XmlConfig,         // *.xml (non-manifest)
    KubeConfig,        // ~/.kube/config
    // Executables / binaries
    ElfBinary,
    ShellScript,
    // Generic text (fallback)
    TextFile,
    BinaryFile,
};

const char* file_kind_str(FileKind k);

// Classify a file by path heuristics + magic bytes
FileKind classify_file(const fs::path& path);

// Read the first N bytes from a file (for magic byte detection)
std::string read_magic(const fs::path& path, std::size_t n = 8);

// True if this FileKind warrants a deeper scan (parsing, secret detection)
bool is_interesting(FileKind k);

} // namespace overtrust

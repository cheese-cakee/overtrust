#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "overtrust/types.hpp"

namespace overtrust {

// ── Linux capability table ────────────────────────────────────────────────────
// Only defined/used on Linux; Windows uses privilege string equivalents instead.

#ifdef __linux__

struct CapEntry {
    uint8_t     bit;
    const char* name;
    bool        dangerous;
};

extern const CapEntry CAPABILITY_TABLE[];
extern const std::size_t CAPABILITY_TABLE_SIZE;

#endif // __linux__

// ── Process info ──────────────────────────────────────────────────────────────

struct ProcessInfo {
    uint32_t    pid  = 0;
    std::string name;       // process name (comm on Linux, exe base on Windows)
    std::string cmdline;    // full command line

#ifdef __linux__
    // Linux-specific: raw capability bitmasks from /proc/pid/status
    uint64_t    cap_eff  = 0;
    uint64_t    cap_prm  = 0;
    uint64_t    cap_bnd  = 0;
    int         seccomp  = 0; // 0=off, 1=strict, 2=filter
    uint32_t    uid      = 0;

    // Namespace inodes (from /proc/pid/ns/*)
    uint64_t    ns_pid   = 0;
    uint64_t    ns_net   = 0;
    uint64_t    ns_mnt   = 0;
    uint64_t    ns_user  = 0;

    // Resolved named capabilities from cap_eff
    std::vector<std::string> active_caps;
    std::vector<std::string> dangerous_caps;
#endif // __linux__

#ifdef _WIN32
    // Windows-specific: token elevation and dangerous privileges
    bool        is_elevated = false;  // TokenElevation — running with admin token
#endif // _WIN32

    // Cross-platform: sensitive open file paths (Linux: /proc/fd; Windows: skipped for MVP)
    std::vector<std::string> sensitive_fds;

    // Cross-platform: dangerous privilege names
    //   Linux: e.g. "CAP_SYS_PTRACE", "CAP_SYS_ADMIN"
    //   Windows: e.g. "SeDebugPrivilege", "SeTcbPrivilege"
    std::vector<std::string> dangerous_privs;
};

// ── Scanner functions ─────────────────────────────────────────────────────────

// Identify if a process looks like an AI tool / IDE assistant
bool is_ai_tool(const ProcessInfo& p);

// Convert ProcessInfo → Findings
std::vector<Finding> score_process(const ProcessInfo& p);

// Scan all processes, return findings
std::vector<Finding> scan_processes();

// Platform-specific (not exposed on Windows):
#ifdef __linux__
std::vector<uint32_t> list_pids();
ProcessInfo read_process(uint32_t pid);
#endif

} // namespace overtrust

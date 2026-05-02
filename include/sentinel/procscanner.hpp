#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "sentinel/types.hpp"

namespace sentinel {

// ── Linux capability names (subset — most security-relevant) ─────────────────

struct CapEntry {
    uint8_t     bit;
    const char* name;
    bool        dangerous;
};

// Full list through bit 40, flagging the high-risk ones
extern const CapEntry CAPABILITY_TABLE[];
extern const std::size_t CAPABILITY_TABLE_SIZE;

// ── Process info ─────────────────────────────────────────────────────────────

struct ProcessInfo {
    uint32_t    pid;
    std::string name;       // from /proc/pid/comm
    std::string cmdline;    // from /proc/pid/cmdline

    // From /proc/pid/status
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

    // Open file descriptors (paths that look sensitive)
    std::vector<std::string> sensitive_fds;

    // Resolved named capabilities from cap_eff
    std::vector<std::string> active_caps;
    std::vector<std::string> dangerous_caps;
};

// ── Scanner functions ─────────────────────────────────────────────────────────

// Read all running PIDs from /proc
std::vector<uint32_t> list_pids();

// Parse /proc/pid/ for one process
ProcessInfo read_process(uint32_t pid);

// Identify if a process looks like an AI tool / IDE assistant
bool is_ai_tool(const ProcessInfo& p);

// Convert ProcessInfo → Findings
std::vector<Finding> score_process(const ProcessInfo& p);

// Scan all processes, return findings
std::vector<Finding> scan_processes();

} // namespace sentinel

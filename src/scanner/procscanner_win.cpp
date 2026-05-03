#ifdef _WIN32

// Windows process scanner — uses Win32 API only, no POSIX headers.
//
// Coverage:
//   - Enumerate all processes via CreateToolhelp32Snapshot
//   - Resolve exe name + full command line via QueryFullProcessImageName / GetCommandLine (own process only)
//     and NtQueryInformationProcess for others where accessible
//   - Detect elevated token via OpenProcessToken + GetTokenInformation(TokenElevation)
//   - Flag dangerous privileges: SeDebugPrivilege, SeTcbPrivilege, SeLoadDriverPrivilege,
//     SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege
//   - AI tool name detection (same list as Linux)
//   - Sensitive FD scan: skipped on Windows for MVP (requires SeDebugPrivilege + NtQuerySystemInformation)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "overtrust/procscanner.hpp"

#include <windows.h>
#include <tlhelp32.h>   // CreateToolhelp32Snapshot, Process32First/Next
#include <psapi.h>      // QueryFullProcessImageName (via Kernel32 on Vista+), GetProcessImageFileName
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

// Privilege names considered dangerous (Windows equivalents of Linux dangerous caps)
static const char* DANGEROUS_PRIVS[] = {
    "SeDebugPrivilege",               // equivalent of CAP_SYS_PTRACE — attach to any process
    "SeTcbPrivilege",                 // equivalent of CAP_SYS_ADMIN  — act as OS
    "SeLoadDriverPrivilege",          // equivalent of CAP_SYS_MODULE — load kernel drivers
    "SeImpersonatePrivilege",         // impersonate any logged-on user
    "SeAssignPrimaryTokenPrivilege",  // replace a process's primary token
    "SeTakeOwnershipPrivilege",       // take ownership of any object
    "SeRestorePrivilege",             // write to any file regardless of ACL
    "SeBackupPrivilege",              // read any file regardless of ACL
};
static const int DANGEROUS_PRIVS_COUNT =
    static_cast<int>(sizeof(DANGEROUS_PRIVS) / sizeof(DANGEROUS_PRIVS[0]));

namespace overtrust {

// ── Helpers ───────────────────────────────────────────────────────────────────

// Narrow (ANSI) string from wide string — good enough for process names/paths
static std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                  nullptr, 0, nullptr, nullptr);
    if (sz <= 0) return {};
    std::string s(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                         s.data(), sz, nullptr, nullptr);
    return s;
}

// Get the full executable path for a process handle (needs PROCESS_QUERY_LIMITED_INFORMATION)
static std::string get_exe_path(HANDLE hProc) {
    wchar_t buf[MAX_PATH + 1] = {};
    DWORD sz = MAX_PATH;
    if (QueryFullProcessImageNameW(hProc, 0, buf, &sz))
        return narrow(std::wstring(buf, sz));
    return {};
}

// Extract just the filename from a full path (no extension stripping — keep .exe)
static std::string basename(const std::string& path) {
    auto pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}

// Check if the process token is elevated (UAC high integrity level / full admin token)
static bool check_elevation(HANDLE hProc) {
    HANDLE hTok = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok))
        return false;

    TOKEN_ELEVATION elev{};
    DWORD returnLen = 0;
    bool elevated = false;
    if (GetTokenInformation(hTok, TokenElevation, &elev, sizeof(elev), &returnLen))
        elevated = (elev.TokenIsElevated != 0);

    CloseHandle(hTok);
    return elevated;
}

// Enumerate which dangerous privileges are enabled (not just present) in the token
static std::vector<std::string> get_dangerous_privs(HANDLE hProc) {
    std::vector<std::string> result;

    HANDLE hTok = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok))
        return result;

    DWORD needed = 0;
    GetTokenInformation(hTok, TokenPrivileges, nullptr, 0, &needed);
    if (needed == 0) { CloseHandle(hTok); return result; }

    std::vector<BYTE> buf(needed);
    if (!GetTokenInformation(hTok, TokenPrivileges, buf.data(), needed, &needed)) {
        CloseHandle(hTok); return result;
    }

    auto* tp = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
    for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
        // Only care if the privilege is enabled (SE_PRIVILEGE_ENABLED)
        if (!(tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
            continue;

        char name[64] = {};
        DWORD nameLen = sizeof(name);
        if (!LookupPrivilegeNameA(nullptr, &tp->Privileges[i].Luid, name, &nameLen))
            continue;

        for (int j = 0; j < DANGEROUS_PRIVS_COUNT; ++j) {
            if (strcmp(name, DANGEROUS_PRIVS[j]) == 0) {
                result.emplace_back(name);
                break;
            }
        }
    }

    CloseHandle(hTok);
    return result;
}

// ── is_ai_tool (Windows) ──────────────────────────────────────────────────────

bool is_ai_tool(const ProcessInfo& p) {
    static const std::vector<std::string> AI_PROCESS_NAMES = {
        "cursor", "copilot", "codeium", "tabnine", "claude",
        "continue", "cody", "aider", "ghostwriter",
    };
    std::string lower_name = p.name;
    std::string lower_cmd  = p.cmdline;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    std::transform(lower_cmd.begin(),  lower_cmd.end(),  lower_cmd.begin(),  ::tolower);
    for (auto& n : AI_PROCESS_NAMES) {
        if (lower_name.find(n) != std::string::npos) return true;
        if (lower_cmd.find(n)  != std::string::npos) return true;
    }
    return false;
}

// ── score_process (Windows) ───────────────────────────────────────────────────

std::vector<Finding> score_process(const ProcessInfo& p) {
    std::vector<Finding> out;

    // Skip the System and Idle pseudo-processes
    if (p.pid == 0 || p.pid == 4) return out;

    auto add = [&](const char* rule, Severity sev, double score,
                   std::string msg, std::string ev = "") {
        Finding f;
        f.id       = next_finding_id();
        f.rule_id  = rule;
        f.severity = sev;
        f.file     = "PID:" + std::to_string(p.pid);
        f.message  = std::move(msg);
        f.score    = score;
        f.evidence = std::move(ev);
        out.push_back(std::move(f));
    };

    std::string proc_label = p.name + " (PID " + std::to_string(p.pid) + ")";

    // Dangerous privileges enabled in non-system processes
    if (!p.dangerous_privs.empty()) {
        std::string privs;
        for (auto& pr : p.dangerous_privs) privs += pr + " ";
        add("PROC-001", Severity::High, 7.5,
            proc_label + " has dangerous privileges enabled",
            "Privileges: " + privs);
    }

    // Elevated (UAC) process — not inherently bad but worth noting
    if (p.is_elevated) {
        add("PROC-002", Severity::Medium, 4.5,
            proc_label + " is running with elevated (admin) token",
            "TokenElevation: true");
    }

    // Sensitive files open (not populated on Windows MVP, but keep the check)
    for (auto& fd_path : p.sensitive_fds) {
        add("PROC-003", Severity::High, 7.0,
            proc_label + " has sensitive file open",
            "path: " + fd_path);
    }

    // AI tool with dangerous privileges
    if (is_ai_tool(p) && !p.dangerous_privs.empty()) {
        add("PROC-004", Severity::Critical, 9.5,
            "AI tool " + proc_label + " has dangerous privileges",
            "Privileges: " + [&]{ std::string s; for (auto& x : p.dangerous_privs) s += x + " "; return s; }());
    }

    // AI tool running elevated
    if (is_ai_tool(p) && p.is_elevated) {
        add("PROC-005", Severity::High, 8.0,
            "AI tool " + proc_label + " is running with elevated token",
            "TokenElevation: true");
    }

    return out;
}

// ── scan_processes (Windows) ──────────────────────────────────────────────────

std::vector<Finding> scan_processes() {
    std::vector<Finding> results;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return results;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(snap, &entry)) {
        CloseHandle(snap);
        return results;
    }

    do {
        DWORD pid = entry.th32ProcessID;

        ProcessInfo info;
        info.pid = static_cast<uint32_t>(pid);

        // Open process with minimum rights we need:
        //   PROCESS_QUERY_LIMITED_INFORMATION — for exe path + token
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) {
            // Can't open (probably System/protected process) — use snapshot name only
            info.name = narrow(std::wstring(entry.szExeFile));
            // Still score it (name-based AI detection still works)
            auto findings = score_process(info);
            results.insert(results.end(), findings.begin(), findings.end());
            continue;
        }

        // Executable path → base name as process name
        std::string exe_path = get_exe_path(hProc);
        if (!exe_path.empty())
            info.name = basename(exe_path);
        else
            info.name = narrow(std::wstring(entry.szExeFile));

        // Command line is not easily available per-process without NtQueryInformationProcess
        // + reading PEB from target process (requires PROCESS_VM_READ).
        // For MVP: leave cmdline empty — name-based detection still catches AI tools.
        info.cmdline = "";

        // Token checks
        info.is_elevated  = check_elevation(hProc);
        info.dangerous_privs = get_dangerous_privs(hProc);

        CloseHandle(hProc);

        auto findings = score_process(info);
        results.insert(results.end(), findings.begin(), findings.end());

    } while (Process32NextW(snap, &entry));

    CloseHandle(snap);
    return results;
}

} // namespace overtrust

#endif // _WIN32

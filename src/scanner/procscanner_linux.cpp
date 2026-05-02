#ifdef __linux__

#include "overtrust/procscanner.hpp"

#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <dirent.h>
#include <sys/stat.h>

namespace overtrust {

namespace fs = std::filesystem;

// ── Capability table ──────────────────────────────────────────────────────────

const CapEntry CAPABILITY_TABLE[] = {
    {  0, "CAP_CHOWN",              false },
    {  1, "CAP_DAC_OVERRIDE",       false },
    {  2, "CAP_DAC_READ_SEARCH",    true  },
    {  3, "CAP_FOWNER",             false },
    {  4, "CAP_FSETID",             false },
    {  5, "CAP_KILL",               false },
    {  6, "CAP_SETGID",             true  },
    {  7, "CAP_SETUID",             true  },
    {  8, "CAP_SETPCAP",            false },
    {  9, "CAP_LINUX_IMMUTABLE",    false },
    { 10, "CAP_NET_BIND_SERVICE",   false },
    { 11, "CAP_NET_BROADCAST",      false },
    { 12, "CAP_NET_ADMIN",          true  },
    { 13, "CAP_NET_RAW",            true  },
    { 14, "CAP_IPC_LOCK",           false },
    { 15, "CAP_IPC_OWNER",          false },
    { 16, "CAP_SYS_MODULE",         true  },
    { 17, "CAP_SYS_RAWIO",          true  },
    { 18, "CAP_SYS_CHROOT",         false },
    { 19, "CAP_SYS_PTRACE",         true  },
    { 20, "CAP_SYS_PACCT",          false },
    { 21, "CAP_SYS_ADMIN",          true  },
    { 22, "CAP_SYS_BOOT",           true  },
    { 23, "CAP_SYS_NICE",           false },
    { 24, "CAP_SYS_RESOURCE",       false },
    { 25, "CAP_SYS_TIME",           false },
    { 26, "CAP_SYS_TTY_CONFIG",     false },
    { 27, "CAP_MKNOD",              false },
    { 28, "CAP_LEASE",              false },
    { 29, "CAP_AUDIT_WRITE",        false },
    { 30, "CAP_AUDIT_CONTROL",      true  },
    { 31, "CAP_SETFCAP",            false },
    { 32, "CAP_MAC_OVERRIDE",       true  },
    { 33, "CAP_MAC_ADMIN",          true  },
    { 34, "CAP_SYSLOG",             false },
    { 35, "CAP_WAKE_ALARM",         false },
    { 36, "CAP_BLOCK_SUSPEND",      false },
    { 37, "CAP_AUDIT_READ",         false },
    { 38, "CAP_PERFMON",            false },
    { 39, "CAP_BPF",                false },
    { 40, "CAP_CHECKPOINT_RESTORE", false },
};
const std::size_t CAPABILITY_TABLE_SIZE =
    sizeof(CAPABILITY_TABLE) / sizeof(CAPABILITY_TABLE[0]);

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::string read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string read_cmdline(uint32_t pid) {
    std::string raw = read_file("/proc/" + std::to_string(pid) + "/cmdline");
    for (char& c : raw) if (c == '\0') c = ' ';
    while (!raw.empty() && raw.back() == ' ') raw.pop_back();
    return raw;
}

static uint64_t parse_hex_field(const std::string& status, const std::string& field) {
    auto pos = status.find(field);
    if (pos == std::string::npos) return 0;
    pos += field.size();
    while (pos < status.size() && std::isspace(status[pos])) ++pos;
    std::string hex;
    while (pos < status.size() && std::isxdigit(status[pos])) hex += status[pos++];
    if (hex.empty()) return 0;
    try { return std::stoull(hex, nullptr, 16); } catch (...) { return 0; }
}

static uint64_t parse_ns_inode(uint32_t pid, const char* ns_name) {
    std::string link = "/proc/" + std::to_string(pid) + "/ns/" + ns_name;
    std::error_code ec;
    fs::path target = fs::read_symlink(link, ec);
    if (ec) return 0;
    std::string s = target.string();
    auto lb = s.find('['), rb = s.find(']');
    if (lb == std::string::npos || rb == std::string::npos) return 0;
    try { return std::stoull(s.substr(lb + 1, rb - lb - 1)); } catch (...) { return 0; }
}

static bool fd_path_is_sensitive(const std::string& path) {
    static const std::vector<std::string> SENSITIVE = {
        "/.ssh/", "/.aws/", "/.gnupg/", "/credentials",
        ".env", "id_rsa", "id_ed25519", "private_key",
        "/.config/gh/", "/.kube/", "/secrets/",
    };
    for (auto& s : SENSITIVE)
        if (path.find(s) != std::string::npos) return true;
    return false;
}

// ── list_pids ─────────────────────────────────────────────────────────────────

std::vector<uint32_t> list_pids() {
    std::vector<uint32_t> pids;
    DIR* d = opendir("/proc");
    if (!d) return pids;
    struct dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        if (ent->d_type != DT_DIR && ent->d_type != DT_UNKNOWN) continue;
        bool all_digits = true;
        for (char* p = ent->d_name; *p; ++p)
            if (!std::isdigit(*p)) { all_digits = false; break; }
        if (!all_digits || ent->d_name[0] == '\0') continue;
        try { pids.push_back(static_cast<uint32_t>(std::stoul(ent->d_name))); }
        catch (...) {}
    }
    closedir(d);
    return pids;
}

// ── read_process ──────────────────────────────────────────────────────────────

ProcessInfo read_process(uint32_t pid) {
    ProcessInfo p;
    p.pid = pid;
    std::string base = "/proc/" + std::to_string(pid) + "/";

    p.name = read_file(base + "comm");
    while (!p.name.empty() && (p.name.back() == '\n' || p.name.back() == '\r'))
        p.name.pop_back();

    p.cmdline = read_cmdline(pid);

    std::string status = read_file(base + "status");
    p.cap_eff = parse_hex_field(status, "CapEff:");
    p.cap_prm = parse_hex_field(status, "CapPrm:");
    p.cap_bnd = parse_hex_field(status, "CapBnd:");

    {
        auto pos = status.find("Uid:");
        if (pos != std::string::npos) {
            std::istringstream ss(status.substr(pos + 4));
            ss >> p.uid;
        }
    }
    {
        auto pos = status.find("Seccomp:");
        if (pos != std::string::npos) {
            std::istringstream ss(status.substr(pos + 8));
            ss >> p.seccomp;
        }
    }

    for (std::size_t i = 0; i < CAPABILITY_TABLE_SIZE; ++i) {
        auto& ce = CAPABILITY_TABLE[i];
        if (p.cap_eff & (1ULL << ce.bit)) {
            p.active_caps.push_back(ce.name);
            if (ce.dangerous) {
                p.dangerous_caps.push_back(ce.name);
                p.dangerous_privs.push_back(ce.name); // populate cross-platform field too
            }
        }
    }

    p.ns_pid  = parse_ns_inode(pid, "pid");
    p.ns_net  = parse_ns_inode(pid, "net");
    p.ns_mnt  = parse_ns_inode(pid, "mnt");
    p.ns_user = parse_ns_inode(pid, "user");

    std::string fd_dir = base + "fd";
    std::error_code ec;
    for (auto& entry : fs::directory_iterator(fd_dir, ec)) {
        fs::path target = fs::read_symlink(entry.path(), ec);
        if (ec) { ec.clear(); continue; }
        std::string tstr = target.string();
        if (fd_path_is_sensitive(tstr))
            p.sensitive_fds.push_back(tstr);
    }

    return p;
}

// ── is_system_process (Linux) ─────────────────────────────────────────────────

static bool is_system_process(const ProcessInfo& p) {
    static const std::vector<std::string> SYSTEM_NAMES = {
        "systemd", "init", "kthreadd", "ksoftirqd", "kworker",
        "migration", "rcu_", "watchdog", "kdevtmpfs", "kauditd",
        "khungtaskd", "oom_reaper", "writeback", "kcompactd",
        "ksmd", "khugepaged", "kintegrityd", "kblockd", "tpm_dev_wq",
        "edac-poller", "devfreq_wq", "kswapd", "irq/", "smpboot",
        "idle_inject", "kstrp", "zswap-shrink", "kthrotld",
        "ipv6_addrconf", "kmemleak", "jbd2", "ext4", "loop",
        "scsi_eh", "usb-storage", "bioset",
    };
    if (p.pid <= 2) return true;
    if (p.cmdline.empty() && p.name[0] == 'k') return true;
    std::string lower = p.name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (auto& sn : SYSTEM_NAMES)
        if (lower.find(sn) != std::string::npos) return true;
    return false;
}

// ── is_ai_tool ────────────────────────────────────────────────────────────────

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

// ── score_process ─────────────────────────────────────────────────────────────

std::vector<Finding> score_process(const ProcessInfo& p) {
    std::vector<Finding> out;
    if (is_system_process(p)) return out;

    static int counter = 5000;
    auto add = [&](const char* rule, Severity sev, double score,
                   std::string msg, std::string ev = "") {
        Finding f;
        f.id       = "F-" + std::to_string(++counter);
        f.rule_id  = rule;
        f.severity = sev;
        f.file     = "/proc/" + std::to_string(p.pid);
        f.message  = std::move(msg);
        f.score    = score;
        f.evidence = std::move(ev);
        out.push_back(std::move(f));
    };

    std::string proc_label = p.name + " (PID " + std::to_string(p.pid) + ")";

    if (!p.dangerous_caps.empty() && p.uid >= 1000) {
        std::string caps;
        for (auto& c : p.dangerous_caps) caps += c + " ";
        add("PROC-001", Severity::High, 7.5,
            proc_label + " (user process) has elevated capabilities",
            "CapEff: " + caps);
    }

    if (p.seccomp == 0 && p.uid == 0 && p.pid > 100) {
        add("PROC-002", Severity::Medium, 5.5,
            proc_label + " runs as root with no seccomp filter",
            "Seccomp: 0, UID: 0");
    }

    for (auto& fd_path : p.sensitive_fds) {
        add("PROC-003", Severity::High, 7.0,
            proc_label + " has sensitive file open",
            "fd \xe2\x86\x92 " + fd_path);
    }

    if (is_ai_tool(p) && !p.sensitive_fds.empty()) {
        add("PROC-004", Severity::Critical, 9.5,
            "AI tool " + proc_label + " is reading sensitive files",
            "Open sensitive FDs: " + std::to_string(p.sensitive_fds.size()));
    }

    return out;
}

// ── scan_processes ────────────────────────────────────────────────────────────

std::vector<Finding> scan_processes() {
    std::vector<Finding> results;
    for (uint32_t pid : list_pids()) {
        ProcessInfo info = read_process(pid);
        if (info.name.empty()) continue;
        auto findings = score_process(info);
        results.insert(results.end(), findings.begin(), findings.end());
    }
    return results;
}

} // namespace overtrust

#endif // __linux__

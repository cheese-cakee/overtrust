# Overtrust

> AI-era workstation security scanner. Deterministic. No LLMs.

```
 ██████╗ ██╗   ██╗███████╗██████╗ ████████╗██████╗ ██╗   ██╗███████╗████████╗
██╔═══██╗██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
██║   ██║██║   ██║█████╗  ██████╔╝   ██║   ██████╔╝██║   ██║███████╗   ██║
██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══██╗██║   ██║╚════██║   ██║
╚██████╔╝ ╚████╔╝ ███████╗██║  ██║   ██║   ██║  ██║╚██████╔╝███████║   ██║
 ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
```

Overtrust audits what your AI tools, IDE extensions, npm packages, and Docker
containers can see on your system — with zero network calls, zero token cost,
100% reproducible results, and a beautiful terminal UI.

**"An AI that audits what other AIs you've trusted — without being an AI itself."**

---

## Quick Start

**Linux / macOS**

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

./build/overtrust                     # scan home directory (TUI mode)
./build/overtrust /path/to/project    # scan specific directory
```

**Windows**

```powershell
cmake -B build -DCMAKE_BUILD_TYPE=Release -G "Visual Studio 17 2022"
cmake --build build --config Release

.\build\Release\overtrust.exe         # scan home directory
.\build\Release\overtrust.exe C:\path\to\project
```

**CLI flags**

| Flag | Description |
|------|-------------|
| `<path>` | Directory to scan (default: `$HOME`) |
| `--no-tui` | Print findings to stdout, no interactive UI |
| `--report <file>` | Write full JSON report to `<file>` after scan |
| `--exit-code` | Exit with code 1 if any findings found (CI-friendly) |
| `--version` | Print version and exit |
| `-h`, `--help` | Show usage |

---

## What It Detects

| Category | What Overtrust Finds |
|----------|---------------------|
| **IDE Extensions** | Terminal access, auth providers, debug adapters, always-on activation |
| **npm Packages** | Preinstall/postinstall scripts, curl\|bash patterns |
| **Dockerfiles** | Root containers, curl\|bash RUN instructions |
| **Secrets** | AWS keys, GitHub tokens, Anthropic/OpenAI keys, Stripe, PEM keys |
| **Credentials Files** | `~/.aws/credentials`, `.env` files, SSH private keys |
| **Processes** | Linux capabilities (CAP_SYS_PTRACE, CAP_SYS_ADMIN), open sensitive FDs; Windows elevated tokens, dangerous privileges |
| **AI Tools** | Cursor/Copilot/Codeium reading your secrets at runtime |

29 secret patterns scanned across 5 detection phases (keyword pre-filter → regex → entropy → false-positive guard → PEM context guard).

---

## Interface

```
┌─ OVERTRUST ─────────────────────── Trust Score: 34/100 [████░░░░] CRITICAL ─┐
│                                                                              │
├─ Scan Log ──────┬─ Overview ───────────────────┬─ Findings (8) ─────────────┤
│ .env            │   [SYSTEM]                   │ [CRIT] AWS credentials  [9]│
│ credentials     │   ├── [CRIT] .env file   [9] │ [CRIT] Anthropic key   [9] │
│ package.json    │   ├── [HIGH] ai-helper    [8] │ [HIGH] Extension term   [8]│
│ Dockerfile      │   └── [MED]  Dockerfile   [7] │ [HIGH] Debug adapter    [8]│
│ ✓ Scan complete │                              │ [CRIT] Auth provider    [9] │
├─ Detail ────────────────────────────────────────────────────────────────────┤
│ Rule: EXT-003  │ File: .vscode/extensions/ai-code-helper/package.json       │
│ Severity: CRITICAL  │  Score: 9.5                                           │
│ Extension 'ai-code-helper' is an authentication provider                    │
│ contributes.authentication — can intercept auth tokens                      │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Keybindings

| Key | Action |
|-----|--------|
| `j` / `↓` | Next finding |
| `k` / `↑` | Previous finding |
| `v` | Toggle graph view (compact tree ↔ visual canvas) |
| `r` | Re-scan |
| `e` | Export JSON report (auto-named with timestamp) |
| `?` | Toggle help overlay |
| `q` | Quit |

---

## Ignore file

Create `.overtrustignore` or `.trustignore` in the scan target directory:

```gitignore
# Directories to skip
vendor
node_modules/

# Path patterns
**/*.generated.h
**/third_party/
```

Plus 15 built-in noise directories are skipped automatically (`node_modules`, `.git`, `build`, `target`, `.cache`, `__pycache__`, `.npm`, `dist`, `.next`, `.nuxt`, `vendor`, `Pods`, `.stack-work`, `elm-stuff`, `.gradle`).

---

## Architecture

```
src/
├── main.cpp                  Entry point, CLI args, re-scan loop, signal handler
├── scanner/
│   ├── walker.cpp            std::filesystem recursive walker, skips noise dirs
│   ├── classifier.cpp        File type detection (path heuristics + magic bytes)
│   ├── manifest.cpp          VS Code / npm / Dockerfile parsers → Findings
│   ├── secrets.cpp           Keyword filter → regex → entropy → FP guard
│   ├── procscanner_linux.cpp /proc caps, namespace inodes, sensitive FD scan
│   ├── procscanner_win.cpp   Win32 CreateToolhelp32Snapshot, token privileges
│   └── engine.cpp            ScanEngine: orchestrates all phases in background thread
├── graph/
│   └── graph.cpp             TrustGraph: DFS reachability, permission closure, Tarjan SCC
├── tui/
│   ├── app.hpp               FTXUI App: 5-panel layout, live updates, keybindings
│   ├── splash.hpp            ASCII art banner
│   ├── widgets.hpp           Reusable FTXUI elements (trust bar, finding rows, detail)
│   ├── colors.hpp            Severity + score color palette
│   └── graph_view.hpp        Compact tree + visual canvas graph renderers
└── report.cpp                JSON report export

include/overtrust/
├── types.hpp                 Finding, ScanState, Severity
├── scanner.hpp               ScanCallbacks, walk_directory, ignore patterns
├── classifier.hpp            FileKind, classify_file
├── manifest.hpp              VsCodeExtManifest, NpmManifest, DockerfileManifest
├── secrets.hpp               SecretMatch, scan_for_secrets, shannon_entropy
├── procscanner.hpp           ProcessInfo, CapEntry, scan_processes
├── graph.hpp                 TrustGraph, GraphNode, GraphEdge
├── engine.hpp                ScanEngine
├── report.hpp                write_json_report
└── version.hpp               Version constants
```

---

## Stack

| Component | Library | Why |
|-----------|---------|-----|
| TUI | [FTXUI v5](https://github.com/ArthurSonzogni/FTXUI) | Declarative, beautiful, active development |
| JSON | [nlohmann/json](https://github.com/nlohmann/json) | Single-header, zero drama |
| Rules | Hardcoded C++ | Zero deps, deterministic, no YAML parse attack surface |
| Filesystem | `std::filesystem` (C++17) | No deps, recursive walk |
| Processes (Linux) | `/proc` pseudo-FS | Zero kernel modules, read-only |
| Processes (Windows) | Win32 `CreateToolhelp32Snapshot` | Pure Win32, no admin required |
| eBPF | libbpf (planned) | Runtime tracing for AI tool monitoring |

---

## Trust Score

```
100 → 80   TRUSTED     Green    System looks clean
 79 → 50   MODERATE    Yellow   Some risks, review findings
 49 → 25   HIGH RISK   Orange   Significant exposure
 24 →  0   CRITICAL    Red      Immediate action needed
```

Score = weighted penalty system across all findings, process risks, and graph-based risk propagation.

---

## Demo Fixtures

```bash
./build/overtrust demo/
```

The `demo/` directory contains intentionally bad configs:

- `demo/.vscode/extensions/ai-code-helper/` — extension with terminal, auth, debugger, webview
- `demo/.aws/credentials` — AWS key file
- `demo/.env` — OpenAI, Anthropic, Stripe, GitHub keys
- `demo/packages/evil-npm/` — `curl | bash` in preinstall script
- `demo/Dockerfile` — `curl | bash` + no USER directive
- `demo/scripts/deploy.sh` — hardcoded secrets

Expected trust score: ~0–15 (Critical)

---

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Overtrust Security Scan
  run: |
    ./build/overtrust --no-tui --exit-code /path/to/repo
```

Pass `--exit-code` to fail the pipeline if findings exist, and `--report overtrust-report.json` for artifact upload.

---

## Roadmap

- [ ] eBPF runtime sensor (openat/execve/connect tracepoints)
- [ ] Fanotify watch mode (`--watch` for real-time alerts)
- [ ] HTML report export (`--output report.html`)
- [ ] JetBrains `plugin.xml` scorer
- [ ] ELF static analysis (stripped binaries, unusual interpreters)
- [ ] Custom rule definitions via config file
- [ ] GitHub Actions CI integration
- [ ] SBOM output (CycloneDX / SPDX)
- [ ] Baseline diff mode (compare two scans)
- [ ] Pre-commit hook

---

## License

MIT — see [LICENSE](LICENSE)

Built with C++17, FTXUI, and systems knowledge. No AI was used in the detection logic.

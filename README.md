<p align="center">
<pre align="center">
 ██████╗ ██╗   ██╗███████╗██████╗ ████████╗██████╗ ██╗   ██╗███████╗████████╗
██╔═══██╗██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
██║   ██║██║   ██║█████╗  ██████╔╝   ██║   ██████╔╝██║   ██║███████╗   ██║
██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══██╗██║   ██║╚════██║   ██║
╚██████╔╝ ╚████╔╝ ███████╗██║  ██║   ██║   ██║  ██║╚██████╔╝███████║   ██║
 ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
</pre>
</p>

<p align="center">AI-era workstation security scanner. Deterministic. No LLMs.</p>

<p align="center">
  <a href="https://github.com/cheese-cakee/overtrust/blob/master/LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" /></a>
  <a href="https://github.com/cheese-cakee/overtrust/actions"><img alt="Build" src="https://img.shields.io/badge/build-passing-brightgreen?style=flat-square" /></a>
  <img alt="C++17" src="https://img.shields.io/badge/C%2B%2B-17-informational?style=flat-square" />
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square" />
</p>

---

```
┌─ OVERTRUST ─────────────────────────── Trust Score: 34/100 [████░░░░] CRITICAL ─┐
│                                                                                  │
├─ Scan Log ──────┬─ Overview ──────────────────┬─ Findings (8) ──────────────────┤
│ .env            │   [SYSTEM]                  │ [CRIT] AWS credentials file [9] │
│ credentials     │   ├── [CRIT] .env file  [9] │ [CRIT] Anthropic key found  [9] │
│ package.json    │   ├── [HIGH] ai-helper   [8] │ [HIGH] Extension terminal   [8] │
│ Dockerfile      │   └── [MED]  Dockerfile  [7] │ [HIGH] Debug adapter        [8] │
│ ✓ Scan complete │                             │ [CRIT] Auth provider        [9] │
├─ Detail ────────────────────────────────────────────────────────────────────────┤
│ Rule: EXT-003  │ File: .vscode/extensions/ai-code-helper/package.json           │
│ Severity: CRITICAL  │  Score: 9.5                                               │
│ Extension 'ai-code-helper' is an authentication provider                        │
│ contributes.authentication — can intercept auth tokens                          │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

### Installation

**Linux / macOS**

```bash
git clone https://github.com/cheese-cakee/overtrust.git
cd overtrust
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
./build/overtrust
```

**Windows**

> [!TIP]
> Install [Visual Studio 2022](https://visualstudio.microsoft.com/downloads/) (Desktop development with C++ workload) and [CMake](https://cmake.org/download/) — tick "Add to PATH" during the CMake install.

```powershell
git clone https://github.com/cheese-cakee/overtrust.git
cd overtrust
cmake -B build -DCMAKE_BUILD_TYPE=Release -G "Visual Studio 17 2022"
cmake --build build --config Release -j
.\build\Release\overtrust.exe
```

---

### Usage

```bash
./build/overtrust                     # scan home directory (TUI mode)
./build/overtrust /path/to/project    # scan specific directory
./build/overtrust demo/               # try the included demo fixtures
```

| Flag | Description |
|------|-------------|
| `<path>` | Directory to scan (default: `$HOME`) |
| `--no-tui` | Print findings to stdout, no interactive UI |
| `--report <file>` | Write JSON report to `<file>` (implies `--no-tui`) |

---

### What It Detects

| Category | What Overtrust Finds |
|----------|----------------------|
| **IDE Extensions** | Terminal access, auth providers, debug adapters, always-on activation |
| **npm Packages** | Preinstall/postinstall scripts, `curl\|bash` patterns |
| **Dockerfiles** | Root containers, `curl\|bash` RUN instructions |
| **Secrets** | AWS keys, GitHub tokens, Anthropic/OpenAI keys, Stripe, PEM keys |
| **Credentials Files** | `~/.aws/credentials`, `.env` files, SSH private keys |
| **Processes** | Linux capabilities (`CAP_SYS_PTRACE`, `CAP_SYS_ADMIN`), open sensitive FDs |
| **AI Tools** | Cursor/Copilot/Codeium reading your secrets at runtime |

---

### Keybindings

| Key | Action |
|-----|--------|
| `↑` / `k` | Previous finding |
| `↓` / `j` | Next finding |
| `v` | Toggle graph view (compact tree ↔ visual canvas) |
| `r` | Re-scan |
| `?` | Toggle help overlay |
| `q` | Quit |

---

### Trust Score

```
100 → 80   TRUSTED     Green    System looks clean
 79 → 50   MODERATE    Yellow   Some risks, review findings
 49 → 25   HIGH RISK   Orange   Significant exposure
 24 →  0   CRITICAL    Red      Immediate action needed
```

Score = `100 - clamp(Σ(finding.score) × 2, 0, 100)`

---

### Demo

The `demo/` directory ships with intentionally bad configs — a ready-made target for testing:

```bash
./build/overtrust demo/
# Expected trust score: ~0–15 (Critical)
```

| Fixture | What it triggers |
|---------|-----------------|
| `demo/.vscode/extensions/ai-code-helper/` | Terminal access, auth provider, debug adapter, webview |
| `demo/.aws/credentials` | AWS credentials file |
| `demo/.env` | OpenAI, Anthropic, Stripe, GitHub keys |
| `demo/packages/evil-npm/` | `curl \| bash` in preinstall script |
| `demo/Dockerfile` | `curl \| bash` + no USER directive |
| `demo/scripts/deploy.sh` | Hardcoded secrets |

---

### Architecture

```
src/
├── main.cpp                  Entry point, CLI args, wires engine → TUI
├── scanner/
│   ├── walker.cpp            std::filesystem recursive walker, skips noise dirs
│   ├── classifier.cpp        File type detection (path heuristics + magic bytes)
│   ├── manifest.cpp          VS Code / npm / Dockerfile parsers → Findings
│   ├── secrets.cpp           Keyword filter → regex → entropy → FP guard
│   ├── procscanner_linux.cpp /proc caps, namespace inodes, sensitive FD scan
│   ├── procscanner_win.cpp   Win32 process enumeration, token privileges, elevation check
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
├── classifier.hpp            FileKind, classify_file
├── manifest.hpp              VsCodeExtManifest, NpmManifest, DockerfileManifest
├── secrets.hpp               SecretMatch, scan_for_secrets, shannon_entropy
├── procscanner.hpp           ProcessInfo, CapEntry, scan_processes
├── graph.hpp                 TrustGraph, GraphNode, GraphEdge
├── engine.hpp                ScanEngine
└── report.hpp                write_json_report
```

---

### Stack

| Component | Library | Why |
|-----------|---------|-----|
| TUI | [FTXUI v5](https://github.com/ArthurSonzogni/FTXUI) | Declarative, beautiful, active development |
| JSON | [nlohmann/json](https://github.com/nlohmann/json) | Single-header, zero drama |
| Rules | Hardcoded C++ | Zero deps, deterministic, no YAML parse attack surface |
| Filesystem | `std::filesystem` (C++17) | No deps, recursive walk |
| Processes (Linux) | `/proc` pseudo-FS | Zero kernel modules, read-only |
| Processes (Windows) | Win32 `CreateToolhelp32Snapshot` | Pure Win32, no admin required |

---

### Roadmap

- [ ] eBPF runtime sensor (openat/execve/connect tracepoints)
- [ ] Fanotify watch mode (`--watch` for real-time alerts)
- [ ] HTML report export (`--output report.html`)
- [ ] JetBrains `plugin.xml` scorer
- [ ] ELF static analysis (stripped binaries, unusual interpreters)
- [ ] Custom rule definitions via config file
- [ ] GitHub Actions CI integration

---

### FAQ

#### How is this different from other security scanners?

Most scanners are cloud-based, LLM-powered, or require agents/daemons. Overtrust is different:

- **100% offline** — zero network calls, ever
- **Deterministic** — same input always produces the same findings, no AI hallucinations
- **AI-aware** — specifically targets the new attack surface created by IDE AI tools (Cursor, Copilot, Codeium) that have broad filesystem access
- **Zero runtime cost** — no tokens, no subscriptions, no API keys needed to run it
- **Single binary** — ships as one statically-linked executable

#### Does it require root / admin?

No. Overtrust only reads files and `/proc` entries it has permission to access. It will skip anything it can't read and note it in the scan log.

#### Is any data sent anywhere?

Never. All analysis is local. No telemetry, no crash reports, no update checks.

---

### Contributing

PRs welcome. Read the code first — it's small and well-commented.

---

### License

MIT — see [LICENSE](LICENSE)

> Built with C++17, FTXUI, and systems knowledge. No AI was used in the detection logic.

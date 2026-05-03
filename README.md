<p align="center">
  <img src="https://storage.googleapis.com/runable-templates/cli-uploads%2FH8YZRVcKqo1iYrAhLBkIjhBo6MSmtriB%2FAMVtcE1gT2LdpcqCCsVs0%2Fdemo_real.gif" alt="Overtrust demo" width="800" />
</p>
<p align="center"><a href="https://overtrust.runable.site/"><strong>Overtrust</strong></a> is an AI-era workstation security scanner. Deterministic. No LLMs.
</p> </p>
<p align="center">
  <a href="https://github.com/cheese-cakee/overtrust/blob/master/LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" /></a>
  <img alt="Version" src="https://img.shields.io/badge/version-0.1.0-informational?style=flat-square" />
  <img alt="C++17" src="https://img.shields.io/badge/C%2B%2B-17-informational?style=flat-square" />
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square" />
</p>

---

```
 OVERTRUST │ Trust Score: 34/100 [████████░░░░░░░░░░░░░░░░] CRITICAL
───────────┼───────────────────────────────────────────────────────────────────
 Scan Log  │ Overview              │ Findings (8)
───────────┤ ● 3 critical          │ [CRIT] AWS credentials file      [9.0]
 .env      │ ● 2 high              │ [CRIT] Anthropic key in .env     [9.0]
 creds     │ ● 1 medium            │ [CRIT] Auth provider extension   [9.5]
 pkg.json  │ ● 1 low               │ [HIGH] Extension terminal access [8.0]
 Dockerf.. │                       │ [HIGH] SSH private key exposed   [7.5]
 ✓ done    │ Press v for graph     │ [HIGH] Debug adapter             [8.0]
───────────┴───────────────────────┴───────────────────────────────────────────
 Detail
 Rule: EXT-003  │ File: .vscode/extensions/ai-code-helper/package.json
 Severity: CRITICAL  │  Score: 9.5
 Extension 'ai-code-helper' is an authentication provider
 contributes.authentication — can intercept auth tokens
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
> Install [Visual Studio 2022](https://visualstudio.microsoft.com/downloads/) with the **Desktop development with C++** workload, and [CMake](https://cmake.org/download/) — tick **"Add CMake to the system PATH"** during install.

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
./build/overtrust                       # scan $HOME (TUI mode)
./build/overtrust /path/to/project      # scan a specific directory
./build/overtrust demo/                 # try the included demo fixtures
./build/overtrust --no-tui              # headless JSON output to stdout
./build/overtrust --report out.json     # write full JSON report to file
./build/overtrust --exit-code           # exit 1 if any findings found (CI use)
```

| Flag | Description |
|------|-------------|
| `<path>` | Directory to scan (default: `$HOME`) |
| `--no-tui` | Headless mode — prints findings as JSON to stdout |
| `--report <file>` | Write full JSON report to file after scan |
| `--exit-code` | Exit with code `1` if any findings exist (useful in CI) |
| `--version` | Print version and exit |
| `-h`, `--help` | Show usage |

> [!NOTE]
> `--no-tui` is automatically activated when stdout is not a TTY (e.g. piped or redirected), making it safe to use in scripts and CI without extra flags.

---

### What It Detects

| Category | What Overtrust Finds |
|----------|----------------------|
| **IDE Extensions** | Terminal access, auth providers, debug adapters, always-on activation |
| **npm Packages** | Preinstall/postinstall scripts, `curl\|bash` patterns |
| **Dockerfiles** | Root containers, `curl\|bash` RUN instructions |
| **Secrets** | AWS keys, GitHub tokens, Anthropic/OpenAI keys, Stripe, PEM certs |
| **Credentials Files** | `~/.aws/credentials`, `.env` files, SSH private keys |
| **Kubernetes** | `~/.kube/config` — may contain cluster credentials and bearer tokens |
| **Shell History** | `.bash_history`, `.zsh_history` — may contain secrets typed in plain text |
| **Processes (Linux)** | `CAP_SYS_PTRACE`, `CAP_SYS_ADMIN`, open sensitive file descriptors |
| **Processes (Windows)** | `SeDebugPrivilege`, `SeTcbPrivilege`, elevated tokens, dangerous privileges |
| **AI Tools** | Cursor, Copilot, Codeium and others running with access to your secrets |

---

### Keybindings

| Key | Action |
|-----|--------|
| `↑` / `k` | Previous finding |
| `↓` / `j` | Next finding |
| `v` | Toggle graph view (overview ↔ trust graph canvas) |
| `r` | Re-scan |
| `e` | Export JSON report and exit |
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

### Ignoring Paths

Create a `.overtrustignore` or `.trustignore` file in the scanned directory to skip paths:

```
# ignore local dev directories
.dev-secrets/
vendor/
my-test-env/
```

Lines starting with `#` are comments. Both file/directory names and path substrings are matched.

---

### Demo

The `demo/` directory ships with intentionally bad configs — a ready-made target for testing:

```bash
./build/overtrust demo/
# Expected trust score: ~0–15 (Critical)
```

| Fixture | What it triggers |
|---------|-----------------|
| `demo/.vscode/extensions/ai-code-helper/` | Terminal, auth provider, debug adapter, webview |
| `demo/.aws/credentials` | AWS credentials file |
| `demo/.env` | OpenAI, Anthropic, Stripe, GitHub keys |
| `demo/packages/evil-npm/` | `curl \| bash` in preinstall script |
| `demo/Dockerfile` | `curl \| bash` + no USER directive |
| `demo/scripts/deploy.sh` | Hardcoded secrets |

---

### CI Integration

```yaml
# .github/workflows/overtrust.yml
- name: Run overtrust
  run: |
    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j$(nproc)
    ./build/overtrust ${{ github.workspace }} --exit-code --report overtrust.json
- name: Upload report
  uses: actions/upload-artifact@v4
  with:
    name: overtrust-report
    path: overtrust.json
```

`--exit-code` makes the step fail if any findings are found. Pipe the JSON output to your security dashboard or SIEM.

---

### Architecture

```
src/
├── main.cpp                  Entry point, CLI args, signal handling, TUI/headless dispatch
├── scanner/
│   ├── walker.cpp            Recursive filesystem walker, skips noise dirs, respects ignore files
│   ├── classifier.cpp        File type detection (path heuristics + magic bytes)
│   ├── manifest.cpp          VS Code / npm / Dockerfile parsers → Findings
│   ├── secrets.cpp           Keyword filter → regex → entropy → FP guard
│   ├── procscanner_linux.cpp /proc caps, namespace inodes, sensitive FD scan
│   ├── procscanner_win.cpp   Win32 process enumeration, token privileges, elevation check
│   └── engine.cpp            ScanEngine: orchestrates all phases in a background thread
├── graph/
│   └── graph.cpp             TrustGraph: DFS reachability, permission closure, Tarjan SCC
├── tui/
│   ├── app.hpp               FTXUI App: 5-panel layout, live updates, keybindings
│   ├── splash.hpp            Splash screen with ASCII banner
│   ├── widgets.hpp           Reusable FTXUI elements (trust bar, finding rows, detail panel)
│   ├── colors.hpp            Severity + score color palette
│   └── graph_view.hpp        Compact tree + visual canvas graph renderers
└── report.cpp                JSON report export

include/overtrust/
├── version.hpp               Version constants (APP_NAME, VERSION)
├── types.hpp                 Finding, ScanState, ScanSummary, Severity, next_finding_id()
├── scanner.hpp               ScanCallbacks, walk_directory, ignore file loading
├── classifier.hpp            FileKind enum, classify_file()
├── manifest.hpp              VsCodeExtManifest, NpmManifest, DockerfileManifest
├── secrets.hpp               SecretMatch, scan_for_secrets(), shannon_entropy()
├── procscanner.hpp           ProcessInfo, CapEntry, scan_processes(), is_ai_tool()
├── graph.hpp                 TrustGraph, GraphNode, GraphEdge, compute_trust_score()
├── engine.hpp                ScanEngine
└── report.hpp                write_json_report()
```

---

### Stack

| Component | Library | Why |
|-----------|---------|-----|
| TUI | [FTXUI v5](https://github.com/ArthurSonzogni/FTXUI) | Declarative, beautiful, active maintenance |
| JSON | [nlohmann/json v3.11](https://github.com/nlohmann/json) | Single-header, zero drama |
| Rules | Hardcoded C++ | Zero deps, deterministic, no YAML parse attack surface |
| Filesystem | `std::filesystem` (C++17) | No deps, recursive walk with permission skip |
| Processes (Linux) | `/proc` pseudo-FS | Zero kernel modules, read-only |
| Processes (Windows) | Win32 `CreateToolhelp32Snapshot` + `Advapi32` | Pure Win32, no admin required |
| Build | CMake 3.16+ with `FetchContent` | Auto-fetches FTXUI and nlohmann/json |

---

### FAQ

#### Does it require root / admin?

No. Overtrust only reads files and `/proc` entries it already has permission to access. Anything it can't read is silently skipped. On Windows, process enumeration works without elevation — privilege details for protected processes are simply omitted.

#### Is any data sent anywhere?

Never. All analysis is fully local. No telemetry, no crash reports, no network calls of any kind.

#### How is it different from other scanners?

- **Offline-first** — no API keys, no cloud, no tokens consumed
- **Deterministic** — identical input always produces identical output
- **AI-aware** — specifically built for the new attack surface created by AI coding tools with broad filesystem access
- **Single binary** — one statically-linked executable, no runtime dependencies

#### Why not just use a linter or secrets scanner?

Those tools find secrets in code. Overtrust finds what already has *access* to your secrets right now — running processes, IDE extensions with elevated permissions, misconfigured containers, and credential files sitting in readable directories.

---

### Contributing

PRs welcome. Read the code first — it's small and well-commented.

---

### License

MIT — see [LICENSE](LICENSE)

> Built with C++17, FTXUI, and systems knowledge. No AI was used in the detection logic.

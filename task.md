# Sentinel Build Plan

## Stack
- C++17/20 + CMake
- FTXUI (TUI)
- libbpf (eBPF, optional/later)
- nlohmann/json
- yaml-cpp
- std::filesystem, std::regex, std::thread

## Commit Sequence (gradual, readable)

### Commit 1: Project scaffold
- CMakeLists.txt with FetchContent for FTXUI, nlohmann/json, yaml-cpp
- src/ structure: main.cpp, scanner/, tui/, rules/, graph/
- .gitignore, README skeleton
- Basic "Hello World" TUI that opens and closes

### Commit 2: TUI shell + layout
- Full 5-panel layout (top bar, left log, center graph, right findings, bottom detail)
- Keyboard input: q quit, ? help, arrows navigate, v toggle view
- Splash screen with ASCII art "SENTINEL"
- Placeholder data in all panels

### Commit 3: Filesystem walker
- Recursive walker using std::filesystem
- Collect metadata: size, perms, mtime, magic bytes
- Skip noise: node_modules/, .git/, build/
- Stream results to TUI left panel in real-time (thread)

### Commit 4: File classifier + manifest parsers
- File type detection (extension + magic bytes)
- VS Code package.json parser (contributes, activationEvents)
- npm package.json parser (scripts, dependencies)
- Dockerfile parser (FROM, RUN, USER)
- Basic struct for ScanResult

### Commit 5: Secret detector
- Aho-Corasick style keyword scan (manual trie or std::string find, AKIA/ghp_/sk-ant- etc.)
- Regex patterns for AWS, GitHub, Stripe, OpenAI keys
- Shannon entropy filter
- False positive exclusions

### Commit 6: Scoring engine + YAML rules
- Rule struct (id, name, severity, score)
- Load rules from rules/default.yaml
- Score each finding
- Aggregate trust score (0-100)

### Commit 7: Trust graph engine
- Node/Edge structs (extension, package, file, process, permission)
- Build graph from findings
- DFS reachability (blast radius)
- Permission closure

### Commit 8: TUI integration (live scan)
- Wire scanner to TUI state (atomic flags, mutex-guarded queue)
- Live findings list (right panel) with scrollable table
- Trust score animated bar (top)
- Finding detail view (bottom panel)

### Commit 9: TUI graph view
- Compact mode: tree-style text in center panel
- Visual mode (v): Unicode node/edge drawing
- Navigate nodes, press Enter for details

### Commit 10: /proc + capability scanner
- Parse /proc/[pid]/status for capabilities
- Decode CapEff bitmask → named caps
- Flag dangerous: CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_MODULE
- Parse /proc/[pid]/fd for open files
- Add process findings to trust graph

### Commit 11: Polish + demo prep
- Help overlay (?)
- Error handling (small terminal, permission denied)
- JSON report export (--output report.json)
- README with GIF placeholder + keybindings table

## Current status: Starting commit 1

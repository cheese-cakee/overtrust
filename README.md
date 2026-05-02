# Sentinel

> AI-era workstation security scanner. Deterministic. No LLMs.

```
Trust Score: 34/100 [████░░░░░░░░░░░░░░░░] CRITICAL
```

Sentinel audits what your AI tools, IDE extensions, npm packages, and Docker
containers can see on your system — with zero network calls, zero token cost,
and 100% reproducible results.

## Install

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
./build/sentinel
```

## Keybindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `?` | Help |
| `↑↓` | Navigate findings |
| `Enter` | View finding detail |
| `v` | Toggle graph view |
| `r` | Re-scan |

## Architecture

- **Layer 1:** Dispatch (file classifier, OS detection, rule loader)
- **Layer 2:** Sensors (procfs, filesystem walker, eBPF)
- **Layer 3:** Scanning engine (Aho-Corasick → entropy → regex → parse → score)
- **Layer 4:** Graph engine (trust graph, reachability, centrality)
- **Layer 5:** TUI (FTXUI, keyboard-driven, shareable)

## Stack

- C++17 + CMake
- [FTXUI](https://github.com/ArthurSonzogni/FTXUI) — TUI
- [nlohmann/json](https://github.com/nlohmann/json) — JSON parsing
- [yaml-cpp](https://github.com/jbeder/yaml-cpp) — Rule definitions
- libbpf (optional, for eBPF runtime sensors)

## License

MIT

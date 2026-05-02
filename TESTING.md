# Overtrust — Rigorous Testing Guide

## 1. Smoke Test (30 seconds)

```bash
./build/overtrust --version          # sanity check
./build/overtrust --help
./build/overtrust demo/              # should find 10-20 findings, score ≤ 15
```

Expected findings from `demo/`:
| Rule | What | Expected Severity |
|------|------|-------------------|
| EXT-003 | ai-code-helper auth provider | CRITICAL |
| EXT-001 | ai-code-helper terminal | HIGH |
| EXT-002 | ai-code-helper debugger | HIGH |
| EXT-004 | ai-code-helper webview | MEDIUM |
| EXT-005 | ai-code-helper always-on | MEDIUM |
| NPM-001 | evil-npm curl\|bash preinstall | CRITICAL |
| FILE-002 | .aws/credentials | CRITICAL |
| SEC-001 | AWS key in credentials file | CRITICAL |
| DOCKER-001 | Dockerfile no USER | HIGH |
| DOCKER-002 | Dockerfile curl\|bash | CRITICAL |
| SEC-007 | OpenAI key in .env | CRITICAL |
| SEC-006 | Anthropic key in .env | CRITICAL |
| SEC-008 | Stripe live key in .env | CRITICAL |
| SEC-003 | GitHub token in .env | CRITICAL |

---

## 2. Unit Tests (write these — they're small)

Create `tests/` directory with a simple test runner (no framework needed — just `assert`):

### 2.1 Classifier tests

```cpp
// tests/test_classifier.cpp
#include <cassert>
#include "overtrust/classifier.hpp"

int main() {
    using namespace overtrust;

    // Path heuristics
    assert(classify_file("/home/user/.aws/credentials") == FileKind::AwsCredentials);
    assert(classify_file("/home/user/.ssh/id_rsa")      == FileKind::SshKey);
    assert(classify_file("/home/user/.ssh/id_rsa.pub")  != FileKind::SshKey);  // pub key
    assert(classify_file("/home/user/.env")             == FileKind::DotEnv);
    assert(classify_file("/home/user/.env.local")       == FileKind::DotEnv);
    assert(classify_file("Dockerfile")                  == FileKind::Dockerfile);
    assert(classify_file("Dockerfile.prod")             == FileKind::Dockerfile);

    // VS Code extension detection
    assert(classify_file("/home/user/.vscode/extensions/foo/package.json")
                                                        == FileKind::VsCodeExtension);
    // Generic npm (not in extensions dir)
    assert(classify_file("/home/user/project/package.json")
                                                        == FileKind::NpmPackageJson);

    printf("classifier: all tests passed\n");
    return 0;
}
```

### 2.2 Secret detector tests

```cpp
// tests/test_secrets.cpp
#include <cassert>
#include "overtrust/secrets.hpp"

int main() {
    using namespace overtrust;

    // Should find AWS key
    auto m = scan_for_secrets("aws_access_key_id = AKIAI44QH8DHBEXAMPLE", "test.env");
    assert(!m.empty());
    assert(m[0].rule_id == "SEC-001");

    // Should NOT match false positive
    auto m2 = scan_for_secrets("key = AKIAIOSFODNN7EXAMPLE", "test.env");
    assert(m2.empty());  // this is the AWS docs example key

    // GitHub token
    auto m3 = scan_for_secrets("token = ghp_16C7e42F292c6912E169ABCdefGHIjklMNOp", "test");
    assert(!m3.empty());
    assert(m3[0].rule_id == "SEC-003");

    // PEM key
    auto m4 = scan_for_secrets("-----BEGIN RSA PRIVATE KEY-----", "id_rsa");
    assert(!m4.empty());
    assert(m4[0].rule_id == "SEC-012");

    // No false fire on empty file
    auto m5 = scan_for_secrets("", "empty.txt");
    assert(m5.empty());

    // Entropy test: low-entropy "secret" should not fire SEC-013
    auto m6 = scan_for_secrets("secret = aaaaaaaaaaaaaaaaaaaaaa", "test");
    assert(m6.empty());  // entropy < 3.8

    printf("secrets: all tests passed\n");
    return 0;
}
```

### 2.3 Shannon entropy tests

```cpp
// tests/test_entropy.cpp
#include <cassert>
#include <cmath>
#include "overtrust/secrets.hpp"

int main() {
    using namespace overtrust;

    // Uniform byte = max entropy
    std::string uniform;
    for (int i = 0; i < 256; ++i) uniform += (char)i;
    assert(shannon_entropy(uniform) > 7.9);

    // All same byte = 0 entropy
    assert(shannon_entropy(std::string(100, 'a')) < 0.01);

    // Empty = 0
    assert(shannon_entropy("") == 0.0);

    // Base64-like string should be ~5.5-6
    double e = shannon_entropy("sk-ant-api03ABCDEFGHIJKLMNOPabcdefghijklmno");
    assert(e > 4.0 && e < 7.0);

    printf("entropy: all tests passed\n");
    return 0;
}
```

### 2.4 Manifest parser tests

```cpp
// tests/test_manifest.cpp — test against demo fixtures
#include <cassert>
#include "overtrust/manifest.hpp"

int main() {
    using namespace overtrust;

    auto m = parse_vscode_manifest("demo/.vscode/extensions/ai-code-helper-1.2.0/package.json");
    assert(m.name == "ai-code-helper");
    assert(m.has_terminal == true);
    assert(m.has_auth_provider == true);
    assert(m.has_debugger == true);
    assert(m.has_webview == true);
    assert(m.always_on == true);

    auto findings = score_vscode_ext(m, "test");
    // Should have at least EXT-001, EXT-002, EXT-003, EXT-004, EXT-005
    assert(findings.size() >= 5);

    // Dockerfile
    auto d = parse_dockerfile("demo/Dockerfile");
    assert(d.runs_as_root == true);
    assert(d.has_curl_pipe_bash == true);

    // npm
    auto n = parse_npm_manifest("demo/packages/evil-npm/package.json");
    assert(n.has_preinstall == true);
    assert(!n.suspicious_scripts.empty());

    printf("manifest: all tests passed\n");
    return 0;
}
```

### 2.5 Trust graph tests

```cpp
// tests/test_graph.cpp
#include <cassert>
#include "overtrust/types.hpp"
#include "overtrust/graph.hpp"

int main() {
    using namespace overtrust;

    // Empty findings → score 100
    TrustGraph g = build_trust_graph({});
    assert(compute_trust_score(g) == 100);

    // Single critical finding → low score
    Finding f;
    f.id = "F-1"; f.rule_id = "EXT-003";
    f.severity = Severity::Critical; f.score = 9.5;
    f.file = "/test/ext/package.json";

    TrustGraph g2 = build_trust_graph({f});
    int score = compute_trust_score(g2);
    assert(score < 50);

    // Reachability: root → file node
    auto reachable = g2.reachable_from("system");
    assert(reachable.count("file:/test/ext/package.json") > 0);

    printf("graph: all tests passed\n");
    return 0;
}
```

### Add tests to CMakeLists.txt

```cmake
# At the bottom of CMakeLists.txt:
enable_testing()

foreach(test classifier secrets entropy manifest graph)
    add_executable(test_${test} tests/test_${test}.cpp
        # add the relevant .cpp files each test needs
    )
    target_include_directories(test_${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(test_${test} PRIVATE nlohmann_json::nlohmann_json)
    add_test(NAME ${test} COMMAND test_${test})
endforeach()
```

Run: `cmake --build build && ctest --test-dir build -V`

---

## 3. Integration Tests (against real system)

### 3.1 Run on your home directory

```bash
./build/overtrust ~
```

What to verify:
- Doesn't crash on symlinks, permission-denied dirs, empty files, binary files
- Scans complete (doesn't hang)
- Findings make sense (no obviously wrong positives)

### 3.2 Run on a known-clean directory

```bash
mkdir /tmp/clean_dir && echo "hello world" > /tmp/clean_dir/test.txt
./build/overtrust /tmp/clean_dir
```
Expected: trust score = 100, 0 findings.

### 3.3 Run on a large codebase (stress test)

```bash
# Clone a big project
git clone --depth=1 https://github.com/torvalds/linux /tmp/linux-src
time ./build/overtrust /tmp/linux-src
```
What to check:
- Completes in < 30 seconds for ~80k files
- No memory blow-up (`/usr/bin/time -v ./build/overtrust /tmp/linux-src`)
- Walker correctly skips `.git/`, `build/`

### 3.4 False positive test

```bash
# Scan a well-known open-source project with no real secrets
git clone --depth=1 https://github.com/redis/redis /tmp/redis
./build/overtrust /tmp/redis
```
Should find: Dockerfile issues (runs as root likely), maybe npm scripts. Should NOT find: real secrets (it's a public repo).

### 3.5 Test permission-denied handling

```bash
./build/overtrust /root     # non-root — should silently skip, not crash
./build/overtrust /proc     # pseudo-fs — should handle gracefully
./build/overtrust /dev      # device files — should skip binary, not hang
```

---

## 4. Process Scanner Tests

### 4.1 Verify it reads your own process

```bash
# Run as current user, check that your shell shows up in /proc scan
./build/overtrust /tmp/clean_dir 2>&1 | grep -i "proc"
```

### 4.2 Verify capability decode

```bash
# Check what caps the test process itself has
cat /proc/$$/status | grep Cap
# Then run overtrust and see if it decodes them the same way
capsh --decode=$(cat /proc/$$/status | grep CapEff | awk '{print $2}')
```

### 4.3 Root-specific test (if you have sudo)

```bash
sudo ./build/overtrust /etc
```
Expected: More findings visible (can read more FDs), /etc/shadow etc. visible.

---

## 5. Edge Cases to Hammer

| Case | How to Test |
|------|-------------|
| Empty file | `touch /tmp/empty && ./build/overtrust /tmp` |
| Binary file with secret-like bytes | `printf '\x41\x4b\x49\x41AAAAAAAAAAAAAAAA' > /tmp/bin.bin` |
| Symlink loop | `mkdir /tmp/loop && ln -s /tmp/loop /tmp/loop/self && ./build/overtrust /tmp/loop` |
| 0-byte permissions file | `chmod 000 /tmp/noperm && ./build/overtrust /tmp` |
| Very long filename | `python3 -c "open('/tmp/' + 'a'*200 + '.env','w').write('x=y')"` |
| Unicode path | `mkdir /tmp/tëst && touch '/tmp/tëst/.env'` |
| File removed mid-scan | Race condition: delete a file while scanner is running |
| /proc/[pid] disappears | Process dies during scan — `read_process()` should return empty |

---

## 6. Performance Profiling

```bash
# Install perf tools
sudo apt-get install -y linux-perf valgrind

# Valgrind memcheck (use small dir, it's slow)
valgrind --leak-check=full --error-exitcode=1 \
  ./build/overtrust demo/ 2>&1 | tail -20

# Measure peak RSS on large scan
/usr/bin/time -v ./build/overtrust ~ 2>&1 | grep "Maximum resident"

# CPU profile on big dir
perf record -g ./build/overtrust /tmp/linux-src
perf report --stdio | head -40
```

Target metrics:
- **100k files**: < 5 seconds wall time
- **Peak RSS**: < 100MB
- **No leaks** in Valgrind on `demo/`

---

## 7. AddressSanitizer Build

The CMakeLists.txt already enables ASan in Debug builds:

```bash
cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug
cmake --build build-asan -j$(nproc)
./build-asan/overtrust demo/
./build-asan/overtrust ~
```

ASan catches: buffer overflows, use-after-free, heap corruption, stack overflows.

---

## 8. Fuzz Testing (advanced)

Secret detector and manifest parsers are good fuzz targets since they consume untrusted input.

```bash
# LibFuzzer target for scan_for_secrets
cat > tests/fuzz_secrets.cpp << 'EOF'
#include "overtrust/secrets.hpp"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string input(reinterpret_cast<const char*>(data), size);
    overtrust::scan_for_secrets(input, "fuzz.txt");
    return 0;
}
EOF

clang++ -fsanitize=fuzzer,address -std=c++17 \
  tests/fuzz_secrets.cpp src/scanner/secrets.cpp \
  -I include -o fuzz_secrets

./fuzz_secrets -max_total_time=60   # run for 60 seconds
```

---

## Quick test sequence before a commit

```bash
# Build Debug (ASan)
cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug && cmake --build build-asan -j$(nproc)

# Core functionality
./build-asan/overtrust demo/               # should produce ~15 findings, score ≤ 15
./build-asan/overtrust /tmp/clean_dir      # should produce 0 findings, score = 100

# Crash resistance
./build-asan/overtrust /proc               # should not crash
./build-asan/overtrust /dev/null           # degenerate input

# Memory clean
valgrind --error-exitcode=1 ./build/overtrust demo/ && echo "CLEAN"
```

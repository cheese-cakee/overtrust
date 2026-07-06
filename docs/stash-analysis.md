# Stash, Supermemory, Mem0 — and where I can move the needle

**Prepared by Farzan Aman Khan · for Fergana Labs · July 2026**

---

## TL;DR

**Supermemory and Mem0 sell memory primitives to app developers:** an LLM distills conversations into facts, stores them in vector-and-graph indexes, and serves them back through an API. **Stash sells legible, team-shared memory to people who run coding agents:** memory is files, the interface is a filesystem, and humans and agents read and write the same workspace.

That is a different layer of the stack — and for coding agents specifically, I think it's the right one. Below: the comparison, the hard problems I see coming, and the exact places I'd contribute, with receipts.

---

## 01 · Three products, two philosophies

### Mem0 — open-source memory layer

The default OSS choice. Pipeline: an LLM extracts salient facts from conversation, links entities, and writes into a hybrid store (vector + graph + key-value). Retrieval fuses semantic search, BM25, and entity matching. Memory is scoped per user, session, and agent. Research-backed — their paper reports ~26% higher accuracy than OpenAI's built-in memory on long-conversation benchmarks. Fundamentally a *personalization* layer: what should the model remember about this user?

### Supermemory — managed memory API

Same layer, more managed polish. A vector-graph engine with automatic fact extraction, contradiction resolution ("I moved to SF" supersedes "I live in NYC"), decay and recency bias, sub-400ms retrieval claims, connectors (Drive, Gmail, Notion, GitHub), and pluggable vector backends. Positioned as a drop-in beneath your existing AI SDK stack. Strong infrastructure — but the memory itself is machine-managed and largely opaque to the people it describes.

### Stash — shared knowledge base for the agent era

A different bet. Sessions (full agent transcripts streamed via hooks), pages and tables that humans and agents co-edit in real time, Skills as the sharing/forking unit, connectors — and three agent-native interfaces: CLI, MCP server, and the VFS shell (`stash vfs ls /`, `find`, `rg`). MIT-licensed, self-hostable via Docker Compose, and the LLM features are optional rather than load-bearing.

The clean way to say it: **Mem0 and Supermemory answer "what should the model remember about this user?" Stash answers "what does this team — humans and agents together — know?"** Those sound similar in a pitch deck and are completely different systems to build.

---

## 02 · Side by side

| | **Stash** | **Supermemory** | **Mem0** |
|---|---|---|---|
| Unit of memory | Files: sessions, pages, tables — human-readable | LLM-extracted facts + chunks in a vector-graph | Extracted "memories" with entity links |
| Write path | Hooks stream full transcripts; humans & agents edit pages directly | Extraction pipeline at ingestion | Extraction pipeline (add-heavy, entity linking) |
| Read path | `ls` / `find` / `rg` + semantic & keyword search with citations | Hybrid RAG + memory API, sub-400ms claim | Semantic + BM25 + entity fusion |
| Interface | VFS shell, CLI, MCP, collaborative web UI | REST API / SDKs | SDKs / API / managed platform |
| Legibility | Fully legible — memory can be reviewed, diffed, edited | Machine-managed; facts visible but not the reasoning | Machine-managed |
| Sharing scope | Team-wide; Skills forkable public/private | Per end-user profiles | Per user / session / agent |
| Works without LLM | Yes — keyword search and VFS are deterministic | No — extraction is the product | No — extraction needs a model |
| Self-host | Docker Compose, MIT | OSS core, cloud-first positioning | OSS + managed platform |
| Who buys | Teams running Claude Code / Cursor at work | App developers adding personalization | App developers adding personalization |

---

## 03 · Why I think the filesystem bet is right

**The interface matches agent priors.** Coding agents are post-trained on millions of trajectories of `ls`, `find`, and `grep`. The VFS is zero-shot usable — no tool schema to learn, no retrieval API to wrap. More importantly, it turns retrieval into *navigation*: an agent can orient (`ls`), narrow (`find -maxdepth 3`), and confirm (`rg`) with deterministic, reproducible results. Top-k vector retrieval fails silently; a failed `rg` tells the agent what *doesn't* exist, which is itself signal.

**Memory you can code-review.** In extracted-fact stores, a wrong memory is discovered at inference time, by the model, silently. In Stash, contradiction resolution is a diff on a page — a human problem solved with human tools. For teams this isn't a nicety; auditable memory is the enterprise unlock.

**Session capture is the actual moat.** Per-user preference memory is a thin moat — every player has it. Full transcripts of what agents attempted, decided, and abandoned is data nobody else captures. The most expensive knowledge in a codebase is *why the last attempt failed*, and Stash is the only one of the three that stores it.

**Graceful degradation.** No Anthropic key? Stash is still a fast, searchable team knowledge base. A deterministic core with optional intelligence is the right dependency direction — the competitors are inverted: remove the LLM and there's no product left.

**Self-hosting is the wedge, not a checkbox.** Transcripts are the most sensitive artifact an engineering org produces. The orgs that most need shared agent memory are exactly the orgs that can't stream it to a third-party cloud. MIT + Docker Compose isn't a community gesture — it's the go-to-market.

---

## 04 · The hard problems coming (honest section)

1. **Transcripts are a secrets firehose.** Tool calls embed env output, API tokens, connection strings. Streaming them into shared, searchable, team-wide memory turns one leaked secret into everyone's secret — surfaced to every future agent session by the very search that makes Stash useful. This needs redaction *at ingest, client-side, before upload*. (This is the problem I've already built a scanner for — see below.)

2. **`rg /` stops scaling.** A live regex scan over a growing corpus of sessions degrades linearly. The fix that preserves the VFS surface is incremental trigram indexing (zoekt-style) behind the same commands, plus client-side caching in the CLI. The interface is the moat; the implementation underneath can get smarter without changing it.

3. **Memory rot.** Files don't decay, and a stale runbook is worse than no runbook. Managed forgetting is the one thing Mem0/Supermemory genuinely have that files don't. The file-native answer is staleness *signals*, not LLM guessing: last-verified metadata, citation age weighted into search ranking, "this page contradicts a newer session" flags.

4. **Self-host version skew.** Your issue [#563](https://github.com/Fergana-Labs/stash/issues/563) — CLI↔server version handshake for self-hosted instances. Boring and load-bearing: silent CLI/server mismatch is exactly the kind of failure that erodes trust with the self-host audience that (per above) is the wedge.

5. **The 49% claim needs receipts.** "49% faster from internal testing" is a great number with no public methodology. The evaluation harness in [PR #85](https://github.com/Fergana-Labs/stash/pull/85) is the seed of the fix: a reproducible public benchmark turns a marketing claim into evidence competitors have to respond to.

---

## 05 · Where I fit — with receipts

### Secret redaction at ingest
- **Evidence:** I built [Overtrust](https://github.com/cheese-cakee/overtrust), a deterministic security scanner whose core is exactly this pipeline: keyword prefilter → regex → Shannon-entropy scoring → false-positive guard, tuned so it doesn't drown users in noise.
- **First PR:** Port the detection pass into the session-streaming hook path (Python), behind a config flag: transcripts scrubbed client-side before upload, findings logged locally. The entropy + FP-guard stages are what make it usable rather than annoying.

### Issue #563 — CLI↔server version handshake
- **Evidence:** LFX mentee at Linux Foundation Decentralized Trust: designed and built the Hiero GitHub Workflow App — webhook routing, AJV schema-validated config engine, a normalized API layer across 10 wrappers, 138 tests at 94% coverage.
- **First PR:** Version + capability negotiation on connect, with explicit, actionable mismatch errors. Shippable in week one; I'd use it as my ramp-up task.

### Retrieval performance and ranking
- **Evidence:** Last few weeks at Lucebox: 14 PRs, 12 merged — including prefix-aware cache eviction (#452), pinned-copy-stream async page ops (#408), and ranking-aware loss training, ListNet/RankNet (#411). Before that: a GEMM kernel at 490 GFLOPS (65% of theoretical peak) built by profiling, not guessing.
- **First PR:** Profile `stash vfs rg` against a large synthetic stash, publish the numbers, then attack the top bottleneck — likely incremental indexing or CLI-side caching.

### Storage semantics under the VFS
- **Evidence:** 8 merged PRs in Ceph RGW under 1-on-1 mentorship from a core maintainer: S3 `x-amz-request-id` compliance, CLI migration PoC, live debugging of bucket-notification engine crashes. Object-store semantics, API compatibility, multi-tenancy — the substrate a virtual filesystem sits on.
- **First PR:** Wherever the VFS grows next (permissions, listing consistency, path semantics at scale), I've worked in the codebase that solved those problems at exabyte scale.

### CI, release, and supply-chain hardening
- **Evidence:** Hiero triage member, 20 merged PRs: SHA-pinning workflows, patching shell-injection risks in CI, stabilizing verified-commits. Stash ships GHCR images and a pip-installed CLI to security-conscious self-hosters — supply-chain posture is a selling point there, and I literally built a scanner for AI-tooling risk.
- **First PR:** Audit and pin the release pipeline; add provenance to the GHCR images.

---

## 06 · What my first month looks like

| When | What |
|---|---|
| Days 1–3 | Self-host Stash from scratch. File every point of friction as an issue; fix the worst papercut as PR #1. |
| Week 1 | Ship issue #563 — the version/capability handshake with clean mismatch errors. |
| Weeks 2–3 | Redaction-at-ingest MVP behind a flag: regex + entropy pass in the hook uploader, config surface in the CLI, tests and docs. |
| Week 4 | Publish `stash vfs` performance numbers on a large synthetic stash; if they hurt, prototype the trigram index under the same interface. |

I work the way a two-founders-and-an-intern stage needs: small PRs, fast follow-ups, no ego about review feedback. My GitHub is the receipt.

---

**Farzan Aman Khan** — CS undergrad · systems, infra, dev tools
[github.com/cheese-cakee](https://github.com/cheese-cakee) · farzanaman99@gmail.com · PR portfolios linked on profile

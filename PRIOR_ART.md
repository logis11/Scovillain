# Prior Art — where Scovillain sits

> Purpose of this doc: an honest map of what already exists, so the project's
> direction does not overclaim novelty. **The core concept — binary → graph →
> source/sink reachability + taint, used to reject candidates cheaply — is a
> well-researched, crowded area.** Read this before writing code.

---

## TL;DR

Every pillar of the original pitch already has a well-cited tool:

| Scovillain claim                         | Already done by            |
|------------------------------------------|----------------------------|
| Multi-binary graph / cross-binary edges  | **Karonte, SaTC, Operation Mango** |
| Reachability used as a *falsifier*/pruner| **RAPTOR, PopKORN**        |
| Binary → unified queryable graph (CPG)   | **Joern**                  |
| Source→sink taint to a critical sink     | **PopKORN** (and all above)|

The idea is not novel. If anything survives, it is the **form** (an interactive,
multi-binary, *agent-queryable* reachability substrate for binaries) — an
engineering/UX bet, not a research contribution. See "White space" below.

---

## The landscape, grouped by claim

### 1. Reachability-as-falsifier (the core thesis: "reject the hypothesis cheaply")

- **RAPTOR** — a Claude Code security agent. When CodeQL produces a path, path
  constraints are checked for satisfiability *before* any LLM call; provably
  unreachable paths are dropped immediately, and for reachable ones Z3 produces
  concrete candidate inputs. This is the "prune by reachability before expensive
  analysis" loop, at source level.
  <https://github.com/cinerieus/raptor>
- **POPKORN** (ACSAC 2022) — taint analysis + *targeted* symbolic execution to
  prove unsanitized user input reaches security-critical Windows-kernel sinks;
  analyzes the driver binary alone (no device/kernel). 38 bugs / 27 drivers, 31
  previously unknown, no false positives on manual review, 2 CVEs.
  <https://sites.cs.ucsb.edu/~vigna/publications/2022_ACSAC_popkorn.pdf>

### 2. Multi-binary graph (the headline differentiator: "cross-binary channels")

- **Karonte** (IEEE S&P / Oakland 2020) — builds a **Binary Dependency Graph**
  and propagates taint *across* binary boundaries (env vars, NVRAM, IPC) in
  embedded firmware. Closest relative to the multi-binary graph idea. 46 0-days;
  ~2 orders-of-magnitude alert reduction; tested to 899 samples.
  <https://sites.cs.ucsb.edu/~chris/research/doc/oakland20_karonte.pdf>
- **SaTC** (USENIX Security 2021) — Shared-keyword Aware Taint Checking:
  connects front-end (web) input keywords to back-end binary sinks across the
  process boundary.
  <https://ieeexplore.ieee.org/document/10226330/>
- **Operation Mango** (USENIX Security 2024) — current SOTA for scalable
  taint-style reachability in **multi-binary firmware services**; open source;
  finds 56 bugs SaTC misses on 7 firmwares. **The closest living relative to
  Scovillain — study this hardest before building.**
  <https://www.usenix.org/conference/usenixsecurity24/presentation/gibbs>
  (PDF: <https://www.usenix.org/system/files/usenixsecurity24-gibbs.pdf>)

### 3. The interactive graph workbench (the "typed queryable graph" form)

- **Joern / Code Property Graph** — already the "binary → unified queryable
  graph, vuln pattern = graph traversal" tool; merges AST+CFG+PDG; has an x86
  frontend via Ghidra. The reference for the CPG idea.
  <https://github.com/joernio/joern> ·
  <https://docs.joern.io/code-property-graph/> ·
  <https://en.wikipedia.org/wiki/Code_property_graph>

### 4. Recovery engines Scovillain would build on (not compete with)

- **angr** — recovers ICFG (`CFGFast`) and data-dependence graphs (`DDG`) from
  binaries; reference for CFG/DFG recovery and backward slicing.

### Adjacent / worth a look
- **SinkTaint** — taint-style discovery with backtracking + constraint analysis
  + symbolic-execution-based taint.
- "Harnessing the Power of LLM to Support Binary Taint Analysis"
  <https://arxiv.org/pdf/2310.08275>
- "Precise Discovery of More Taint-Style Vulnerabilities in Embedded Firmware"
  (IEEE TDSC 2024) <https://dl.acm.org/doi/10.1109/TDSC.2024.3434667>

---

## White space (what might actually be left)

Not the idea — the **form**. Both are engineering bets, not research novelty:

1. **Interactive, human-/agent-driven query substrate for *binaries*.**
   Karonte / SaTC / Mango are batch push-button detectors hardwired to a fixed
   bug class (command injection / overflow on the network border). None expose
   the graph as a substrate for *arbitrary* hypotheses. Joern does — but for
   source, with a weak binary frontend. "Joern-quality interactive querying, but
   multi-binary and binary-first" is a real gap.
2. **LLM-agent over a binary reachability graph.** RAPTOR proves the
   agent-drives-reachability loop works — but at *source* (CodeQL/Z3). The
   binary + multi-binary equivalent, driven from an IDA-MCP + LLM setup, is much
   less explored and is the most defensible angle.

---

## Decision this forces

- **Research contribution** → bar is high and mostly taken; needs a sharp narrow
  claim measured against Mango on the same firmware set. Do **not** rebuild
  Karonte.
- **Practical personal tool** (like the earlier Huntail) → novelty is
  irrelevant, usefulness is the only bar. Then build the query/agent layer *on
  top of* an existing substrate (angr / Operation Mango / Joern) instead of
  re-implementing CFG recovery and cross-binary taint.

**Next action:** read the Operation Mango paper + repo. If it already does ~80%
of the target, Scovillain becomes "a query/agent front-end to Mango's graph" — a
smaller, honest project — rather than "a new multi-binary reachability tool."

---

### Source index
- POPKORN (ACSAC 2022): <https://sites.cs.ucsb.edu/~vigna/publications/2022_ACSAC_popkorn.pdf>
- Karonte (S&P 2020): <https://sites.cs.ucsb.edu/~chris/research/doc/oakland20_karonte.pdf>
- SaTC (USENIX Sec 2021 / IEEE): <https://ieeexplore.ieee.org/document/10226330/>
- Operation Mango (USENIX Sec 2024): <https://www.usenix.org/conference/usenixsecurity24/presentation/gibbs> · <https://www.usenix.org/system/files/usenixsecurity24-gibbs.pdf>
- RAPTOR (Claude Code security agent): <https://github.com/cinerieus/raptor>
- Joern: <https://github.com/joernio/joern> · <https://docs.joern.io/code-property-graph/>
- Code Property Graph (overview): <https://en.wikipedia.org/wiki/Code_property_graph>
- LLM binary taint analysis: <https://arxiv.org/pdf/2310.08275>
- Precise Discovery of Taint-Style Vulns (IEEE TDSC 2024): <https://dl.acm.org/doi/10.1109/TDSC.2024.3434667>

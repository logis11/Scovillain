# Scovillain — Design

> Scovillain is a **falsification oracle** delivered as an **MCP server**. A
> hunting tool (Huntail) sends candidate sinks; Scovillain answers whether each
> can be **refuted** (unreachable / sanitized) over a graph of one complex
> binary. The product is the **verdict**; its defining property is that a
> negative is **sound enough to delete a candidate on.**

See [`README.md`](README.md) for the pitch and [`PRIOR_ART.md`](PRIOR_ART.md)
for why this is a *service*, not another detector.

---

## 1. The verdict contract (the actual product)

Cost of a wrong answer is asymmetric — a false "unreachable" buries a real bug,
a false "reachable" only wastes analysis. So the oracle is **sound on negatives
or it refuses.** Never return a bare boolean.

```
enum Verdict:
  REFUTED          # provably no path/flow. Caller MAY delete the candidate.
                   #   emitted ONLY when the frontier has zero unresolved dispatch
  REFUTED_MODULO   # no path found, but K unresolved indirect calls remain.
                   #   advisory. Caller MUST NOT auto-delete. K sites enumerated.
  NOT_REFUTED      # a path/flow exists (evidence returned), OR may via unresolved
                   #   dispatch. Candidate survives.
  UNKNOWN          # analysis failed / budget exceeded / unsupported construct.
                   #   treated as NOT_REFUTED by a safe caller.
```

Every verdict carries **evidence**:
- `NOT_REFUTED` → a concrete path (node sequence) and, for tier-2, the def→use
  chain from ingress to the sink argument.
- `REFUTED` → the cut / the reason (disjoint components, or the validating node
  every path crosses).
- `REFUTED_MODULO` → the list of K unresolved dispatch sites on the frontier, so
  the caller (or a human) can decide whether to resolve them and re-ask.

**Invariant:** a caller that deletes candidates only on `REFUTED` can never lose
a true positive to Scovillain. This invariant is the whole project.

---

## 2. Why indirect-call resolution is the core problem

Structural reachability over the call graph is an **under-approximation** when
indirect calls (vtables, function pointers, jump tables, dispatch loops) are
unresolved: edges are *missing*, so "no path found" may be false. That single
fact is what separates `REFUTED` (safe) from `REFUTED_MODULO` (advisory).

So the engineering effort concentrates here:
- Resolve indirect targets where possible — vtable/CFI tables, jump tables,
  constant propagation to call sites, type-based candidate sets, or borrow
  angr/Arbiter's resolution.
- **Count and expose** the residual unresolved sites on each query's frontier.
- Default to the *conservative* verdict when in doubt (`REFUTED_MODULO`, never
  `REFUTED`).

The oracle's value = how many candidates it can move from `REFUTED_MODULO` into
`REFUTED`. That is the metric to optimize.

---

## 3. Architecture

```
   caller (Huntail / LLM agent)
        │  MCP tool calls
        ▼
   ┌─────────────────────────────────────────────┐
   │  MCP surface        (§5 tool contract)        │
   ├─────────────────────────────────────────────┤
   │  query engine       tier-1 reachability       │
   │                     tier-2 dataflow            │
   │                     verdict + evidence         │
   ├─────────────────────────────────────────────┤
   │  graph model        typed multigraph, in mem   │
   │                     (networkx → Kùzu later)    │
   ├─────────────────────────────────────────────┤
   │  IR (the contract)  funcs/blocks/edges/xrefs   │
   ├─────────────────────────────────────────────┤
   │  frontends          IDA MCP · angr · Ghidra    │  ← borrowed recovery,
   └─────────────────────────────────────────────┘     NOT rebuilt
```

- **Frontends emit the IR; nothing downstream imports a frontend.** Swap IDA for
  angr without touching the query engine. Recovery (CFG, xrefs, indirect-call
  resolution) is *borrowed* from angr / Arbiter / Mango-DFA / the IDA MCP.
- **The IR is the keystone** — design it first (§4).
- **Stateful.** A session loads one binary, builds the graph once, then serves
  many queries. This is why MCP (long-lived, resource-holding) fits and a
  one-shot CLI does not.

---

## 4. IR / graph schema

Markers are *attributes*, not node types (a sink can also be a function).

```
NODES                                  EDGES (directed)
Binary   {hash, arch, base}            CONTAINS  Binary→Func→Block(→Instr)
Function {addr, name, import?, export?}CALLS     Func→Func {resolved:
Block    {addr, func, size}                                 direct|indirect|UNRESOLVED}
Instr    {addr, mnem}      (opt tier)  CFG       Block→Block (intra-proc)
DataNode {global|field|alloc}          FLOW      def→use  (data dependence)
                                       RETURNS   Func→Block
attrs (not types):
  ingress? {kind}                      Cross-binary CHANNEL edges: OUT OF SCOPE
  sink?    {kind, arg_index}           for the single-binary target (kept in the
                                       schema as reserved, unused).
```

A hypothesis = a path predicate: *"∃ path over (CALLS ∪ CFG) from an `ingress`
to this `sink`, and a `FLOW` path carrying the ingress value into
`sink.arg_index` crossing no validating node."*

---

## 5. MCP tool surface (draft)

```
scovillain.load(binary_path, opts?)          → session_id
    build IR + graph once; report node/edge counts and unresolved-dispatch total

scovillain.reachable(session, source, sink)  → {verdict, evidence}
    tier-1. structural reachability. the primary false-positive filter.

scovillain.flow(session, source, sink, arg)  → {verdict, evidence}
    tier-2. does attacker data reach sink arg unsanitized? (implies reachable)

scovillain.ingress_of(session, sink)         → [ingress...]  (+ per-verdict)
    which entrypoints can reach this sink at all — for triage/ranking

scovillain.explain(session, verdict_id)      → path | cut | unresolved-frontier
    human/agent-readable evidence for a prior verdict

scovillain.resolve_hint(session, callsite, targets)   (optional)
    caller supplies indirect-call targets it knows; may upgrade
    REFUTED_MODULO → REFUTED on re-query
```

Design notes:
- `reachable` is the workhorse: given a candidate `(source, sink)` from Huntail,
  return a verdict Huntail can act on.
- Sources/sinks are supplied by the caller (Huntail knows its candidates) or
  looked up by recipe; Scovillain does not need to own detection.
- `resolve_hint` closes the loop: a smarter caller (or human) feeds back
  dispatch targets to shrink the unresolved frontier and unlock `REFUTED`.

---

## 6. Tech choices

- **Language:** Python (angr, IDA/Ghidra scripting, graph libs).
- **Graph store:** start in-memory `networkx` behind a storage interface; move to
  **Kùzu** (embedded, Cypher, recursive queries, no server) when binaries get
  large. Not Neo4j — the server is friction.
- **Recovery:** borrow. First frontend = **IDA via the MCP tools** in this
  environment; **angr** as the programmatic alternate; consider reusing
  Arbiter / Mango-DFA analyses rather than writing dataflow from scratch.
- **Delivery:** MCP server. Library/RPC core underneath for non-agent callers.

---

## 7. Directory layout

```
scovillain/
  ir/          schema.py            # the IR dataclasses — the contract
  frontends/   ida.py  angr.py      # emit IR; nothing downstream imports these
  graph/       build.py  store.py   # IR → multigraph; storage interface
  query/       reach.py  flow.py    # tier-1 / tier-2
  verdict/     contract.py          # Verdict enum + evidence types (§1)
  dispatch/    resolve.py           # indirect-call resolution (§2, the core)
  mcp/         server.py            # the MCP tool surface (§5)
  cli.py                            # thin, for local testing only
tests/  fixtures/                   # tiny binaries with KNOWN reachable/unreachable
                                    #   pairs — ground truth to validate soundness
```

---

## 8. Walking skeleton (first milestone)

Smallest slice that proves the contract end to end — build this before breadth:

> `load()` one binary via the IDA MCP frontend (funcs + CALLS + CFG only) →
> build a networkx graph → implement tier-1 `reachable(source, sink)` →
> return `REFUTED` / `REFUTED_MODULO(K)` / `NOT_REFUTED(path)` for a real
> `ingress → memcpy` pair → expose it as one MCP tool.

No tier-2, no persistence, no recipe library yet. Success = on a fixture with a
*known* unreachable sink, the oracle returns `REFUTED` (not `REFUTED_MODULO`)
and, on a known-reachable one, returns `NOT_REFUTED` with the correct path.
Validate against `tests/fixtures/` ground truth — a false `REFUTED` is a
project-defining bug, so test for it first.

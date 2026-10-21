# Scovillain — Direction Decision

> Status: direction fixed **2026-09-24**. This supersedes the earlier
> "shelve it — overlaps with existing tools" call. Read after
> [`README.md`](README.md) / [`DESIGN.md`](DESIGN.md) / [`PRIOR_ART.md`](PRIOR_ART.md).

---

## 1. Why the shelving was wrong

`PRIOR_ART.md` maps every **mechanism** of the pitch to a well-cited tool
(Karonte, SaTC, Operation Mango, PopKORN, Joern) — and that mapping is correct.
But the same document's *White space* section never finds a tool that occupies
the **form** it names: a *negative-sound, agent-queryable refutation oracle over
one binary that other tools plug into*.

The shelving conflated two different claims:

- **Mechanism overlap** (binary → graph → source/sink reachability + taint) —
  real, crowded, do not reclaim.
- **Form overlap** (a reusable, sound-on-negatives, MCP-queryable oracle a
  hunting agent calls to *delete* candidates) — **absent**. Nobody ships this.

Two logic errors fed the shelving:

1. *"Many tools exist → a usable one exists."* Invalid. "Usable" is indexed to a
   purpose. None of the prior tools is simultaneously (a) single Windows-kernel
   binary, (b) sound-on-negatives (safe to delete on), (c) agent-queryable via
   MCP, (d) detector-agnostic. They are batch detectors hardwired to a bug class
   on firmware/ELF, or source-level (Joern/RAPTOR).
2. A crowded **successor lineage** (Karonte 2020 → SaTC 2021 → Mango 2024) is
   evidence the problem is *unsolved*, not solved. A usable general tool would
   have ended the lineage.

## 2. The direction (one sentence)

**Scovillain is the vuln-harness's absence-gate oracle.** Its one job: turn
*"cannot prove absence because of unresolved indirect dispatch"* into either a
trustworthy `REFUTED` or an honestly enumerated `MODULO(K)`. Not a scanner, not
multi-binary, not a research claim measured against Mango. Firmware and
multi-binary orchestration are ceded entirely to Karonte/Mango.

The success metric is **not** "beat Mango in the literature." It is **"unblock my
own harness."** The harness one directory over has a documented, recurring,
currently-active wall this is shaped to remove (see §7).

## 3. Key reframe — frontier-first, not REFUTED-first

`DESIGN.md` treats `REFUTED` as the product and `REFUTED_MODULO` as a fallback.
For Windows kernel drivers this must be **inverted**, because indirect dispatch
is pervasive (IRP major-function tables, `guard_dispatch_icall`, data-registered
callbacks, DPC/timer/work-item queues) — so nearly every real query lands on
`MODULO`, not `REFUTED`.

> **Primary product = a sound, complete, *ranked* enumeration of the dispatch
> frontier standing between an ingress and a sink.** `REFUTED` is the special
> case where that frontier is empty.

Why the inversion is the correct direction:

- **Robust to the yield risk.** A "REFUTED-is-the-product" tool dies if `REFUTED`
  rarely fires on real drivers. A frontier-first tool is valuable *because*
  `MODULO` is the common case — it makes `MODULO` an actionable worklist instead
  of a dead end.
- **Matches the harness's actual failure mode.** The harness does not fail by
  deleting too little; it fails by looping on leads stuck in *"absence-form,
  cannot resolve K function-pointer stores."* Enumerating + ranking the frontier
  converts *"blocked, unknowable"* into *"blocked on these K — resolve #3 and #7
  first,"* which breaks the loop.
- **Soundness gets cheaper.** Being sound about the *frontier* requires
  *completely enumerating* edge-loss sources, not *resolving* dispatch.
  Completeness of enumeration is a far more tractable soundness target than
  completeness of resolution.

## 4. Scope (hard limits)

- **One binary. Windows kernel driver first** — the real targets, and where the
  harness bleeds. ELF/firmware later, if ever.
- Cross-binary `CHANNEL` edges stay **reserved but unbuilt** in the schema.
- No general CPG, no Joern-for-binaries. One job.

## 5. Concentrate all risk in `dispatch/`

Frontier enumeration + ranking is the whole project. Everything else is borrowed
or scaffold:

- **Recovery:** borrow (IDA-MCP frontend first; angr `CFGFast`/`DDG` as alternate).
- **Graph:** networkx behind the storage interface; Kùzu only if size forces it.
- **MCP surface / verdict contract / tiers:** scaffold around the one hard module.

## 6. Soundness invariant (redefined for the frontier)

The invariant is no longer "REFUTED means provably no path." It is:

> **The frontier counts *every* edge-loss source, not just indirect calls.**

That includes data-registered kernel callbacks (`IoRegister*`, filter callbacks,
DPC/timer/work-item queues), tail calls, and exception/unwind dispatch. Miss any
class and a `REFUTED` (empty frontier) becomes a lie.

Test-first: fixtures with a **deliberately planted missed-callback**, and the
first test asserts the frontier *catches* it. A false `REFUTED` is the
project-defining bug — test for it before anything else. (This is the harness's
own positive-control discipline: a measured "clean" is only trustworthy next to
a positive control that would have fired.)

## 7. First customer & acceptance test

The harness. The acceptance test is a **live block**, not a toy fixture:

- Input: the mrxsmb `SmbQuicExplicitReceiveComplete@0x140051f88` lead (the
  arm-independent drain-window re-entry), whose absence-gate a human analyst
  could not clear inside a session because it is gated on **39 unresolved
  function-pointer stores**.
- Success: Scovillain reproduces that 39-site frontier, ranks it, and returns
  `MODULO(39)` (or `REFUTED` if it can resolve them) — matching what the analyst
  derived by hand.

That one case proves or refutes the project's value live.

### 7-a. MEASURED 2026-10-17 — first run on a real binary

The premise above is **stale** and the result is better than it: the human
cleared that wall on 09-24 (harness `work/notes/S155-GOAL-ANSWERED-39-FNPTR-STORES-RESOLVED-read-this-first.md`), resolving the 39 into **77 LEA-to-store
sites / 49 distinct targets, 49/49 in GFIDS, zero targeting the slot**. So the
acceptance criterion is no longer "reproduce MODULO(39)" — it is
**agree with a hand-derived ground truth**, which is a stronger test.

Run: `frontends/pe_capstone` on `mrxsmb-9444.sys` (+PDB publics), 1.7 s,
2193 functions, 5044 direct + 2094 import call edges, **938 edge-loss sites**
(634 indirect_call / 209 exception_dispatch / 89 codeptr_escape / 6 tailcall).
Build identity by CV GUID = `B760BF46A144CE64EC98EBAF32D21BB3` age 1 — the exact
GUID the analyst's notes pin, so the anchor is the same image.

- **Path**: `reachable(0x86a40, 0x51f88)` returns `NOT_REFUTED(path_len=3)` with
  `0x86a40 -> 0x52f18 -> 0x51f88` = ClientStreamCallback -> SmbQuicStreamEventRecv
  -> SmbQuicExplicitReceiveComplete. That is **the analyst's chain, reproduced**.
- **Frontier**: K=19 ranked sites; top is the kCFG thunk `0x59f60`
  (`_guard_dispatch_icall`), which is exactly where the note says the real
  dispatch happens.
- **Escape detector vs ground truth**: 89 sites / 65 distinct targets against the
  human's 77 / 49. A **sound superset** (the right direction): the detector flags
  every `lea` of a function start, the human counted only the ones *stored*. The
  gap is the calibration debt to pay next, not a soundness hole.

Open fidelity items found by running it (none of them unsound, all
frontier-inflating): (a) a `call <thunk>` attributes the loss to the thunk's
function, not the call site, so ranking is coarser than it could be;
(b) jump tables stay fully-unknown; (c) PDB *publics* only, so static functions
come out as `sub_<rva>` — the analyst's names for them came from private symbols.

## 8. Walking skeleton (re-pointed)

Same slice as `DESIGN.md §8`, but aimed at the live block above rather than a toy
`ingress → memcpy`. Success = it reproduces the human-derived frontier for the
mrxsmb lead, with the frontier's soundness (§6) tested first.

## 9. RESOLVED 2026-10-17 — standalone-first, captive by adapter

**Decision: standalone-first.** The code was already written that way
(`ir/schema.py` docstring), and the question answered itself when the first
frontend landed: `frontends/pe_capstone` depends on `capstone`+`pefile` only — no
IDA, no MCP, no harness import — and it ran on a real driver in 1.7 s. Making it
captive now would buy nothing and would couple the IR to one caller's state
format. The captive path stays available as a thin adapter (`mcp/server.py`
wrapping `query.reach`), to be written when a caller actually needs it.
Nothing in the tree contradicts this any more; the old recommendation is kept
below for provenance.

(superseded) Recommendation: **captive-first** — the harness is the
only proven customer, so wire Scovillain as an MCP tool the nightrun agent calls
and extract value fast, while keeping the **IR boundary clean** so it can be
lifted out later. Designing it as "a standalone tool the harness happens to use
first" spends early time on IR generality and delays first value. This fork
changes coupling, IR generality, and how much to invest in the MCP contract vs a
plain Python import — confirm before building.

## 10. Tier-1b: paired-operation population audit (added 2026-10-17)

A second query over the same graph and the same soundness rule, written because
the harness lost a real bug to a question this project could not ask. The
analyst held a low-privilege write primitive into an `ahcache` cache entry, capped
the axis on **impact**, and the vendor then fixed the **lifetime** of that exact
object one LCU later (presumed CVE-2026-72955, App Compat Cache UAF, 2026-10-13).
What would have surfaced it is one table — acquire vs release per holder — where
three of four members are symmetric and one is not.

`query/pairing.py` makes that a first-class query: complete over known call
edges (every holder is a row), with a verdict per holder — `DIRECT_PAIRED`,
`DELEGATED_KNOWN`, `UNPAIRED_MODULO(K)`, `UNPAIRED_PROVEN` — and the population
shape named when it is "symmetric except a minority".

Two design points worth keeping:

- **It does not reuse `Answer.safe_to_delete`.** For reachability, the sound
  negative (`REFUTED`) authorises deleting a candidate. For pairing, "no release
  is reachable" is the *bug signal*. Returning the reachability `Answer` would
  invert the project's one invariant, so pairing has its own verdict type and
  keeps the `Answer` inside it as evidence. A test pins that inversion.
- **Verb pairs are not interchangeable.** `Acquire/Release`, `Lock/Unlock`,
  `Reference/Dereference` are *local* disciplines, so a delegated release is
  already a lead. `Alloc/Free` is an ownership *transfer* — allocating in
  `XCreate` and freeing in `XDelete` is normal — so the same row is noise there.
  Measured: with one rule for both, ahcache's `AslAlloc/AslFree*` produced ten
  benign rows that buried the one real asymmetry.

### Measured on real binaries the same day

| run | result |
|---|---|
| ahcache 9278 / 9549 (pre-fix) | `AhcCacheLookup acq=2 rel=0 DELEGATED_KNOWN`, 3 others symmetric → **PARTIAL APPLICATION** flagged. Run before October, this puts the function the vendor then fixed at the top of the list. |
| ahcache 9711 (post-fix) | population fully `DIRECT_PAIRED`; the flag is gone. A **before/after control on a real binary**, with the hand-derived table as ground truth. |
| bfs 9711 | 2 leads: `BfsCreateStorage` (2 allocs, no free, MODULO(4)) and `BfsIdleCheckTimerCallback` (work item, callerless → capped). |

### Two frontend defects this run exposed (both now fixed)

1. **Function pointers held in initialised data were invisible.** A lea-only
   escape detector misses `FLT_OPERATION_REGISTRATION`-style tables, i.e. the
   registered-callback case the frontier model cares most about. mrxsmb 9444:
   codeptr escapes 89 → 224 once data is scanned. Attribution of those sites is
   an **open item** (currently the image entry point, documented in the
   frontend) — they are enumerable via `data_codeptrs()` but do not inflate
   ordinary source→sink queries, which was verified by re-running the acceptance
   query unchanged.
2. **Chained `.pdata` regions were treated as separate functions.** MSVC splits
   functions; each region has its own entry with `UNW_FLAG_CHAININFO`. A fragment
   then looks *callerless* and its forward closure is *truncated at the jump
   out* — which can produce a false `REFUTED`. It was found because the first
   pairing run on bfs produced a phantom lead (`sub_35d2`, a 70-byte tail ending
   in `je`). Regions are now merged to the primary: bfs 293 functions instead of
   321, and the phantom lead disappeared while the ahcache control stayed
   identical.

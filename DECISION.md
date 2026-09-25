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

## 8. Walking skeleton (re-pointed)

Same slice as `DESIGN.md §8`, but aimed at the live block above rather than a toy
`ingress → memcpy`. Success = it reproduces the human-derived frontier for the
mrxsmb lead, with the frontier's soundness (§6) tested first.

## 9. The one open decision

**Captive vs standalone.** Recommendation: **captive-first** — the harness is the
only proven customer, so wire Scovillain as an MCP tool the nightrun agent calls
and extract value fast, while keeping the **IR boundary clean** so it can be
lifted out later. Designing it as "a standalone tool the harness happens to use
first" spends early time on IR generality and delays first value. This fork
changes coupling, IR generality, and how much to invest in the MCP contract vs a
plain Python import — confirm before building.

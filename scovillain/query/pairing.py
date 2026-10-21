"""Tier-1b: paired-operation population audit (acquire/release, lock/unlock,
alloc/free, probe/commit).

## Why this exists, and why it is a *different* query

Added 2026-10-17 from a measured miss in the harness (the customer of §7). The
analyst held a low-privilege *write* primitive into an `ahcache` cache entry and
capped the axis on **impact** ("writes only pick a PCA label"). The vendor then
reworked the lifetime of that exact object in the next LCU (a UAF fix). What
would have flagged it was not a reachability question at all — it was one table:

    caller                        acquire  release        (ahcache 9278/9549)
    AhcCacheLookup                      2        0   <-- the odd member
    AhcCacheRemove                      1        1
    AhcCacheUpdate                      1        1
    AhcpCacheEntryFinalizeLookup        1        1

Three of four members of the population are symmetric and one is not. The
harness's own rule says the real defect is almost never an *absent* check but a
**partially applied** one, and this is that shape. So this module makes the
population and its odd members a first-class query.

## The semantic hazard this module exists to contain

`query.reach` answers "can control get there", and its sound negative is
`REFUTED`, which *authorises deleting a candidate*. Pairing inverts that: "no
release is reachable" is **not** a dismissal, it is the bug signal. Reusing
`Answer.safe_to_delete` here would mean a caller deleting a candidate exactly
when the asymmetry is proven — a silent inversion of the project's one
invariant. So pairing gets its own verdict type and keeps the reachability
`Answer` *inside* it as evidence, never as the verdict.

## What is claimed, and modulo what

Nothing here claims a bug. Each row says how the release could still be
happening, so the caller knows what to go measure:

- `DIRECT_PAIRED`        — the holder calls the release itself.
- `DELEGATED_KNOWN`      — no direct release, but a known call path reaches one
                           (the path is returned). Pairing is delegated to a
                           callee, so per-reference symmetry is NOT established:
                           counts can still mismatch (ahcache: 2 acquires, one
                           delegated release). This is a lead, not a verdict.
- `UNPAIRED_MODULO(K)`   — no direct release and no known path, but K dispatch
                           frontier sites could still reach one. Sound: the
                           asymmetry is real only if those K are resolved.
- `UNPAIRED_PROVEN`      — no direct release, no known path, frontier empty.
                           The strongest lead this module can produce.
- `UNKNOWN`              — the graph cannot answer (missing node / budget).

Function granularity is the limit: proving that *every path* from one acquire
site reaches a release needs block-level post-dominance, which tier-1 does not
carry. That limit is stated per row rather than papered over — a `DELEGATED_KNOWN`
row with `n_acquire > n_release_on_path` is precisely the ahcache shape and is
surfaced as such.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum

from scovillain.dispatch.frontier import enumerate_frontier
from scovillain.graph.store import KNOWN_CALL, NetworkxStore
from scovillain.ir.schema import EdgeKind
from scovillain.verdict.contract import (
    Answer, not_refuted, refuted, refuted_modulo, unknown,
)


class PairKind(str, Enum):
    """Does the discipline expect the pairing to happen *inside* the holder?

    Measured 2026-10-17: running the audit with one rule for all verb pairs
    flooded the output. `Acquire/Release`, `Lock/Unlock`, `Reference/Dereference`
    are **local** disciplines — the holder that takes the reference is the one
    that must drop it, so delegating it is already a lead. `Alloc/Free` is an
    **ownership transfer** — allocating in `XCreate` and freeing in `XDelete` is
    the normal shape, so the same row there is noise, not signal. Conflating the
    two is how a precision-only tool becomes unusable (and how a real
    partially-applied refcount gets buried under 10 benign rows).
    """
    LOCAL = "local"
    TRANSFER = "transfer"


class Pairing(str, Enum):
    DIRECT_PAIRED = "DIRECT_PAIRED"
    DELEGATED_KNOWN = "DELEGATED_KNOWN"
    UNPAIRED_MODULO = "UNPAIRED_MODULO"
    UNPAIRED_PROVEN = "UNPAIRED_PROVEN"
    UNKNOWN = "UNKNOWN"

    @property
    def is_lead(self) -> bool:
        """True == a human should look. Deliberately NOT called 'is_bug'."""
        return self in (Pairing.DELEGATED_KNOWN, Pairing.UNPAIRED_MODULO,
                        Pairing.UNPAIRED_PROVEN)


@dataclass
class PairingRow:
    holder: int                      # function that acquires
    name: str
    n_acquire: int                   # acquire call sites in this function
    n_release: int                   # release call sites in this function
    pairing: Pairing
    reach: Answer                    # the underlying release-reachability answer
    note: str = ""
    kind: PairKind = PairKind.LOCAL

    @property
    def is_lead(self) -> bool:
        """Verdict AND discipline. A delegated release is a lead only where the
        discipline is local (see PairKind)."""
        if self.kind is PairKind.TRANSFER and self.pairing is Pairing.DELEGATED_KNOWN:
            return False
        return self.pairing.is_lead

    @property
    def k(self) -> int:
        return self.reach.evidence.k

    def line(self) -> str:
        return "%-42s acq=%-2d rel=%-2d %-16s %s" % (
            self.name, self.n_acquire, self.n_release,
            self.pairing.value + (("(%s)" % (self.k or "ctx"))
                                  if self.pairing is Pairing.UNPAIRED_MODULO else ""),
            self.note)


@dataclass
class PairingReport:
    acquire: int
    release: int
    rows: list[PairingRow] = field(default_factory=list)
    binary_hash: str = ""            # same anchor rule as Answer: name the build
    build: str = ""
    label: str = ""                  # "Acquire / Release*" pair this report is for

    kind: PairKind = PairKind.LOCAL

    @property
    def leads(self) -> list[PairingRow]:
        return [r for r in self.rows if r.is_lead]

    @property
    def pairing_field(self):
        """The population's pairing verdicts as a field — so the shape claim is
        subject to the same guard as any other attribute read
        (`verdict/discriminator.py`): a label that would be emitted for a
        population where nothing varies is not a finding, it is a tautology."""
        from scovillain.verdict.discriminator import FieldPopulation
        return FieldPopulation(name="pairing",
                               values=tuple(r.pairing.value for r in self.rows),
                               members=tuple(r.name for r in self.rows))

    @property
    def partial_application(self) -> bool:
        """The shape the harness says is almost always the defect: the whole
        population is symmetric except a minority. True when there is at least
        one lead, the symmetric members outnumber them, AND the pairing field
        actually varies across the population (the discriminator guard)."""
        n = len(self.rows)
        leads = len(self.leads)
        if not (bool(leads) and n >= 3 and leads <= max(1, n // 3)):
            return False
        return self.pairing_field.discriminates

    def shape(self) -> str:
        c = Counter(r.pairing for r in self.rows)
        head = ", ".join("%s=%d" % (k.value, v) for k, v in sorted(c.items(), key=lambda kv: kv[0].value))
        tag = "  <== PARTIAL APPLICATION (population symmetric except a minority)" \
            if self.partial_application else ""
        return "population=%d  %s%s" % (len(self.rows), head, tag)

    def render(self) -> str:
        out = ["%s  [%s · build=%s cv=%s]" % (self.label or "pairing",
                                              self.kind.value, self.build,
                                              self.binary_hash)]
        out += [r.line() for r in sorted(
            self.rows, key=lambda r: (not r.is_lead, -r.n_acquire, r.name))]
        out.append(self.shape())
        return "\n".join(out)


def _callsite_counts(store: NetworkxStore, dst: int) -> Counter:
    """How many call *sites* each function has to `dst`. The frontend emits one
    edge per call instruction, so multiplicity is meaningful here — and the
    count is the whole point: 2-acquires-1-release is the shape we are after."""
    c: Counter = Counter()
    for e in store.module.edges:
        if e.kind is EdgeKind.CALLS and e.dst == dst and e.resolution in KNOWN_CALL:
            c[e.src] += 1
    return c


def audit_pairing(store: NetworkxStore, acquire: int, release: int,
                  also_release: tuple[int, ...] = (),
                  kind: PairKind = PairKind.LOCAL) -> PairingReport:
    """Enumerate every holder of `acquire` and classify how its `release` pairs.

    Complete over known call edges: every function with an acquire call site is a
    row (no ranking cut, no sampling) — a population claim must count everyone.

    `also_release` exists because real releases split: ahcache 9711 has
    `...ReleaseForRead` *and* had `...ReleaseForWrite`, and a holder that calls
    either one is paired. A holder is only a lead when NONE of them pairs it, and
    an UNPAIRED_PROVEN requires every release to be provably unreachable.
    """
    rep = PairingReport(acquire=acquire, release=release, kind=kind,
                        binary_hash=store.module.binary_hash,
                        build=store.module.build)
    acq = _callsite_counts(store, acquire)
    rel: Counter = Counter()
    for r in (release,) + tuple(also_release):
        rel.update(_callsite_counts(store, r))

    for holder, n_acq in acq.items():
        name = store.module.nodes[holder].name if holder in store.module.nodes else "sub_%x" % holder
        n_rel = rel.get(holder, 0)

        if not store.has_func(holder) or not store.has_func(release):
            rep.rows.append(PairingRow(holder, name, n_acq, n_rel, Pairing.UNKNOWN,
                                       unknown("holder or release not in graph"),
                                       "graph cannot answer", kind))
            continue

        if n_rel:
            # Still report the count relation: symmetric counts are the clean case.
            note = "" if n_rel >= n_acq else \
                "count mismatch: %d acquire sites vs %d release sites" % (n_acq, n_rel)
            rep.rows.append(PairingRow(
                holder, name, n_acq, n_rel, Pairing.DIRECT_PAIRED,
                not_refuted(path=(holder, release), source=holder, sink=release,
                            binary_hash=rep.binary_hash, build=rep.build),
                note, kind))
            continue

        frs = [enumerate_frontier(store, holder, r)
               for r in (release,) + tuple(also_release) if store.has_func(r)]
        # prefer a known path (pairing exists); else the smallest frontier; a
        # PROVEN asymmetry needs EVERY release proven unreachable.
        fr = next((x for x in frs if x.has_known_path),
                  min(frs, key=lambda x: len(x.sites)) if frs else None)
        if fr is None:
            rep.rows.append(PairingRow(holder, name, n_acq, 0, Pairing.UNKNOWN,
                                       unknown("no release node in graph"),
                                       "graph cannot answer", kind))
            continue
        stamp = dict(binary_hash=rep.binary_hash, build=rep.build)
        if fr.has_known_path:
            hops = len(fr.known_path) - 1
            names = " -> ".join(
                store.module.nodes[a].name if a in store.module.nodes else "sub_%x" % a
                for a in fr.known_path)
            rep.rows.append(PairingRow(
                holder, name, n_acq, 0, Pairing.DELEGATED_KNOWN,
                not_refuted(path=fr.known_path, frontier=fr.sites,
                            source=holder, sink=release, **stamp),
                "release delegated %d hop(s): %s%s" % (
                    hops, names,
                    "; %d acquire sites vs 1 delegated release => per-reference "
                    "symmetry NOT established" % n_acq if n_acq > 1 else ""), kind))
            continue

        callerless = not set(store.callers(holder))
        if fr.empty and all(x.empty for x in frs) and not callerless:
            rep.rows.append(PairingRow(
                holder, name, n_acq, 0, Pairing.UNPAIRED_PROVEN,
                refuted(cut="no release reachable over known edges and the "
                            "dispatch frontier is empty", source=holder,
                        sink=release, **stamp),
                "PROVEN unpaired over the enumerated frontier", kind))
            continue

        if callerless:
            # Measured on bfs 9711: both unpaired rundown holders have ZERO known
            # callers — they are registered callbacks, and a minifilter pre/post
            # pair legitimately acquires in one callback and releases in another.
            # No forward query from inside such a function can see that pair, so
            # claiming PROVEN here is the pairing-shaped false negative.
            note = ("holder has NO known callers = reached by unmodelled dispatch "
                    "(registered callback); a cross-callback pre/post pair cannot "
                    "be excluded from inside it, so capped at MODULO" +
                    ("" if fr.sites else " (forward frontier is empty)"))
        else:
            note = ("asymmetry holds only if these %d dispatch sites cannot "
                    "release; top: %s" % (len(fr.sites),
                                          fr.sites[0].reason[:60] if fr.sites else "-"))
        rep.rows.append(PairingRow(
            holder, name, n_acq, 0, Pairing.UNPAIRED_MODULO,
            refuted_modulo(frontier=fr.sites, source=holder, sink=release, **stamp)
            if fr.sites else unknown("callerless holder, empty forward frontier",
                                     source=holder, sink=release, **stamp),
            note, kind))
    return rep


# --------------------------------------------------------------------------
# Pair discovery — so the audit can be run as a census, not one guess at a time
# --------------------------------------------------------------------------

# Verb pairs whose asymmetry is a lifetime or locking defect. Deliberately
# narrow: Add/Remove, Create/Destroy and Open/Close pair across *different*
# objects too often and would bury the signal in noise.
_VERBS = (
    ("Acquire", "Release", PairKind.LOCAL),
    ("Reference", "Dereference", PairKind.LOCAL),
    ("Lock", "Unlock", PairKind.LOCAL),
    ("Enter", "Leave", PairKind.LOCAL),
    ("Enter", "Exit", PairKind.LOCAL),
    ("Allocate", "Free", PairKind.TRANSFER),
    ("Alloc", "Free", PairKind.TRANSFER),
)


def discover_pairs(module) -> list[tuple[int, tuple[int, ...], str, PairKind]]:
    """Find (acquire, releases, label) triples by name. A release matches when
    its name is the acquire's name with the verb substituted, as a *prefix* —
    `AhcpCacheEntryAcquire` pairs with `AhcpCacheEntryReleaseForWrite`, which an
    exact-name rule would miss (and that miss is how the ahcache table went
    unbuilt for weeks)."""
    byname = {n.name: nid for nid, n in module.nodes.items() if n.name}
    out: list[tuple[int, tuple[int, ...], str, PairKind]] = []
    for name, nid in sorted(byname.items()):
        for a, b, kind in _VERBS:
            if a not in name:
                continue
            stem = name.replace(a, b)
            rels = tuple(sorted(
                i for nm, i in byname.items()
                if nm == stem or nm.startswith(stem)))
            if rels:
                out.append((nid, rels, "%s / %s*" % (name, stem), kind))
                break
    return out


def sweep(store: NetworkxStore, leads_only: bool = True) -> list[PairingReport]:
    """Run `audit_pairing` over every discovered pair. Returns the reports that
    carry a lead (or all of them, which is the honest denominator)."""
    reps = []
    for acq, rels, label, kind in discover_pairs(store.module):
        rep = audit_pairing(store, acq, rels[0], rels[1:], kind)
        rep.label = label
        if rep.rows and (not leads_only or rep.leads):
            reps.append(rep)
    return reps

"""The dispatch frontier — the whole project (DECISION.md §3, §5, §6).

Given (source, sink), enumerate **every** edge-loss site that stands between
them and could extend a path to the sink, then rank them. The frontier is the
product; REFUTED is the special case where it is empty.

Soundness invariant (DECISION.md §6), stated operationally:

  Let fwd = functions reachable from `source` over KNOWN call edges.
  A loss site s in a function f in fwd is kept on the frontier UNLESS we can
  *prove* it cannot reach the sink. We can prove that only for a site whose
  targets are all known and whose entire known forward closure is free of loss
  sites and excludes the sink. A `fully_unknown` site can NEVER be proven
  irrelevant, so it is always kept.

  => REFUTED (empty frontier) is emitted only when no known path exists AND every
     edge-loss site reachable from the source is provably sink-irrelevant. Any
     unmodelled edge-loss class that the frontend fails to emit as an
     EdgeLossSite is the one way this becomes unsound — hence the frontend, not
     this module, is the place completeness must be audited, and the planted-
     callback test guards exactly that seam.
"""

from __future__ import annotations

from dataclasses import dataclass

from scovillain.graph.store import NetworkxStore
from scovillain.ir.schema import EdgeLossKind, EdgeLossSite
from scovillain.verdict.contract import FrontierSite


# Sites of these kinds carrying zero known targets are the conservative core:
# unknown destination => could reach anything => never droppable.
_ALWAYS_KEEP_IF_UNKNOWN = frozenset(EdgeLossKind)  # all kinds; unknown == keep


@dataclass
class FrontierResult:
    fwd: set[int]                 # functions reachable from source over known edges
    known_path: tuple[int, ...] | None   # a concrete source->sink call path, if any
    sites: list[FrontierSite]     # the ranked frontier (empty => REFUTED-able)

    @property
    def has_known_path(self) -> bool:
        return self.known_path is not None

    @property
    def empty(self) -> bool:
        return not self.sites


def _funcs_with_loss(store: NetworkxStore) -> set[int]:
    return {s.func for s in store.module.edge_loss}


def _provably_sink_irrelevant(store: NetworkxStore, site: EdgeLossSite,
                              sink_f: int, loss_funcs: set[int]) -> bool:
    """Can this site provably NOT reach the sink? Sound: returns True only when
    certain. A `fully_unknown` site always returns False."""
    if site.fully_unknown:
        return False
    for t in site.known_targets:
        closure = store.forward_reachable(t)
        if sink_f in closure:
            return False                      # a target reaches the sink
        if closure & loss_funcs:
            return False                      # closure has its own unresolved loss
    return True                               # every target fully resolved, misses sink


def _score(store: NetworkxStore, site: EdgeLossSite,
           source_f: int, sink_f: int, sink_cone: set[int]) -> tuple[float, str]:
    """Rank key: higher == resolve first. Heuristic and deliberately swappable.

    The dominant signal is whether resolving this site would *complete a path*:
    a known target already in the sink's backward cone means materialising this
    one edge yields source -> ... -> sink. Those rank first. After that we prefer
    sites nearer the sink, then cheaper-to-resolve (fewer candidates)."""
    d_src = store.call_hops(source_f, site.func)
    d_src = 0 if d_src is None else d_src
    reasons = []
    score = 1.0

    bridges = False
    if not site.fully_unknown:
        for t in site.known_targets:
            if t == sink_f or sink_f in store.forward_reachable(t) or t in sink_cone:
                bridges = True
                break
    if bridges:
        score += 100.0
        reasons.append("known target reaches sink cone (resolving completes a path)")
    elif site.func in sink_cone:
        score += 40.0
        reasons.append("site's function is in the sink's backward cone")
    elif not site.fully_unknown:
        score += 5.0
        reasons.append("has candidate targets to resolve")
    else:
        score += 1.0
        reasons.append("destination fully unknown (kept for soundness)")

    # nearer the source ranks a little higher (earlier on real paths)
    score += 2.0 / (1.0 + d_src)

    # cheaper to resolve ranks higher
    if site.known_targets:
        score += 2.0 / (1.0 + len(site.known_targets))
        reasons.append(f"{len(site.known_targets)} candidate target(s)")
    else:
        reasons.append("0 candidate targets")

    # exotic dispatch is rarer / harder — mild deprioritise as a tie-breaker
    if site.kind is EdgeLossKind.EXCEPTION_DISPATCH:
        score -= 0.25

    reasons.append(f"{site.kind.value} @ {site.site:#x}")
    if site.detail:
        reasons.append(site.detail)
    return score, "; ".join(reasons)


def enumerate_frontier(store: NetworkxStore, source: int, sink: int) -> FrontierResult:
    """Enumerate and rank the dispatch frontier between source and sink.

    `source`/`sink` are node ids; each is resolved to its containing function."""
    source_f = store.func_of(source)
    sink_f = store.func_of(sink)

    fwd = store.forward_reachable(source_f)
    known_path = store.shortest_path(source_f, sink_f)  # None unless a known path

    loss_funcs = _funcs_with_loss(store)
    sink_cone = store.backward_reachable(sink_f)

    sites: list[FrontierSite] = []
    for site in store.module.edge_loss:
        if site.func not in fwd:
            continue                          # not reachable from source; can't matter
        if site.materialized:
            continue                          # its edges are already in the graph
        if _provably_sink_irrelevant(store, site, sink_f, loss_funcs):
            continue                          # proven unable to reach the sink
        s, reason = _score(store, site, source_f, sink_f, sink_cone)
        sites.append(FrontierSite(loss=site, score=s, reason=reason))

    sites.sort(key=lambda fs: (-fs.score, fs.site))
    return FrontierResult(fwd=fwd, known_path=known_path, sites=sites)

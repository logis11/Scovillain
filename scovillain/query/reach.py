"""Tier-1: structural reachability -> verdict (DESIGN.md §5, DECISION.md §3).

This is thin on purpose. All the hard, soundness-critical work is in
`dispatch.frontier`. Tier-1 just maps a frontier result onto the verdict
contract:

    known path found        -> NOT_REFUTED (path evidence)
    no path, frontier empty  -> REFUTED     (provably no path)
    no path, frontier K>0    -> REFUTED_MODULO(K)  (ranked worklist)
"""

from __future__ import annotations

from scovillain.dispatch.frontier import enumerate_frontier
from scovillain.graph.store import NetworkxStore
from scovillain.verdict.contract import (
    Answer, not_refuted, refuted, refuted_modulo, unknown,
)


def reachable(store: NetworkxStore, source: int, sink: int) -> Answer:
    """Can attacker-reachable control get from `source` to `sink`? Sound on
    negatives: only REFUTED authorises deleting the candidate."""
    source_f = store.func_of(source)
    sink_f = store.func_of(sink)
    if not store.has_func(source_f):
        return unknown(f"source function {source_f:#x} not in graph", source, sink)
    if not store.has_func(sink_f):
        return unknown(f"sink function {sink_f:#x} not in graph", source, sink)

    fr = enumerate_frontier(store, source, sink)

    if fr.has_known_path:
        return not_refuted(path=fr.known_path, frontier=fr.sites,
                           source=source, sink=sink)

    if fr.empty:
        return refuted(
            cut=(f"no path over known call edges from {source_f:#x} to "
                 f"{sink_f:#x}; every edge-loss site reachable from the source "
                 f"is provably sink-irrelevant (frontier empty)"),
            source=source, sink=sink)

    return refuted_modulo(frontier=fr.sites, source=source, sink=sink)

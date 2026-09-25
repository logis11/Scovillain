"""Graph storage interface + in-memory networkx backend (DESIGN.md §6).

Start in-memory; the interface exists so Kùzu can replace it when binaries get
large, without touching the query engine.

Tier-1 works at **function granularity**: the call graph carries only *known*
CALLS edges (DIRECT / INDIRECT_RESOLVED / MATERIALIZED). An UNRESOLVED transfer
is deliberately NOT an edge here — its potential is recorded as an EdgeLossSite
and surfaced by the frontier. Adding a phantom edge for it would corrupt both
the "path found" and the "no path" answers.
"""

from __future__ import annotations

from typing import Iterable, Protocol

import networkx as nx

from scovillain.ir.schema import (
    CallResolution, EdgeKind, EdgeLossSite, Module, Node,
)

KNOWN_CALL = frozenset({
    CallResolution.DIRECT,
    CallResolution.INDIRECT_RESOLVED,
    CallResolution.MATERIALIZED,
})


class GraphStore(Protocol):
    def has_func(self, func: int) -> bool: ...
    def callees(self, func: int) -> Iterable[int]: ...       # known CALLS out-edges
    def callers(self, func: int) -> Iterable[int]: ...       # known CALLS in-edges
    def func_of(self, node: int) -> int: ...                 # containing function
    def loss_in(self, func: int) -> list[EdgeLossSite]: ...
    def node(self, node: int) -> Node: ...


class NetworkxStore:
    """In-memory GraphStore. Holds the Module (source of truth for markers and
    edge-loss) and a derived call MultiDiGraph for fast reachability."""

    def __init__(self, module: Module):
        self.module = module
        self.cg = nx.MultiDiGraph()
        self._contained: dict[int, int] = {}   # block/instr id -> function id
        self._build()

    def _build(self) -> None:
        for nid, node in self.module.nodes.items():
            self.cg.add_node(nid)
        for e in self.module.edges:
            if e.kind is EdgeKind.CALLS and e.resolution in KNOWN_CALL:
                self.cg.add_edge(e.src, e.dst, resolution=e.resolution)
            elif e.kind is EdgeKind.CONTAINS:
                # remember containment so a sink at a block/instr maps to its func
                self._contained[e.dst] = e.src

    # -- GraphStore ---------------------------------------------------------

    def has_func(self, func: int) -> bool:
        return self.cg.has_node(func)

    def callees(self, func: int) -> Iterable[int]:
        if not self.cg.has_node(func):
            return ()
        return set(self.cg.successors(func))

    def callers(self, func: int) -> Iterable[int]:
        if not self.cg.has_node(func):
            return ()
        return set(self.cg.predecessors(func))

    def func_of(self, node: int) -> int:
        """Resolve a node to its containing function (walk CONTAINS up)."""
        seen = set()
        cur = node
        while cur in self._contained and cur not in seen:
            seen.add(cur)
            cur = self._contained[cur]
        return cur

    def loss_in(self, func: int) -> list[EdgeLossSite]:
        return self.module.loss_in(func)

    def node(self, node: int) -> Node:
        return self.module.nodes[node]

    # -- reachability primitives used by query/dispatch ---------------------

    def forward_reachable(self, src: int) -> set[int]:
        """Functions reachable from src over KNOWN call edges (incl. src)."""
        if not self.cg.has_node(src):
            return set()
        return set(nx.descendants(self.cg, src)) | {src}

    def backward_reachable(self, dst: int) -> set[int]:
        """Functions that can reach dst over KNOWN call edges (incl. dst)."""
        if not self.cg.has_node(dst):
            return set()
        return set(nx.ancestors(self.cg, dst)) | {dst}

    def shortest_path(self, src: int, dst: int) -> tuple[int, ...] | None:
        if not (self.cg.has_node(src) and self.cg.has_node(dst)):
            return None
        try:
            return tuple(nx.shortest_path(self.cg, src, dst))
        except nx.NetworkXNoPath:
            return None

    def call_hops(self, src: int, dst: int) -> int | None:
        """Number of known call edges on the shortest src->dst path, or None."""
        p = self.shortest_path(src, dst)
        return None if p is None else len(p) - 1

"""Scovillain IR — the contract.

This is the keystone (DESIGN.md §4). Every frontend (IDA-MCP, angr, Ghidra)
emits *this* and nothing downstream imports a frontend. The IR is deliberately
frontend-agnostic and standalone-general (DECISION.md §9, resolved 2026-10-17 =
standalone-first; captive use is a thin adapter over `query.reach`).

The one non-obvious thing this schema does, and the reason the whole project
exists: it gives **edge-loss sources** first-class representation (`EdgeLossSite`),
separate from the edges that *are* known. Structural reachability over known
edges is an under-approximation; the set of places where an edge *might* be
missing is what Scovillain enumerates and ranks. The soundness invariant
(DECISION.md §6) is that this set counts **every** class of edge loss —
indirect calls, code-pointer escapes / registered kernel callbacks, tail calls,
and exception/unwind dispatch — not just indirect calls. Miss one class and an
empty frontier (a `REFUTED`) becomes a lie.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# --------------------------------------------------------------------------
# Node / edge taxonomy
# --------------------------------------------------------------------------

class NodeKind(str, Enum):
    BINARY = "binary"
    FUNCTION = "function"
    BLOCK = "block"
    INSTR = "instr"
    DATA = "data"          # global | field | alloc site


class EdgeKind(str, Enum):
    CONTAINS = "contains"  # Binary->Func->Block(->Instr)
    CALLS = "calls"        # Func->Func (see CallResolution)
    CFG = "cfg"            # Block->Block, intra-proc control flow
    FLOW = "flow"          # def->use data dependence (tier-2)
    RETURNS = "returns"    # Func->Block
    CHANNEL = "channel"    # cross-binary; RESERVED, unused for single-binary target


class CallResolution(str, Enum):
    """How a CALLS edge was recovered. UNRESOLVED is not a resolution — it is a
    marker that the *real* out-edges at this site are (partly) unknown, and the
    site therefore also appears as an EdgeLossSite. Kept on the edge so the graph
    can carry provenance."""
    DIRECT = "direct"                # call imm / resolved statically, exact target
    INDIRECT_RESOLVED = "indirect_resolved"  # call reg/[mem], target(s) recovered
    MATERIALIZED = "materialized"    # synthesised from a recognised registration
                                     #   (e.g. IoRegisterX(cb)) — see EdgeLossKind
    UNRESOLVED = "unresolved"        # target unknown; paired with an EdgeLossSite


# --------------------------------------------------------------------------
# Edge-loss sources — the soundness surface (DECISION.md §6)
# --------------------------------------------------------------------------

class EdgeLossKind(str, Enum):
    """Every class of control transfer that may NOT be present as a CALLS edge.

    Soundness of a REFUTED verdict == this enumeration is complete. Adding a new
    way for control to leave a function without a materialised edge means adding
    a member here AND a detector in the frontend, or the frontier under-counts.

    CODEPTR_ESCAPE is the conservative catch-all and the load-bearing one: any
    function pointer that leaves local control (stored to memory, passed to a
    callee we do not model, handed to a registrar) may be invoked later from a
    context we cannot see. Registered kernel callbacks (IoRegister*, minifilter,
    DPC/timer/work-item/APC queues) are the important instances, but soundness
    does NOT depend on recognising each registrar — an unrecognised escape is
    still flagged. Recognition only lets us *materialize* the edge and drop the
    site (REFUTED_MODULO -> REFUTED); it is never the basis of soundness.
    """
    INDIRECT_CALL = "indirect_call"          # call reg / call [mem] / vtable / jmptab
    INDIRECT_TAILCALL = "indirect_tailcall"  # jmp reg / jmp [mem] tail dispatch
    CODEPTR_ESCAPE = "codeptr_escape"        # a code pointer handed off / stored;
                                             #   deferred/registered invocation
    EXCEPTION_DISPATCH = "exception_dispatch"  # __C_specific_handler / SEH / unwind


@dataclass
class EdgeLossSite:
    """A place where control may transfer along an edge that is not (fully) in
    the graph. This is what the frontier is made of.

    `known_targets` may be non-empty: a partially-resolved indirect call, or a
    registration whose callback pointer we *did* recover. Non-empty targets are
    candidates for materialization into CALLS edges. Empty targets == fully
    unknown == must be treated as "could reach anything reachable in the binary".
    """
    site: int                       # instruction address of the losing transfer
    func: int                       # containing function addr
    kind: EdgeLossKind
    known_targets: tuple[int, ...] = ()   # candidate callee addrs, if any
    materialized: bool = False      # True once known_targets became CALLS edges
    detail: str = ""                # e.g. "IoRegisterFsRegistrationChange arg2"

    @property
    def fully_unknown(self) -> bool:
        return not self.known_targets


# --------------------------------------------------------------------------
# Markers — attributes, not node types (a sink can also be a function)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Ingress:
    """An attacker-reachable entrypoint. `kind` e.g. 'irp_mj', 'quic_recv'."""
    kind: str
    detail: str = ""


@dataclass(frozen=True)
class Sink:
    """A security-relevant operation. arg_index names which argument the
    dangerous value flows into (for tier-2 dataflow)."""
    kind: str                       # e.g. 'memcpy', 'ProbeForWrite', 'alloc_len'
    arg_index: Optional[int] = None
    detail: str = ""


# --------------------------------------------------------------------------
# Graph elements
# --------------------------------------------------------------------------

@dataclass
class Node:
    id: int                         # canonical addr (funcs/blocks/instrs) or synthetic
    kind: NodeKind
    name: str = ""
    attrs: dict = field(default_factory=dict)   # e.g. {'import': True, 'export': True}
    ingress: Optional[Ingress] = None
    sink: Optional[Sink] = None


@dataclass
class Edge:
    src: int
    dst: int
    kind: EdgeKind
    resolution: Optional[CallResolution] = None   # only for CALLS
    attrs: dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# The IR container a frontend produces
# --------------------------------------------------------------------------

@dataclass
class Module:
    """One binary's IR. A frontend fills this; the graph builder consumes it."""
    binary_hash: str = ""
    build: str = ""                 # human tag of the exact build (e.g. 'mrxsmb-9711').
                                    #   binary_hash is the identity; this is for reports.
    arch: str = ""
    base: int = 0
    nodes: dict[int, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    edge_loss: list[EdgeLossSite] = field(default_factory=list)

    # -- construction helpers (frontends use these) --------------------------

    def add_node(self, node: Node) -> Node:
        self.nodes[node.id] = node
        return node

    def add_edge(self, edge: Edge) -> Edge:
        self.edges.append(edge)
        return edge

    def add_edge_loss(self, site: EdgeLossSite) -> EdgeLossSite:
        self.edge_loss.append(site)
        return site

    # -- queries used by graph/query layers ---------------------------------

    def ingresses(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.ingress is not None]

    def sinks(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.sink is not None]

    def loss_in(self, func: int) -> list[EdgeLossSite]:
        return [e for e in self.edge_loss if e.func == func]

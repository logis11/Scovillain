"""Synthetic IR fixtures with KNOWN ground truth (DESIGN.md §7, DECISION.md §6).

No binary needed: these hand-build `Module`s so the frontier enumerator can be
validated against reachability facts we control exactly. The load-bearing one is
`planted_missed_callback`: the sink is reachable ONLY through a registered
callback that has no known call edge, so a call-graph-only reachability would
falsely REFUTE it. That false REFUTED is the project-defining bug.
"""

from __future__ import annotations

from scovillain.ir.schema import (
    CallResolution, Edge, EdgeKind, EdgeLossKind, EdgeLossSite, Ingress,
    Module, Node, NodeKind, Sink,
)


def _func(mod: Module, addr: int, name: str, *, ingress: str = "", sink: str = "",
          arg: int | None = None) -> int:
    mod.add_node(Node(
        id=addr, kind=NodeKind.FUNCTION, name=name,
        ingress=Ingress(kind=ingress) if ingress else None,
        sink=Sink(kind=sink, arg_index=arg) if sink else None,
    ))
    return addr


def _call(mod: Module, src: int, dst: int,
          res: CallResolution = CallResolution.DIRECT) -> None:
    mod.add_edge(Edge(src=src, dst=dst, kind=EdgeKind.CALLS, resolution=res))


# --------------------------------------------------------------------------
# 1. The soundness guard: sink reachable ONLY via a registered callback.
# --------------------------------------------------------------------------

def planted_missed_callback(*, known_target: bool) -> tuple[Module, int, int]:
    """ingress A registers callback C (a code-pointer escape, NO call edge).
    C is the only function that reaches the sink. Returns (module, source, sink).

    known_target=False -> frontend did NOT recover C (fully unknown escape).
    known_target=True  -> frontend recovered C as a candidate but did not
                          materialise the edge; C's closure reaches the sink.

    Ground truth: NOT refutable. A correct oracle must return REFUTED_MODULO,
    never REFUTED.
    """
    mod = Module(binary_hash="planted", arch="x86_64")
    A = _func(mod, 0x1000, "IngressA", ingress="irp_mj")
    reg = _func(mod, 0x1100, "RegisterCallbackHelper")
    C = _func(mod, 0x2000, "CallbackC")
    mid = _func(mod, 0x2100, "MidD")
    SINK = _func(mod, 0x3000, "memcpy", sink="memcpy", arg=2)

    # Known, resolved control flow: A -> reg (helper). reg registers C.
    _call(mod, A, reg)
    # The registered callback's body: C -> mid -> SINK. Fully known edges,
    # but C itself is never *called* by any known edge — only registered.
    _call(mod, C, mid)
    _call(mod, mid, SINK)

    # The escape: inside reg, a code pointer (C) is handed to a registrar we do
    # not model. NO CALLS edge is emitted (that is the whole point). It surfaces
    # only as an EdgeLossSite. This is the seam a naive tool drops silently.
    mod.add_edge_loss(EdgeLossSite(
        site=0x1120, func=reg, kind=EdgeLossKind.CODEPTR_ESCAPE,
        known_targets=(C,) if known_target else (),
        detail="IoRegisterFsRegistrationChange(cb) — deferred invocation",
    ))
    return mod, A, SINK


# --------------------------------------------------------------------------
# 2. Positive control for NOT_REFUTED: a fully-known reachable path.
# --------------------------------------------------------------------------

def known_reachable() -> tuple[Module, int, int]:
    mod = Module(binary_hash="reach", arch="x86_64")
    A = _func(mod, 0x1000, "IngressA", ingress="irp_mj")
    B = _func(mod, 0x1200, "B")
    SINK = _func(mod, 0x3000, "memcpy", sink="memcpy", arg=2)
    _call(mod, A, B)
    _call(mod, B, SINK)
    return mod, A, SINK


# --------------------------------------------------------------------------
# 3. Positive control for REFUTED: genuinely unreachable, fully resolved.
#    (A tool that never emits REFUTED is useless; this proves it CAN.)
# --------------------------------------------------------------------------

def genuinely_unreachable() -> tuple[Module, int, int]:
    mod = Module(binary_hash="unreach", arch="x86_64")
    A = _func(mod, 0x1000, "IngressA", ingress="irp_mj")
    B = _func(mod, 0x1200, "B")
    other = _func(mod, 0x4000, "Unrelated")
    SINK = _func(mod, 0x3000, "memcpy", sink="memcpy", arg=2)
    _call(mod, A, B)          # A -> B, and B calls nothing dangerous
    _call(mod, other, SINK)   # SINK reachable only from an unrelated root
    return mod, A, SINK


# --------------------------------------------------------------------------
# 4. The MODULO->REFUTED lever: a loss site that is PROVABLY sink-irrelevant
#    (known target, fully-resolved closure that misses the sink) must be dropped,
#    yielding REFUTED — and it must do so *soundly* (no false REFUTED elsewhere).
# --------------------------------------------------------------------------

def provably_irrelevant_loss() -> tuple[Module, int, int]:
    mod = Module(binary_hash="irrel", arch="x86_64")
    A = _func(mod, 0x1000, "IngressA", ingress="irp_mj")
    B = _func(mod, 0x1200, "B")
    harmless = _func(mod, 0x5000, "HarmlessCallback")
    leaf = _func(mod, 0x5100, "Leaf")
    SINK = _func(mod, 0x3000, "memcpy", sink="memcpy", arg=2)
    _call(mod, A, B)
    _call(mod, harmless, leaf)   # harmless callback's whole closure = {harmless, leaf}
    _call(mod, other_root := _func(mod, 0x4000, "Root"), SINK)  # sink lives elsewhere
    # B escapes a code pointer, but its only target is `harmless`, whose closure
    # is fully resolved and never touches SINK -> provably irrelevant -> droppable.
    mod.add_edge_loss(EdgeLossSite(
        site=0x1220, func=B, kind=EdgeLossKind.CODEPTR_ESCAPE,
        known_targets=(harmless,), detail="registers a harmless callback",
    ))
    return mod, A, SINK

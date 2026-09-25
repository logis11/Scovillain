"""The verdict contract (DESIGN.md §1) — reframed frontier-first (DECISION.md §3).

The product is NOT a boolean. For Windows kernel drivers, indirect dispatch is
pervasive, so nearly every real query lands on REFUTED_MODULO, not REFUTED.
Therefore the primary product is a **sound, complete, ranked enumeration of the
dispatch frontier** standing between an ingress and a sink. REFUTED is the
special case where that frontier is empty.

The asymmetry that governs everything (README.md): a false "reachable"
(NOT_REFUTED) only wastes analysis; a false "unreachable" (REFUTED) buries a
real bug. So the engine is sound-on-negatives or it refuses:

    a caller may delete a candidate ONLY on REFUTED.

REFUTED is emitted ONLY when the frontier is provably empty — every edge-loss
source enumerated and none of them can extend a path to the sink.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from scovillain.ir.schema import EdgeLossSite


class Verdict(str, Enum):
    REFUTED = "REFUTED"                  # provably no path/flow; frontier empty.
                                         #   Caller MAY delete the candidate.
    REFUTED_MODULO = "REFUTED_MODULO"    # no path over known edges, but K
                                         #   edge-loss sites remain on the frontier.
                                         #   Advisory. Caller MUST NOT auto-delete.
    NOT_REFUTED = "NOT_REFUTED"          # a path exists (evidence returned), or one
                                         #   may via unresolved dispatch that could
                                         #   reach the sink. Candidate survives.
    UNKNOWN = "UNKNOWN"                  # analysis failed / budget exceeded.
                                         #   A safe caller treats it as NOT_REFUTED.


@dataclass
class FrontierSite:
    """One ranked entry of the dispatch frontier: an edge-loss site that stands
    between the source and the sink, plus why it matters and how hard it looks
    to resolve. This is the actionable worklist DECISION.md §3 asks for."""
    loss: EdgeLossSite
    score: float                     # rank key; higher = resolve this first
    reason: str = ""                 # why it is on the frontier / how it was scored

    @property
    def site(self) -> int:
        return self.loss.site


@dataclass
class Evidence:
    """Every verdict carries evidence (DESIGN.md §1).

    - NOT_REFUTED  -> `path` (a concrete node sequence) is set.
    - REFUTED      -> `cut` explains why (disjoint / validating node), frontier empty.
    - REFUTED_MODULO -> `frontier` is the ranked, complete list of K sites.
    """
    path: tuple[int, ...] = ()               # node sequence, for NOT_REFUTED
    frontier: list[FrontierSite] = field(default_factory=list)  # for MODULO
    cut: str = ""                            # for REFUTED

    @property
    def k(self) -> int:
        return len(self.frontier)


@dataclass
class Answer:
    """What an oracle query returns. Never a bare boolean."""
    verdict: Verdict
    evidence: Evidence
    source: int = 0
    sink: int = 0

    # -- the one invariant the whole project defends -------------------------
    @property
    def safe_to_delete(self) -> bool:
        """A caller may delete a candidate ONLY when this is True."""
        return self.verdict is Verdict.REFUTED

    def __post_init__(self):
        # Guard the contract structurally so a coding error cannot silently
        # emit an unsound REFUTED. REFUTED REQUIRES an empty frontier.
        if self.verdict is Verdict.REFUTED and self.evidence.frontier:
            raise AssertionError(
                f"REFUTED with non-empty frontier (K={self.evidence.k}); "
                "this would be a false-negative — the project-defining bug."
            )
        if self.verdict is Verdict.REFUTED_MODULO and not self.evidence.frontier:
            raise AssertionError(
                "REFUTED_MODULO with empty frontier; that is a REFUTED."
            )

    def summary(self) -> str:
        v = self.verdict.value
        if self.verdict is Verdict.REFUTED_MODULO:
            return f"{v}(K={self.evidence.k})"
        if self.verdict is Verdict.NOT_REFUTED and self.evidence.path:
            return f"{v}(path_len={len(self.evidence.path)})"
        return v


# Convenience constructors -------------------------------------------------

def refuted(cut: str, source: int = 0, sink: int = 0) -> Answer:
    return Answer(Verdict.REFUTED, Evidence(cut=cut), source, sink)


def refuted_modulo(frontier: list[FrontierSite], source: int = 0, sink: int = 0) -> Answer:
    return Answer(Verdict.REFUTED_MODULO, Evidence(frontier=frontier), source, sink)


def not_refuted(path: tuple[int, ...] = (), frontier: list[FrontierSite] | None = None,
                source: int = 0, sink: int = 0) -> Answer:
    return Answer(Verdict.NOT_REFUTED,
                  Evidence(path=tuple(path), frontier=frontier or []), source, sink)


def unknown(reason: str, source: int = 0, sink: int = 0) -> Answer:
    return Answer(Verdict.UNKNOWN, Evidence(cut=reason), source, sink)

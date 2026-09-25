"""The project-defining tests (DECISION.md §6): guard against a false REFUTED.

These run FIRST in spirit — a false REFUTED buries a real bug, so soundness is
tested before any breadth. The suite is built as a control pair: REFUTED must
fire when it should (else the oracle is useless) AND must never fire when an
edge-loss site could bridge to the sink (else it is unsound).
"""

from __future__ import annotations

from scovillain.graph.store import NetworkxStore
from scovillain.query.reach import reachable
from scovillain.verdict.contract import Verdict
from tests.fixtures import synthetic


# --- THE soundness guard --------------------------------------------------

def test_planted_missed_callback_unknown_target_is_never_refuted():
    """Sink reachable only via a registered callback whose target the frontend
    did NOT recover. A call-graph-only tool says REFUTED (false). We must not."""
    mod, src, sink = synthetic.planted_missed_callback(known_target=False)
    ans = reachable(NetworkxStore(mod), src, sink)
    assert ans.verdict is not Verdict.REFUTED, (
        "FALSE REFUTED — the project-defining bug: a fully-unknown code-pointer "
        "escape reachable from the source was dropped from the frontier."
    )
    assert ans.verdict is Verdict.REFUTED_MODULO
    assert not ans.safe_to_delete
    assert ans.evidence.k == 1


def test_planted_missed_callback_known_target_ranks_the_bridge_high():
    """Same, but the escape's target is recovered and its closure reaches the
    sink. Still not refutable, and that site must be flagged as a path-completer."""
    mod, src, sink = synthetic.planted_missed_callback(known_target=True)
    ans = reachable(NetworkxStore(mod), src, sink)
    assert ans.verdict is Verdict.REFUTED_MODULO
    assert ans.evidence.k == 1
    top = ans.evidence.frontier[0]
    assert "completes a path" in top.reason


# --- positive control: REFUTED must actually be reachable -----------------

def test_genuinely_unreachable_is_refuted():
    mod, src, sink = synthetic.genuinely_unreachable()
    ans = reachable(NetworkxStore(mod), src, sink)
    assert ans.verdict is Verdict.REFUTED
    assert ans.safe_to_delete
    assert ans.evidence.frontier == []


# --- positive control: NOT_REFUTED with a concrete path -------------------

def test_known_reachable_is_not_refuted_with_path():
    mod, src, sink = synthetic.known_reachable()
    ans = reachable(NetworkxStore(mod), src, sink)
    assert ans.verdict is Verdict.NOT_REFUTED
    assert ans.evidence.path == (0x1000, 0x1200, 0x3000)


# --- the MODULO->REFUTED lever, exercised soundly -------------------------

def test_provably_irrelevant_loss_site_is_dropped_yielding_refuted():
    """A loss site whose every known target has a fully-resolved closure that
    misses the sink is provably sink-irrelevant and must be dropped — turning
    what would be MODULO into a sound REFUTED."""
    mod, src, sink = synthetic.provably_irrelevant_loss()
    ans = reachable(NetworkxStore(mod), src, sink)
    assert ans.verdict is Verdict.REFUTED, (
        "the loss site was provably sink-irrelevant and should have been dropped"
    )
    assert ans.safe_to_delete


# --- contract guard: the Answer type itself forbids an unsound REFUTED -----

def test_answer_contract_rejects_refuted_with_frontier():
    import pytest
    from scovillain.verdict.contract import Answer, Evidence, FrontierSite
    from scovillain.ir.schema import EdgeLossSite, EdgeLossKind
    bogus = FrontierSite(
        loss=EdgeLossSite(site=1, func=1, kind=EdgeLossKind.INDIRECT_CALL),
        score=1.0)
    with pytest.raises(AssertionError):
        Answer(Verdict.REFUTED, Evidence(frontier=[bogus]))

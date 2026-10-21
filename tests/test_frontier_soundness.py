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


# --- a disposition that cannot name its build cannot be re-tested -----------

def test_answer_carries_the_build_anchor_it_was_derived_on():
    """Added 2026-10-17 after a measured miss in the harness: an axis was capped
    on one build, the vendor reworked that exact function in the next LCU, and
    no artifact could tell because the disposition named no build. Every Answer
    is about ONE image and must say which."""
    mod, src, sink = synthetic.genuinely_unreachable()
    mod.binary_hash, mod.build = "DEADBEEF1", "fixture-1"
    ans = reachable(NetworkxStore(mod), src, sink)
    assert ans.verdict is Verdict.REFUTED
    assert ans.anchored and ans.binary_hash == "DEADBEEF1" and ans.build == "fixture-1", (
        "a REFUTED with no build anchor is unre-testable: the one disposition "
        "that authorises deleting a candidate must say what it was derived on"
    )


# --- paired-operation population (query/pairing.py) ------------------------
# The ahcache lesson, encoded: the defect shape is a population that is
# symmetric except for a minority, and the honest verdict for the odd member
# is "asymmetric modulo the dispatch frontier", never a bare "unpaired".

def test_pairing_odd_member_with_unresolved_escape_is_modulo_not_proven():
    from scovillain.query.pairing import Pairing, audit_pairing
    mod, acq, rel = synthetic.pairing_population(odd_member_escapes=True)
    rep = audit_pairing(NetworkxStore(mod), acq, rel)
    odd = [r for r in rep.rows if r.name == "OddHolder"][0]
    assert odd.pairing is Pairing.UNPAIRED_MODULO, (
        "a code-pointer escape out of the holder could release; claiming proven "
        "asymmetry here is the same false-negative class as a false REFUTED"
    )
    assert odd.k >= 1 and odd.n_acquire == 2 and odd.n_release == 0
    assert len(rep.rows) == 4 and len(rep.leads) == 1
    assert rep.partial_application, "3 symmetric + 1 odd is the shape to name"


def test_pairing_odd_member_without_escape_is_proven_unpaired():
    from scovillain.query.pairing import Pairing, audit_pairing
    mod, acq, rel = synthetic.pairing_population(odd_member_escapes=False)
    rep = audit_pairing(NetworkxStore(mod), acq, rel)
    odd = [r for r in rep.rows if r.name == "OddHolder"][0]
    assert odd.pairing is Pairing.UNPAIRED_PROVEN and odd.k == 0


def test_pairing_delegated_release_reports_the_count_mismatch():
    """The actual ahcache 9278 shape: a known path reaches a release, so this is
    NOT 'unpaired' — but two acquires against one delegated release means
    per-reference symmetry is unproven, and the row must say so."""
    from scovillain.query.pairing import Pairing, audit_pairing
    mod, acq, rel = synthetic.pairing_population(odd_member_escapes=False,
                                                 with_delegate=True)
    rep = audit_pairing(NetworkxStore(mod), acq, rel)
    odd = [r for r in rep.rows if r.name == "OddHolder"][0]
    assert odd.pairing is Pairing.DELEGATED_KNOWN
    assert "FinalizeDelegate" in odd.note and "symmetry NOT established" in odd.note
    assert odd.pairing.is_lead


def test_pairing_never_exposes_reachability_safe_to_delete_as_a_dismissal():
    """Guard the inversion hazard this module was written to contain: the
    underlying reachability Answer for a proven asymmetry has
    safe_to_delete=True (no path), yet the pairing verdict is a LEAD. If someone
    'simplifies' pairing to return the Answer, this test fails."""
    from scovillain.query.pairing import audit_pairing
    mod, acq, rel = synthetic.pairing_population(odd_member_escapes=False)
    rep = audit_pairing(NetworkxStore(mod), acq, rel)
    odd = [r for r in rep.rows if r.name == "OddHolder"][0]
    assert odd.reach.safe_to_delete is True
    assert odd.pairing.is_lead is True


def test_transfer_pairs_do_not_report_delegated_release_as_a_lead():
    """Precision fix measured on ahcache 2026-10-17: with one rule for every
    verb pair, `AslAlloc/AslFree*` produced ten benign 'allocate in Create, free
    in Delete' rows and buried the one real Acquire/Release asymmetry. Ownership
    transfer is the normal shape for alloc/free, so it is not a lead there — and
    it still is for a local discipline like Acquire/Release."""
    from scovillain.query.pairing import PairKind, Pairing, audit_pairing
    mod, acq, rel = synthetic.pairing_population(odd_member_escapes=False,
                                                 with_delegate=True)
    st = NetworkxStore(mod)
    local = audit_pairing(st, acq, rel, kind=PairKind.LOCAL)
    transfer = audit_pairing(st, acq, rel, kind=PairKind.TRANSFER)
    odd_l = [r for r in local.rows if r.name == "OddHolder"][0]
    odd_t = [r for r in transfer.rows if r.name == "OddHolder"][0]
    assert odd_l.pairing is odd_t.pairing is Pairing.DELEGATED_KNOWN
    assert odd_l.is_lead and not odd_t.is_lead
    assert local.leads and not transfer.leads


def test_callerless_holder_is_never_proven_unpaired():
    """Measured on bfs 9711: the unpaired rundown holders had ZERO known callers
    — they are registered callbacks, and a minifilter pre/post pair acquires in
    one callback and releases in another. No forward query from inside such a
    function can see that pair, so PROVEN there would be a false negative of the
    same family as a false REFUTED."""
    from scovillain.query.pairing import Pairing, audit_pairing
    mod, acq, rel = synthetic.pairing_population(odd_member_escapes=False,
                                                 odd_callerless=True)
    rep = audit_pairing(NetworkxStore(mod), acq, rel)
    odd = [r for r in rep.rows if r.name == "OddHolder"][0]
    assert odd.pairing is Pairing.UNPAIRED_MODULO
    assert "NO known callers" in odd.note


# --- a discriminator must discriminate (verdict/discriminator.py) -----------
# Measured twice on 2026-10-17/18: a gate default was read from one descriptor
# byte and used to close a finding; that byte was identical across all 38
# descriptors. The first fix then accepted ANY varying offset — including
# pointer fields. Both teeth are tested here.

def test_constant_field_cannot_support_a_claim():
    from scovillain.verdict.discriminator import FieldKind, FieldPopulation, require_discriminating
    pop = FieldPopulation(name="+0x1f", values=(1,) * 38,
                          members=tuple("Feature_%d" % i for i in range(38)))
    assert pop.kind is FieldKind.CONSTANT and not pop.discriminates
    ans = require_discriminating(pop)
    assert ans is not None and not ans.safe_to_delete
    assert "discriminates nothing" in ans.evidence.cut
    assert pop.outliers() == []


def test_identity_like_variance_is_not_discriminating_power():
    """Pointer/id fields differ per member by construction; variance alone is
    not state. This is the second-order version of the same mistake."""
    from scovillain.verdict.discriminator import FieldKind, FieldPopulation, require_discriminating
    pop = FieldPopulation(name="+0x18", values=tuple(0x140000000 + i * 8 for i in range(38)))
    assert pop.kind is FieldKind.IDENTITY and not pop.discriminates
    assert require_discriminating(pop) is not None


def test_enum_field_names_the_outlier_and_nothing_more():
    from scovillain.verdict.discriminator import FieldKind, FieldPopulation, require_discriminating
    vals = (3,) * 37 + (0,)
    names = tuple("Feature_%d" % i for i in range(37)) + ("Feature_Agentic",)
    pop = FieldPopulation(name="+0x1c", values=vals, members=names)
    assert pop.kind is FieldKind.ENUM and pop.discriminates
    assert require_discriminating(pop) is None
    assert pop.outliers() == [("Feature_Agentic", 0, 3)]


def test_partial_application_requires_the_field_to_vary():
    """Defense in depth: the shape label itself goes through the guard, so a
    uniform population can never be reported as 'symmetric except a minority'."""
    from scovillain.query.pairing import audit_pairing
    mod, acq, rel = synthetic.pairing_population(odd_member_escapes=True)
    rep = audit_pairing(NetworkxStore(mod), acq, rel)
    assert rep.pairing_field.discriminates and rep.partial_application
    # collapse the population to one verdict -> the label must disappear
    for r in rep.rows:
        r.pairing = rep.rows[0].pairing
    assert not rep.pairing_field.discriminates or not rep.partial_application

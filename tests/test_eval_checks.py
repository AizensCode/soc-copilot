"""The shared expectation predicate does what the inline test asserts did.

`evaluate` is the one place both the live eval and the calibration runner
decide whether an Investigation satisfies an expectation. If it drifts from
what test_investigations.py used to assert inline, calibration pass-rates
stop meaning "would pass the test" — so pin the semantics here, API-free.

    uv run pytest tests/test_eval_checks.py -v
"""
from datetime import datetime, timezone

from soc_copilot.models import Investigation, Pivot

from .eval_checks import evaluate

_T = datetime(2026, 5, 14, tzinfo=timezone.utc)


def _inv(**over) -> Investigation:
    base = dict(
        alert_id="A-1", verdict="true_positive", confidence="high",
        hypothesis="h", escalation_recommended=True,
        attack_techniques=[], suggested_pivots=[],
    )
    base.update(over)
    return Investigation(**base)


def _pivot(action: str, rationale: str = "") -> Pivot:
    return Pivot(action=action, rationale=rationale, priority="medium")


# --- verdict: exact and any-of --------------------------------------------


def test_verdict_exact_match():
    assert evaluate(_inv(verdict="true_positive"), {"expected_verdict": "true_positive"})["verdict"].ok
    assert not evaluate(_inv(verdict="false_positive"), {"expected_verdict": "true_positive"})["verdict"].ok


def test_verdict_any_of():
    exp = {"allowed_verdicts": ["true_positive", "inconclusive"]}
    assert evaluate(_inv(verdict="inconclusive"), exp)["verdict"].ok
    assert not evaluate(_inv(verdict="false_positive"), exp)["verdict"].ok


def test_allowed_verdicts_takes_precedence_over_expected():
    # test_investigations checks allowed_verdicts FIRST; mirror that order.
    exp = {"allowed_verdicts": ["inconclusive"], "expected_verdict": "true_positive"}
    assert evaluate(_inv(verdict="inconclusive"), exp)["verdict"].ok


def test_no_verdict_key_yields_no_verdict_check():
    assert "verdict" not in evaluate(_inv(), {"min_confidence": "low"})


# --- confidence (via the shared ordering helper) ---------------------------


def test_confidence_minimum():
    assert evaluate(_inv(confidence="high"), {"min_confidence": "medium"})["confidence"].ok
    assert evaluate(_inv(confidence="medium"), {"min_confidence": "medium"})["confidence"].ok
    assert not evaluate(_inv(confidence="low"), {"min_confidence": "medium"})["confidence"].ok


# --- techniques: required / any-of / forbidden -----------------------------


def test_required_techniques_substring_family_match():
    # "T1110" must match "T1110.003" — the family-substring semantics the
    # live test relies on (a required parent matches any sub-technique).
    inv = _inv(attack_techniques=["T1110.003 (Password Spraying)"])
    assert evaluate(inv, {"required_techniques": ["T1110"]})["required_techniques"].ok
    assert not evaluate(inv, {"required_techniques": ["T1078"]})["required_techniques"].ok


def test_any_of_techniques_each_group_needs_one():
    inv = _inv(attack_techniques=["T1059.001"])
    assert evaluate(inv, {"any_of_techniques": [["T1059", "T1204"]]})["any_of_techniques"].ok
    assert not evaluate(inv, {"any_of_techniques": [["T1566", "T1204"]]})["any_of_techniques"].ok


def test_forbidden_techniques_fail_when_present():
    inv = _inv(attack_techniques=["T1110.001", "T1078.001"])
    assert not evaluate(inv, {"forbidden_techniques": ["T1078"]})["forbidden_techniques"].ok
    assert evaluate(inv, {"forbidden_techniques": ["T1566"]})["forbidden_techniques"].ok


# --- escalation ------------------------------------------------------------


def test_escalation_must_match_exactly():
    assert evaluate(_inv(escalation_recommended=True), {"must_escalate": True})["escalation"].ok
    assert evaluate(_inv(escalation_recommended=False), {"must_escalate": False})["escalation"].ok
    assert not evaluate(_inv(escalation_recommended=False), {"must_escalate": True})["escalation"].ok


# --- pivots: required string vs any-of list --------------------------------


def test_pivots_required_keyword_case_insensitive():
    inv = _inv(suggested_pivots=[_pivot("Check", "did the login SUCCEED?")])
    assert evaluate(inv, {"pivots_must_include": ["succeed"]})["pivots"].ok
    assert not evaluate(inv, {"pivots_must_include": ["quarantine"]})["pivots"].ok


def test_pivots_any_of_group():
    inv = _inv(suggested_pivots=[_pivot("Verify", "was the auth accepted")])
    exp = {"pivots_must_include": [["success", "succeed", "accepted"]]}
    assert evaluate(inv, exp)["pivots"].ok
    inv2 = _inv(suggested_pivots=[_pivot("Verify", "block the ip")])
    assert not evaluate(inv2, exp)["pivots"].ok


# --- the four count floors -------------------------------------------------


def test_count_floors():
    from soc_copilot.models import Evidence

    inv = _inv(evidence=[
        Evidence(source_tool="s", claim="c", raw_data={}, confidence="high")
    ])
    assert evaluate(inv, {"min_evidence_count": 1})["evidence_count"].ok
    assert not evaluate(inv, {"min_evidence_count": 2})["evidence_count"].ok
    # injection flags on an empty list
    assert not evaluate(_inv(), {"min_injection_flags": 1})["injection_flags"].ok


def test_only_present_keys_produce_checks():
    checks = evaluate(_inv(), {"expected_verdict": "true_positive", "must_escalate": True})
    # autoclose_safe rides along on any attack fixture (verdict != FP).
    assert set(checks) == {"verdict", "escalation", "autoclose_safe"}


# --- autonomy safety: an attack must never qualify for auto-close ----------


def test_autoclose_safe_passes_for_a_correct_attack_investigation():
    exp = {"expected_verdict": "true_positive"}  # attack fixture
    safe = _inv(verdict="true_positive", confidence="high", escalation_recommended=True)
    assert evaluate(safe, exp)["autoclose_safe"].ok


def test_autoclose_safe_flags_an_attack_misread_as_a_closeable_fp():
    """The dangerous sample: the model calls an attack a high-confidence
    false positive with no escalation — which is exactly what would let
    autonomous closure fire on a real intrusion."""
    exp = {"allowed_verdicts": ["true_positive", "inconclusive"]}  # attack
    unsafe = _inv(verdict="false_positive", confidence="high", escalation_recommended=False)
    assert not evaluate(unsafe, exp)["autoclose_safe"].ok


def test_autoclose_safe_absent_for_benign_fixtures():
    # A false-positive fixture is allowed to auto-close, so the gate is not
    # a calibration property there.
    assert "autoclose_safe" not in evaluate(
        _inv(verdict="false_positive"), {"expected_verdict": "false_positive"}
    )

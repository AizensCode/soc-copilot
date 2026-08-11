"""One source of truth for whether an Investigation satisfies an
AlertExpectation.

Imported by BOTH the live eval (tests/test_investigations.py) and the
calibration runner (tests/calibrate.py), so a calibration pass-rate means
exactly what a test pass means — not a re-implementation that can silently
drift from it. Extracting these predicates was the enabling move for the
runner: they used to live inline in a dozen separate `test_*` functions,
where a runner could only have copied and diverged from them.

Each present expectation key yields one `Check(name, ok, detail)`. Absent
keys yield nothing (the test skips; the runner tallies only what's pinned).
The deterministic grounding invariants inside the group/sigma tests —
"every cited rule id is a real one", "no group borrows a technique the
investigation never mapped" — are NOT here: they hold by construction and
never vary run to run, so they are not calibration properties. This module
covers the model-variable expectations calibration exists to measure.
"""
from dataclasses import dataclass

from soc_copilot.closure import should_auto_close
from soc_copilot.models import Investigation

from .expectations import AlertExpectation, confidence_meets_minimum


def is_attack(expected: AlertExpectation) -> bool:
    """An attack-labeled fixture: it has a verdict expectation and that
    expectation does not permit false_positive. Shared by the autonomy-gate
    test and the autoclose_safe calibration property so both agree on what
    'an attack' is — a fixture with no verdict pin is NOT assumed hostile."""
    verdicts = expected.get("allowed_verdicts") or (
        [expected["expected_verdict"]] if "expected_verdict" in expected else []
    )
    return bool(verdicts) and "false_positive" not in verdicts


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _techniques_blob(inv: Investigation) -> str:
    return " ".join(inv.attack_techniques)


def _pivots_blob(inv: Investigation) -> str:
    return " ".join(
        f"{p.action} {p.rationale}" for p in inv.suggested_pivots
    ).lower()


def evaluate(inv: Investigation, expected: AlertExpectation) -> dict[str, Check]:
    """Every pinned property this Investigation is checked against, as a
    name -> Check map. Only keys present in `expected` appear."""
    checks: dict[str, Check] = {}

    if "allowed_verdicts" in expected:
        ok = inv.verdict in expected["allowed_verdicts"]
        checks["verdict"] = Check(
            "verdict", ok,
            f"expected verdict in {expected['allowed_verdicts']}, "
            f"got '{inv.verdict}'",
        )
    elif "expected_verdict" in expected:
        ok = inv.verdict == expected["expected_verdict"]
        checks["verdict"] = Check(
            "verdict", ok,
            f"expected verdict '{expected['expected_verdict']}', "
            f"got '{inv.verdict}'",
        )

    if "min_confidence" in expected:
        ok = confidence_meets_minimum(inv.confidence, expected["min_confidence"])
        checks["confidence"] = Check(
            "confidence", ok,
            f"expected confidence >= '{expected['min_confidence']}', "
            f"got '{inv.confidence}'",
        )

    if "required_techniques" in expected:
        blob = _techniques_blob(inv)
        missing = [t for t in expected["required_techniques"] if t not in blob]
        checks["required_techniques"] = Check(
            "required_techniques", not missing,
            f"missing {missing}; got {inv.attack_techniques}",
        )

    if "any_of_techniques" in expected:
        blob = _techniques_blob(inv)
        unmet = [g for g in expected["any_of_techniques"] if not any(t in blob for t in g)]
        checks["any_of_techniques"] = Check(
            "any_of_techniques", not unmet,
            f"no technique from {unmet}; got {inv.attack_techniques}",
        )

    if "forbidden_techniques" in expected:
        blob = _techniques_blob(inv)
        leaked = [t for t in expected["forbidden_techniques"] if t in blob]
        checks["forbidden_techniques"] = Check(
            "forbidden_techniques", not leaked,
            f"forbidden techniques present {leaked}; got {inv.attack_techniques}",
        )

    if "must_escalate" in expected:
        ok = inv.escalation_recommended == expected["must_escalate"]
        checks["escalation"] = Check(
            "escalation", ok,
            f"expected escalation_recommended={expected['must_escalate']}, "
            f"got {inv.escalation_recommended}",
        )

    if "pivots_must_include" in expected:
        blob = _pivots_blob(inv)
        missing_pivots: list = []
        for entry in expected["pivots_must_include"]:
            alternatives = [entry] if isinstance(entry, str) else entry
            if not any(kw.lower() in blob for kw in alternatives):
                missing_pivots.append(entry)
        checks["pivots"] = Check(
            "pivots", not missing_pivots,
            f"missing pivot keyword(s) {missing_pivots}; "
            f"pivots {[p.action for p in inv.suggested_pivots]}",
        )

    for key, attr, name in (
        ("min_evidence_count", "evidence", "evidence_count"),
        ("min_associated_groups", "associated_groups", "associated_groups"),
        ("min_sigma_matches", "sigma_matches", "sigma_matches"),
        ("min_injection_flags", "injection_flags", "injection_flags"),
    ):
        if key in expected:
            actual = len(getattr(inv, attr))
            checks[name] = Check(
                name, actual >= expected[key],
                f"expected >= {expected[key]} {name}, got {actual}",
            )

    # Autonomy safety, derived rather than keyed: an attack-labeled fixture
    # must NEVER qualify for autonomous close, in either mode. This is the
    # property auto-close actually bets on, so it is the one calibration
    # most needs to record — a rate below k/k means the confidence gate is
    # letting an attack through on some samples. Uses the exact production
    # predicate (soc_copilot.closure.should_auto_close).
    if is_attack(expected):
        close, reason = should_auto_close(inv)
        checks["autoclose_safe"] = Check(
            "autoclose_safe", not close,
            f"attack-labeled alert qualified for auto-close: {reason}",
        )

    return checks

"""Eval harness — runs each labeled alert through both phase-one and
agentic modes, asserts on the investigation output.

Each mode produces an Investigation; the same expectations apply to both.
This catches regressions when the agentic implementation diverges from
the phase-one baseline.

Run: uv run pytest tests/test_investigations.py -v
"""
import json
import re
from pathlib import Path

import pytest

from src.copilot import SOCCopilot
from src.models import Alert, Investigation

from .expectations import (
    EXPECTATIONS,
    AlertExpectation,
    confidence_meets_minimum,
)


SAMPLE_ALERTS_DIR = Path("data/sample_alerts")
MODES = ["phase_one", "agentic"]


def _load_alert(filename: str) -> Alert:
    path = SAMPLE_ALERTS_DIR / filename
    with path.open() as f:
        return Alert(**json.load(f))


@pytest.fixture(scope="module")
async def investigations(
    copilot: SOCCopilot,
) -> dict[tuple[str, str], Investigation]:
    """Run every alert through every mode once. Cache results so each
    pytest run does only N_alerts * N_modes API calls total.
    Key: (alert_file, mode) -> Investigation.
    """
    results: dict[tuple[str, str], Investigation] = {}
    for alert_file in EXPECTATIONS.keys():
        alert = _load_alert(alert_file)
        results[(alert_file, "phase_one")] = await copilot.investigate(alert)
        results[(alert_file, "agentic")] = await copilot.investigate_agentic(alert)
    return results


def _cases() -> list[tuple[str, str, AlertExpectation]]:
    """Cartesian product of alerts × modes for parametrization."""
    return [
        (alert_file, mode, expected)
        for alert_file, expected in EXPECTATIONS.items()
        for mode in MODES
    ]


# --- Assertion tests, one per property, parametrized over (alert, mode) ---


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_verdict(
    alert_file: str,
    mode: str,
    expected: AlertExpectation,
    investigations: dict[tuple[str, str], Investigation],
):
    inv = investigations[(alert_file, mode)]
    if "allowed_verdicts" in expected:
        assert inv.verdict in expected["allowed_verdicts"], (
            f"{alert_file} [{mode}]: expected verdict in "
            f"{expected['allowed_verdicts']}, got '{inv.verdict}'. "
            f"Hypothesis: {inv.hypothesis[:200]}"
        )
    elif "expected_verdict" in expected:
        assert inv.verdict == expected["expected_verdict"], (
            f"{alert_file} [{mode}]: expected verdict "
            f"'{expected['expected_verdict']}', got '{inv.verdict}'. "
            f"Hypothesis: {inv.hypothesis[:200]}"
        )
    else:
        pytest.skip("No verdict expectation specified")


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_confidence(
    alert_file: str,
    mode: str,
    expected: AlertExpectation,
    investigations: dict[tuple[str, str], Investigation],
):
    if "min_confidence" not in expected:
        pytest.skip("No min_confidence specified")
    inv = investigations[(alert_file, mode)]
    assert confidence_meets_minimum(inv.confidence, expected["min_confidence"]), (
        f"{alert_file} [{mode}]: expected confidence >= "
        f"'{expected['min_confidence']}', got '{inv.confidence}'"
    )


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_required_mitre_techniques(
    alert_file: str,
    mode: str,
    expected: AlertExpectation,
    investigations: dict[tuple[str, str], Investigation],
):
    if "required_techniques" not in expected:
        pytest.skip("No required_techniques specified")
    inv = investigations[(alert_file, mode)]
    techniques_blob = " ".join(inv.attack_techniques)
    missing = [
        t for t in expected["required_techniques"]
        if t not in techniques_blob
    ]
    assert not missing, (
        f"{alert_file} [{mode}]: missing required MITRE techniques: "
        f"{missing}. Got: {inv.attack_techniques}"
    )


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_forbidden_mitre_techniques(
    alert_file: str,
    mode: str,
    expected: AlertExpectation,
    investigations: dict[tuple[str, str], Investigation],
):
    if "forbidden_techniques" not in expected:
        pytest.skip("No forbidden_techniques specified")
    inv = investigations[(alert_file, mode)]
    techniques_blob = " ".join(inv.attack_techniques)
    leaked = [
        t for t in expected["forbidden_techniques"]
        if t in techniques_blob
    ]
    assert not leaked, (
        f"{alert_file} [{mode}]: contains forbidden MITRE techniques "
        f"(possible cross-contamination): {leaked}. "
        f"Got: {inv.attack_techniques}"
    )


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_escalation_flag(
    alert_file: str,
    mode: str,
    expected: AlertExpectation,
    investigations: dict[tuple[str, str], Investigation],
):
    if "must_escalate" not in expected:
        pytest.skip("No must_escalate specified")
    inv = investigations[(alert_file, mode)]
    assert inv.escalation_recommended == expected["must_escalate"], (
        f"{alert_file} [{mode}]: expected escalation_recommended="
        f"{expected['must_escalate']}, got {inv.escalation_recommended}"
    )


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_pivot_keywords(
    alert_file: str,
    mode: str,
    expected: AlertExpectation,
    investigations: dict[tuple[str, str], Investigation],
):
    if "pivots_must_include" not in expected:
        pytest.skip("No pivots_must_include specified")
    inv = investigations[(alert_file, mode)]
    pivots_blob = " ".join(
        f"{p.action} {p.rationale}" for p in inv.suggested_pivots
    ).lower()
    missing = [
        kw for kw in expected["pivots_must_include"]
        if kw.lower() not in pivots_blob
    ]
    assert not missing, (
        f"{alert_file} [{mode}]: missing expected pivot keywords: "
        f"{missing}. Pivots: {[p.action for p in inv.suggested_pivots]}"
    )


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_evidence_count(
    alert_file: str,
    mode: str,
    expected: AlertExpectation,
    investigations: dict[tuple[str, str], Investigation],
):
    if "min_evidence_count" not in expected:
        pytest.skip("No min_evidence_count specified")
    inv = investigations[(alert_file, mode)]
    actual = len(inv.evidence)
    assert actual >= expected["min_evidence_count"], (
        f"{alert_file} [{mode}]: expected at least "
        f"{expected['min_evidence_count']} evidence entries, got {actual}"
    )


_TCODE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_associated_groups(
    alert_file: str,
    mode: str,
    expected: AlertExpectation,
    investigations: dict[tuple[str, str], Investigation],
):
    if "min_associated_groups" not in expected:
        pytest.skip("No min_associated_groups specified")
    inv = investigations[(alert_file, mode)]

    # Count invariant: enough groups surfaced from the mapped techniques
    actual = len(inv.associated_groups)
    assert actual >= expected["min_associated_groups"], (
        f"{alert_file} [{mode}]: expected at least "
        f"{expected['min_associated_groups']} associated groups, got {actual}. "
        f"Techniques: {inv.attack_techniques}"
    )

    # Grounding invariant: every group's matched_techniques must come from
    # THIS investigation's own techniques (or their parent) — catches
    # hallucinated or cross-contaminated overlap. Groups are filled by the
    # deterministic map, so this should hold by construction; assert it so a
    # future regression in the matcher can't slip through silently.
    inv_codes = {c for t in inv.attack_techniques for c in _TCODE_RE.findall(t)}
    inv_codes |= {c.split(".")[0] for c in inv_codes}  # allow parent rollup
    for gm in inv.associated_groups:
        assert gm.overlap_count == len(gm.matched_techniques) >= 1, (
            f"{alert_file} [{mode}]: group {gm.group} has inconsistent "
            f"overlap_count={gm.overlap_count} vs {gm.matched_techniques}"
        )
        stray = [c for c in gm.matched_techniques if c not in inv_codes]
        assert not stray, (
            f"{alert_file} [{mode}]: group {gm.group} matched techniques "
            f"{stray} not present in the investigation: {inv.attack_techniques}"
        )
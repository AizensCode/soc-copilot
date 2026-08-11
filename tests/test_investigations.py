"""Eval harness — runs each labeled alert through both phase-one and
agentic modes, asserts on the investigation output.

Each mode produces an Investigation; the same expectations apply to both.
This catches regressions when the agentic implementation diverges from
the phase-one baseline.

Run: uv run pytest tests/test_investigations.py -v
"""
import re

import pytest

from soc_copilot.copilot import SOCCopilot
from soc_copilot.models import Alert, Investigation

from .alert_loading import SAMPLE_ALERTS_DIR, load_alert_fixture
from .eval_checks import evaluate, is_attack
from .expectations import EXPECTATIONS, AlertExpectation

# Every test in this module drives live API calls (see the `live` marker
# in pyproject.toml): `-m "not live"` is the free suite.
pytestmark = pytest.mark.live

MODES = ["phase_one", "agentic"]


def _load_alert(filename: str) -> Alert:
    return load_alert_fixture(SAMPLE_ALERTS_DIR / filename)


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


def _assert_property(investigations, alert_file, mode, expected, name):
    """Assert one pinned property via the SHARED predicate (eval_checks.py)
    — the same one the calibration runner tallies, so a green test and a
    k/k calibration mean the same thing. Skips when the property is not
    pinned for this fixture, exactly as the old per-property tests did."""
    check = evaluate(investigations[(alert_file, mode)], expected).get(name)
    if check is None:
        pytest.skip(f"No {name} expectation specified")
    assert check.ok, f"{alert_file} [{mode}]: {check.detail}"


# --- Assertion tests, one per property, parametrized over (alert, mode) ---


# The single-property tests are thin wrappers over the shared predicate in
# eval_checks.py: same skip-when-unpinned behavior, same assertion, one per
# property so a live failure still names the property. The predicate itself
# is unit-tested API-free (tests/test_eval_checks.py); the calibration
# runner tallies the exact same function, so its pass-rates == these tests.


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_verdict(alert_file, mode, expected, investigations):
    _assert_property(investigations, alert_file, mode, expected, "verdict")


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_confidence(alert_file, mode, expected, investigations):
    _assert_property(investigations, alert_file, mode, expected, "confidence")


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_required_mitre_techniques(alert_file, mode, expected, investigations):
    _assert_property(investigations, alert_file, mode, expected, "required_techniques")


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_any_of_mitre_techniques(alert_file, mode, expected, investigations):
    _assert_property(investigations, alert_file, mode, expected, "any_of_techniques")


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_forbidden_mitre_techniques(alert_file, mode, expected, investigations):
    _assert_property(investigations, alert_file, mode, expected, "forbidden_techniques")


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_escalation_flag(alert_file, mode, expected, investigations):
    _assert_property(investigations, alert_file, mode, expected, "escalation")


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_pivot_keywords(alert_file, mode, expected, investigations):
    _assert_property(investigations, alert_file, mode, expected, "pivots")


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_evidence_count(alert_file, mode, expected, investigations):
    _assert_property(investigations, alert_file, mode, expected, "evidence_count")


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

    # Count invariant, via the shared predicate the runner also tallies.
    _assert_property(investigations, alert_file, mode, expected, "associated_groups")

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


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_sigma_matches(
    alert_file: str,
    mode: str,
    expected: AlertExpectation,
    investigations: dict[tuple[str, str], Investigation],
):
    if "min_sigma_matches" not in expected:
        pytest.skip("No min_sigma_matches specified")
    inv = investigations[(alert_file, mode)]

    # Count invariant, via the shared predicate the runner also tallies.
    _assert_property(investigations, alert_file, mode, expected, "sigma_matches")

    # Grounding invariant: every cited rule must be one of the committed
    # curated rules. Filled deterministically, so this holds by
    # construction; assert it so a regression can't slip through silently.
    from soc_copilot.sigma import load_rules

    known_ids = {r["id"] for r in load_rules()}
    stray = [m.rule_id for m in inv.sigma_matches if m.rule_id not in known_ids]
    assert not stray, (
        f"{alert_file} [{mode}]: sigma_matches cite unknown rule ids: {stray}"
    )


# --- Autonomy safety gate ---------------------------------------------------


def _attack_cases() -> list[tuple[str, str]]:
    """(alert, mode) pairs the harness labels as attacks — the same
    derivation the autoclose_safe calibration property uses (is_attack), so
    the two never disagree about which fixtures the gate must refuse."""
    return [
        (alert_file, mode)
        for alert_file, expected in EXPECTATIONS.items()
        if is_attack(expected)
        for mode in MODES
    ]


@pytest.mark.parametrize("alert_file,mode", _attack_cases())
async def test_attack_labeled_alerts_never_qualify_for_auto_close(
    alert_file: str,
    mode: str,
    investigations: dict[tuple[str, str], Investigation],
):
    """The composition --watch --auto-close actually runs is real model
    output × closure policy — and until now it had no eval coverage.
    Whatever the model said about an attack-labeled fixture, the policy
    must refuse autonomous closure; this test fails if a policy change
    (or a model regression the verdict tests happen to miss) ever lets
    an attack self-close."""
    from soc_copilot.closure import should_auto_close

    inv = investigations[(alert_file, mode)]
    close, reason = should_auto_close(inv)
    assert not close, (
        f"{alert_file} [{mode}] qualified for autonomous closure "
        f"({reason}) — an attack-labeled alert must always reach a human"
    )


@pytest.mark.parametrize("alert_file,mode,expected", _cases())
async def test_injection_flags(alert_file, mode, expected, investigations):
    _assert_property(investigations, alert_file, mode, expected, "injection_flags")

"""Unit tests for tiered model routing (API-free, network-free).

The promotion gate is the whole safety story: the cheap tier may finalize
ONLY a clean high-confidence false positive on a below-critical alert;
everything else must reach the strong model. Each gate gets a case, and
the orchestration is exercised against a fake Anthropic client so the
per-tier cost accounting and the single-record contract are pinned
without spending anything.

    uv run pytest tests/test_routing.py -v
"""
import json
from datetime import datetime, timezone
from types import SimpleNamespace

from soc_copilot.config import settings
from soc_copilot.copilot import SOCCopilot
from soc_copilot.history import AlertHistoryStore
from soc_copilot.models import Alert, Correlation, InjectionFlag, Investigation
from soc_copilot.routing import should_promote

_T = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _alert(severity: str = "medium") -> Alert:
    return Alert(
        alert_id="A1", timestamp=_T, source="siem", severity=severity,
        title="t", raw_log={}, indicators={},
    )


def _inv(
    verdict: str = "false_positive",
    confidence: str = "high",
    escalate: bool = False,
    injection: bool = False,
    campaign: bool = False,
) -> Investigation:
    return Investigation(
        alert_id="A1", verdict=verdict, confidence=confidence,
        hypothesis="h", escalation_recommended=escalate,
        injection_flags=(
            [InjectionFlag(location="raw_log", pattern="x", excerpt="y")]
            if injection else []
        ),
        correlation=Correlation(
            is_campaign=campaign, window_hours=72, summary="s"
        ) if campaign else None,
    )


# --- the promotion gate ------------------------------------------------------


def test_clean_high_confidence_fp_finalizes_at_the_cheap_tier():
    promote, reason = should_promote(_inv(), _alert())
    assert promote is False and "authoritative" in reason


def test_true_positive_is_always_promoted():
    promote, reason = should_promote(_inv(verdict="true_positive"), _alert())
    assert promote and "true_positive" in reason


def test_inconclusive_is_always_promoted():
    """A hedge is exactly where the strong model earns its cost."""
    promote, _ = should_promote(_inv(verdict="inconclusive"), _alert())
    assert promote


def test_medium_confidence_fp_is_promoted():
    promote, reason = should_promote(_inv(confidence="medium"), _alert())
    assert promote and "confidence" in reason


def test_escalation_is_promoted_even_if_labeled_false_positive():
    promote, _ = should_promote(_inv(escalate=True), _alert())
    assert promote


def test_injection_flags_force_the_strong_model():
    promote, reason = should_promote(_inv(injection=True), _alert())
    assert promote and "injection" in reason


def test_campaign_correlation_is_promoted():
    promote, reason = should_promote(_inv(campaign=True), _alert())
    assert promote and "campaign" in reason


def test_critical_severity_is_promoted_regardless_of_a_clean_verdict():
    """The cheap model never gets to close the book on a critical, even
    when it is confident the alert is benign."""
    promote, reason = should_promote(_inv(), _alert(severity="critical"))
    assert promote and "critical" in reason


def test_the_gate_matches_the_auto_close_bar_it_mirrors():
    """A result the cheap tier finalizes is, by construction, one the
    closure policy would also be willing to auto-close — the intended
    symmetry, INCLUDING closure's overturned-precedent gate, which
    should_promote reuses so the finalize bar is a true superset."""
    from soc_copilot.closure import should_auto_close

    clean = _inv()
    assert should_promote(clean, _alert())[0] is False
    assert should_auto_close(clean)[0] is True


def _inv_with_overturned_precedent() -> Investigation:
    """A clean cheap FP/high whose prior sighting on a shared indicator was
    overturned by an analyst — a documented miss on this indicator."""
    from soc_copilot.models import PriorSighting

    inv = _inv()
    inv.prior_sightings = [
        PriorSighting(
            alert_id="OLD-1", timestamp=_T, verdict="false_positive",
            confidence="high", title="same indicator, last week",
            matched_iocs=["1.2.3.4"],
            human_verdict="true_positive",   # analyst OVERTURNED the copilot
            human_summary="was a real compromise",
        )
    ]
    return inv


def test_overturned_precedent_forces_promotion_even_on_a_clean_cheap_verdict():
    """The review-caught gap: the cheap model may confidently call an alert
    a benign FP, but if an analyst has overturned the copilot on an
    indicator this alert shares, the strong model must re-examine it — the
    exact case closure refuses to act on autonomously."""
    from soc_copilot.closure import should_auto_close

    inv = _inv_with_overturned_precedent()
    promote, reason = should_promote(inv, _alert())
    assert promote and "overturned" in reason
    # And the mirror holds: closure also refuses to act on this object.
    assert should_auto_close(inv)[0] is False


# --- orchestration against a fake client (no API, no network) ----------------


class _RecordingMessages:
    """A scripted Anthropic client that records which model each call used,
    so the cheap→strong routing can be asserted without spending anything."""

    def __init__(self, scripted):
        self._scripted = list(scripted)   # list of (verdict, confidence, (in,out))
        self.models: list[str] = []

    async def create(self, *, model, **kwargs):
        self.models.append(model)
        verdict, confidence, tokens = self._scripted.pop(0)
        text = json.dumps({
            "alert_id": "A1", "verdict": verdict, "confidence": confidence,
            "hypothesis": "h", "attack_techniques": [], "suggested_pivots": [],
            "escalation_recommended": False, "escalation_draft": None,
            "reasoning_transcript": "r",
        })
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=text)],
            stop_reason="end_turn",
            usage=SimpleNamespace(input_tokens=tokens[0], output_tokens=tokens[1]),
        )


def _copilot(tmp_path, scripted) -> tuple[SOCCopilot, _RecordingMessages]:
    copilot = SOCCopilot(
        history_store=AlertHistoryStore(tmp_path / "investigations.jsonl")
    )
    fake = _RecordingMessages(scripted)
    copilot.client = SimpleNamespace(messages=fake)
    return copilot, fake


async def test_clean_fp_runs_only_the_cheap_model_and_records_once(tmp_path):
    copilot, fake = _copilot(tmp_path, [("false_positive", "high", (1000, 200))])
    inv = await copilot.investigate_tiered(_alert())

    assert fake.models == [settings.TIER_CHEAP_MODEL]   # strong never called
    assert inv.telemetry.model == settings.TIER_CHEAP_MODEL
    assert inv.telemetry.routing and "finalized" in inv.telemetry.routing
    assert inv.telemetry.cost_usd > 0
    # Exactly one investigation on record — the finalized verdict.
    assert len(copilot.history.path.read_text().splitlines()) == 1


async def test_promotion_runs_both_tiers_and_sums_the_cost(tmp_path):
    copilot, fake = _copilot(tmp_path, [
        ("true_positive", "high", (1000, 200)),   # cheap: not clean → promote
        ("true_positive", "high", (2000, 400)),   # strong: authoritative
    ])
    inv = await copilot.investigate_tiered(_alert())

    assert fake.models == [settings.TIER_CHEAP_MODEL, settings.MODEL]
    assert inv.telemetry.model == settings.MODEL            # strong is authoritative
    assert "promoted" in inv.telemetry.routing
    # Cost and tokens are the SUM across both tiers — a promoted alert paid
    # for both, and the recorded number must say so.
    from soc_copilot.pricing import estimate_cost
    expected = round(
        estimate_cost(settings.TIER_CHEAP_MODEL, 1000, 200)
        + estimate_cost(settings.MODEL, 2000, 400), 6
    )
    assert inv.telemetry.cost_usd == expected
    assert inv.telemetry.input_tokens == 3000
    assert inv.telemetry.output_tokens == 600
    assert inv.telemetry.api_calls == 2
    # Still one record: the final verdict, not each tier.
    assert len(copilot.history.path.read_text().splitlines()) == 1
    assert inv.verdict == "true_positive"


async def test_critical_alert_is_promoted_even_on_a_clean_cheap_verdict(tmp_path):
    copilot, fake = _copilot(tmp_path, [
        ("false_positive", "high", (1000, 200)),   # cheap says clean...
        ("false_positive", "high", (2000, 400)),   # ...but critical → strong anyway
    ])
    inv = await copilot.investigate_tiered(_alert(severity="critical"))
    assert fake.models == [settings.TIER_CHEAP_MODEL, settings.MODEL]
    assert "critical" in inv.telemetry.routing

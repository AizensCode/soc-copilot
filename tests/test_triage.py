"""Unit tests for watch-queue priority ordering (no API, no network).

The scorer is a pure function of already-computed signals, so the
ordering the watch loop applies is validated without a live copilot.
The load-bearing case is the ruling-aware one: an analyst ruling
outranks the copilot's recorded verdict here exactly as it does
everywhere else.

    uv run pytest tests/test_triage.py -v
"""
from datetime import datetime, timezone

from src.models import Alert, Correlation, PriorSighting, RelatedAlert
from src.triage import priority_score

_T = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _alert(severity: str = "high") -> Alert:
    return Alert(
        alert_id="A", timestamp=_T, source="edr", severity=severity,
        title="t", raw_log={}, indicators={},
    )


def _sighting(verdict: str, human_verdict: str | None = None) -> PriorSighting:
    return PriorSighting(
        alert_id="OLD-1", timestamp=_T, verdict=verdict, confidence="high",
        title="prior", matched_iocs=["9.9.9.9"], human_verdict=human_verdict,
    )


def _corr(is_campaign: bool = False, related: int = 0) -> Correlation:
    return Correlation(
        is_campaign=is_campaign, window_hours=72,
        related_alerts=[
            RelatedAlert(alert_id=f"R{i}", timestamp=_T, verdict="true_positive",
                         signals=["shared_ioc:9.9.9.9"])
            for i in range(related)
        ],
        summary="s",
    )


def _score(alert, priors=None, corr=None) -> int:
    return priority_score(alert, priors or [], corr)[0]


# --- severity base -----------------------------------------------------------


def test_severity_orders_the_base_score():
    assert (
        _score(_alert("critical"))
        > _score(_alert("high"))
        > _score(_alert("medium"))
        > _score(_alert("low"))
    )


# --- memory signals ----------------------------------------------------------


def test_campaign_outranks_raw_severity():
    """A medium campaign should be investigated before a critical
    isolated alert — the coordination is the story."""
    critical_isolated = _score(_alert("critical"), corr=_corr())
    medium_campaign = _score(_alert("medium"), corr=_corr(is_campaign=True))
    assert medium_campaign > critical_isolated


def test_recurring_true_positive_bumps_over_plain_severity():
    plain = _score(_alert("high"))
    recurring = _score(_alert("high"), priors=[_sighting("true_positive")])
    assert recurring > plain


def test_related_below_threshold_is_a_smaller_bump_than_campaign():
    high = _alert("high")
    related = _score(high, corr=_corr(related=1))
    campaign = _score(high, corr=_corr(is_campaign=True))
    assert _score(high) < related < campaign


# --- the ruling-aware case ---------------------------------------------------


def test_overturned_prior_does_not_count_as_recurring_true_positive():
    """Copilot said true_positive, a human ruled false_positive: this is
    a known false alarm on the indicator, so it must NOT jump the queue."""
    overturned = [_sighting("true_positive", "false_positive")]
    assert _score(_alert("high"), priors=overturned) == _score(_alert("high"))


def test_confirmed_true_positive_ruling_counts_even_if_copilot_hedged():
    """Copilot said inconclusive, a human ruled true_positive: the ruling
    is ground truth, so this recurs a real true positive and bumps."""
    confirmed = [_sighting("inconclusive", "true_positive")]
    assert _score(_alert("high"), priors=confirmed) > _score(_alert("high"))


# --- the reason string -------------------------------------------------------


def test_reason_names_every_active_signal():
    _, reason = priority_score(
        _alert("high"),
        [_sighting("true_positive")],
        _corr(is_campaign=True),
    )
    assert "severity=high" in reason
    assert "campaign-correlated" in reason
    assert "recurs a true positive (OLD-1)" in reason


def test_prioritize_reorders_a_real_queue_from_the_store(tmp_path):
    """Integration: _prioritize reads priors/correlation from a real
    store, sorts, and yields the (doc_id, alert, reason) the watch loop
    consumes. A recurring-true-positive alert must jump ahead of a
    higher-severity one with no history."""
    from types import SimpleNamespace

    from src.history import AlertHistoryStore
    from src.main import _prioritize
    from src.models import Investigation

    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    # A past true positive on IP 5.5.5.5, ruled by an analyst.
    past = Alert(
        alert_id="OLD-TP", timestamp=_T, source="edr", severity="high",
        title="old", raw_log={}, indicators={"ips": ["5.5.5.5"]},
    )
    store.record(past, Investigation(
        alert_id="OLD-TP", verdict="true_positive", confidence="high",
        hypothesis="h", escalation_recommended=True,
    ))
    store.record_disposition("OLD-TP", "true_positive", "thehive:case-1")

    recurring = Alert(
        alert_id="NEW-RECUR", timestamp=_T, source="edr", severity="medium",
        title="recurs", raw_log={}, indicators={"ips": ["5.5.5.5"]},
    )
    critical_fresh = Alert(
        alert_id="NEW-CRIT", timestamp=_T, source="edr", severity="critical",
        title="fresh", raw_log={}, indicators={"ips": ["1.1.1.1"]},
    )
    copilot = SimpleNamespace(history=store)
    fresh = [("doc-crit", critical_fresh), ("doc-recur", recurring)]

    ordered = _prioritize(copilot, fresh)
    assert [doc_id for doc_id, _, _ in ordered] == ["doc-recur", "doc-crit"]
    assert "recurs a true positive" in ordered[0][2]


def test_full_ordering_matches_a_human_lead():
    """A representative queue sorts campaign > recurring-TP > plain-high
    > low, which is the order a lead would work them."""
    items = [
        ("low", [], _corr()),
        ("high", [_sighting("true_positive")], _corr()),
        ("medium", [], _corr(is_campaign=True)),
        ("high", [], _corr()),
    ]
    scored = sorted(
        items,
        key=lambda it: priority_score(_alert(it[0]), it[1], it[2])[0],
        reverse=True,
    )
    labels = [
        "campaign" if it[2].is_campaign
        else "recurring" if it[1]
        else it[0]
        for it in scored
    ]
    assert labels == ["campaign", "recurring", "high", "low"]

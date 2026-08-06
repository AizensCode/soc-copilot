"""Unit tests for the accuracy scorecard (no API, no network).

    uv run pytest tests/test_scorecard.py -v
"""
from datetime import datetime, timezone

from src.history import AlertHistoryStore
from src.models import Alert, Investigation
from src.scorecard import build_scorecard, render_scorecard

_T = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _store(tmp_path) -> AlertHistoryStore:
    return AlertHistoryStore(tmp_path / "investigations.jsonl")


def _record(store, alert_id, verdict, ip="9.9.9.9", title="t"):
    store.record(
        Alert(
            alert_id=alert_id, timestamp=_T, source="edr", severity="high",
            title=title, raw_log={}, indicators={"ips": [ip]},
        ),
        Investigation(
            alert_id=alert_id, verdict=verdict, confidence="high",
            hypothesis="h", escalation_recommended=True,
        ),
    )


def test_empty_store_has_no_data_not_a_perfect_record(tmp_path):
    card = build_scorecard(_store(tmp_path))
    assert card.investigated == 0
    assert card.agreement_rate is None          # no data != 100%
    assert "no accuracy data yet" in render_scorecard(card)


def test_agreement_and_disagreement_are_counted(tmp_path):
    store = _store(tmp_path)
    _record(store, "A1", "true_positive", ip="1.1.1.1")
    _record(store, "A2", "true_positive", ip="2.2.2.2")
    _record(store, "A3", "inconclusive", ip="3.3.3.3")   # never ruled
    store.record_disposition("A1", "true_positive", "thehive:case-1")
    store.record_disposition("A2", "false_positive", "thehive:alert-status",
                             "Sanctioned test.")

    card = build_scorecard(store)
    assert card.investigated == 3
    assert card.ruled == 2
    assert card.agreements == 1
    assert card.agreement_rate == 0.5
    [dis] = card.disagreements
    assert (dis.alert_id, dis.copilot_verdict, dis.human_verdict) == (
        "A2", "true_positive", "false_positive"
    )


def test_copilots_latest_verdict_is_the_one_judged(tmp_path):
    """An alert investigated twice is scored on the copilot's final
    opinion — the one that stood when the human ruled."""
    store = _store(tmp_path)
    _record(store, "A1", "inconclusive")
    _record(store, "A1", "false_positive")     # later, better-grounded run
    store.record_disposition("A1", "false_positive", "thehive:alert-status")

    card = build_scorecard(store)
    assert card.investigated == 1
    assert card.agreements == 1


def test_ruling_without_local_record_is_ignored(tmp_path):
    store = _store(tmp_path)
    store.record_disposition("GHOST", "false_positive", "thehive:alert-status")
    card = build_scorecard(store)
    assert card.ruled == 0 and card.agreement_rate is None


def test_render_puts_disagreements_and_notes_up_front(tmp_path):
    store = _store(tmp_path)
    _record(store, "A1", "true_positive", title="Beaconing to external host")
    store.record_disposition("A1", "false_positive", "thehive:case-3",
                             "Purple team exercise.")
    text = render_scorecard(build_scorecard(store))
    assert "0/1 (0%)" in text
    assert "copilot said true_positive (high), analyst ruled false_positive" in text
    assert 'analyst note: "Purple team exercise."' in text
    assert "Beaconing to external host" in text

"""Unit tests for the alert-history store (cross-alert memory).

These are deterministic and make NO API calls — the store is pure Python, so
its logic is validated without touching Anthropic. Run:

    uv run pytest tests/test_history.py -v
"""
from datetime import datetime, timezone

from src.history import AlertHistoryStore, alert_iocs
from src.models import Alert, Investigation


def _alert(alert_id: str, indicators: dict, when: datetime, title: str = "t") -> Alert:
    return Alert(
        alert_id=alert_id,
        timestamp=when,
        source="edr",
        severity="high",
        title=title,
        raw_log={},
        indicators=indicators,
    )


def _inv(alert_id: str, verdict: str = "true_positive") -> Investigation:
    return Investigation(
        alert_id=alert_id,
        verdict=verdict,
        confidence="high",
        hypothesis="h",
        escalation_recommended=True,
    )


def _store(tmp_path) -> AlertHistoryStore:
    return AlertHistoryStore(tmp_path / "investigations.jsonl")


def test_empty_store_has_no_sightings(tmp_path):
    store = _store(tmp_path)
    alert = _alert("A2", {"ips": ["1.1.1.1"]}, datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert store.prior_sightings(alert) == []


def test_shared_ioc_surfaces_prior(tmp_path):
    store = _store(tmp_path)
    past = _alert("A1", {"ips": ["1.1.1.1"]}, datetime(2026, 1, 1, tzinfo=timezone.utc),
                  title="old brute force")
    store.record(past, _inv("A1"))

    now = _alert("A2", {"ips": ["1.1.1.1"]}, datetime(2026, 2, 1, tzinfo=timezone.utc))
    sightings = store.prior_sightings(now)
    assert len(sightings) == 1
    assert sightings[0].alert_id == "A1"
    assert sightings[0].verdict == "true_positive"
    assert sightings[0].title == "old brute force"
    assert sightings[0].matched_iocs == ["1.1.1.1"]


def test_disjoint_iocs_no_match(tmp_path):
    store = _store(tmp_path)
    store.record(_alert("A1", {"ips": ["1.1.1.1"]}, datetime(2026, 1, 1, tzinfo=timezone.utc)),
                 _inv("A1"))
    now = _alert("A2", {"ips": ["9.9.9.9"]}, datetime(2026, 2, 1, tzinfo=timezone.utc))
    assert store.prior_sightings(now) == []


def test_alert_does_not_match_itself(tmp_path):
    store = _store(tmp_path)
    alert = _alert("A1", {"ips": ["1.1.1.1"]}, datetime(2026, 1, 1, tzinfo=timezone.utc))
    store.record(alert, _inv("A1"))
    # Re-investigating the same alert_id must not surface itself
    assert store.prior_sightings(alert) == []


def test_multiple_shared_iocs_collected_and_deduped(tmp_path):
    store = _store(tmp_path)
    past = _alert("A1", {"ips": ["1.1.1.1"], "domains": ["evil.test"]},
                  datetime(2026, 1, 1, tzinfo=timezone.utc))
    store.record(past, _inv("A1"))

    now = _alert("A2", {"ips": ["1.1.1.1"], "domains": ["evil.test"]},
                 datetime(2026, 2, 1, tzinfo=timezone.utc))
    sightings = store.prior_sightings(now)
    # One prior alert, even though two indicators overlap
    assert len(sightings) == 1
    assert sightings[0].matched_iocs == ["1.1.1.1", "evil.test"]


def test_most_recent_first(tmp_path):
    store = _store(tmp_path)
    store.record(_alert("OLD", {"ips": ["1.1.1.1"]}, datetime(2026, 1, 1, tzinfo=timezone.utc)),
                 _inv("OLD"))
    store.record(_alert("NEW", {"ips": ["1.1.1.1"]}, datetime(2026, 3, 1, tzinfo=timezone.utc)),
                 _inv("NEW"))
    now = _alert("A3", {"ips": ["1.1.1.1"]}, datetime(2026, 4, 1, tzinfo=timezone.utc))
    ids = [s.alert_id for s in store.prior_sightings(now)]
    assert ids == ["NEW", "OLD"]


def test_alert_without_indicators_has_no_sightings(tmp_path):
    store = _store(tmp_path)
    store.record(_alert("A1", {"ips": ["1.1.1.1"]}, datetime(2026, 1, 1, tzinfo=timezone.utc)),
                 _inv("A1"))
    now = _alert("A2", {}, datetime(2026, 2, 1, tzinfo=timezone.utc))
    assert store.prior_sightings(now) == []


def test_alert_iocs_flattens_and_dedups():
    alert = _alert(
        "A1",
        {"ips": ["1.1.1.1", "1.1.1.1"], "users": ["root"], "hashes": []},
        datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert alert_iocs(alert) == ["1.1.1.1", "root"]

"""Unit tests for the alert-history store (cross-alert memory).

These are deterministic and make NO API calls — the store is pure Python, so
its logic is validated without touching Anthropic. Run:

    uv run pytest tests/test_history.py -v
"""
from datetime import datetime, timedelta, timezone

from src.history import AlertHistoryStore, alert_iocs
from src.models import Alert, Investigation


def _alert(
    alert_id: str,
    indicators: dict,
    when: datetime,
    title: str = "t",
    host: str | None = None,
) -> Alert:
    return Alert(
        alert_id=alert_id,
        timestamp=when,
        source="edr",
        severity="high",
        title=title,
        raw_log={"host": host} if host else {},
        indicators=indicators,
    )


def _inv(
    alert_id: str,
    verdict: str = "true_positive",
    techniques: list[str] | None = None,
) -> Investigation:
    return Investigation(
        alert_id=alert_id,
        verdict=verdict,
        confidence="high",
        hypothesis="h",
        attack_techniques=techniques or [],
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


# --- correlation / campaign detection --------------------------------------

_T = datetime(2026, 4, 19, 12, 0, tzinfo=timezone.utc)


def test_correlation_single_alert_is_not_a_campaign(tmp_path):
    store = _store(tmp_path)
    alert = _alert("A1", {"ips": ["10.0.0.1"]}, _T)
    corr = store.correlate(alert, _inv("A1"))
    assert corr.is_campaign is False
    assert corr.related_alerts == []
    assert "No related" in corr.summary


def test_correlation_related_via_same_24(tmp_path):
    store = _store(tmp_path)
    store.record(
        _alert("A1", {"ips": ["185.220.101.10"]}, _T - timedelta(hours=2)),
        _inv("A1"),
    )
    now = _alert("A2", {"ips": ["185.220.101.47"]}, _T)  # same /24, different IP
    corr = store.correlate(now, _inv("A2"))
    assert len(corr.related_alerts) == 1
    assert any(s.startswith("related_ip:") for s in corr.related_alerts[0].signals)


def test_correlation_related_via_shared_host(tmp_path):
    store = _store(tmp_path)
    store.record(
        _alert("A1", {}, _T - timedelta(hours=1), host="prod-web-02.internal"),
        _inv("A1"),
    )
    now = _alert("A2", {}, _T, host="prod-web-02.internal")
    corr = store.correlate(now, _inv("A2"))
    assert len(corr.related_alerts) == 1
    assert "shared_host:prod-web-02.internal" in corr.related_alerts[0].signals


def test_correlation_shared_technique_alone_does_not_relate(tmp_path):
    # Two phishing alerts with no shared infra/target must NOT correlate,
    # even though they share T1566 — otherwise every phish looks like a campaign.
    store = _store(tmp_path)
    store.record(
        _alert("A1", {"domains": ["a.test"]}, _T - timedelta(hours=1)),
        _inv("A1", techniques=["T1566.001 - Spearphishing Attachment"]),
    )
    now = _alert("A2", {"domains": ["b.test"]}, _T)
    corr = store.correlate(now, _inv("A2", techniques=["T1566.002 - Spearphishing Link"]))
    assert corr.related_alerts == []


def test_correlation_technique_corroborates_infra_link(tmp_path):
    store = _store(tmp_path)
    store.record(
        _alert("A1", {"ips": ["185.220.101.10"]}, _T - timedelta(hours=1)),
        _inv("A1", techniques=["T1110.001 - Password Guessing"]),
    )
    now = _alert("A2", {"ips": ["185.220.101.47"]}, _T)  # same /24
    corr = store.correlate(now, _inv("A2", techniques=["T1110.003 - Password Spraying"]))
    signals = corr.related_alerts[0].signals
    assert any(s.startswith("related_ip:") for s in signals)
    assert "shared_technique:T1110" in signals


def test_correlation_outside_window_excluded(tmp_path):
    store = _store(tmp_path)
    store.record(
        _alert("A1", {"ips": ["10.0.0.1"]}, _T - timedelta(hours=100)),
        _inv("A1"),
    )
    now = _alert("A2", {"ips": ["10.0.0.1"]}, _T)
    corr = store.correlate(now, _inv("A2"), window_hours=72)
    assert corr.related_alerts == []


def test_correlation_campaign_threshold(tmp_path):
    store = _store(tmp_path)
    # Two prior alerts sharing the same host within the window -> campaign
    for i in range(2):
        store.record(
            _alert(f"A{i}", {}, _T - timedelta(hours=i + 1), host="db-01.internal"),
            _inv(f"A{i}"),
        )
    now = _alert("A9", {}, _T, host="db-01.internal")
    corr = store.correlate(now, _inv("A9"))
    assert corr.is_campaign is True
    assert len(corr.related_alerts) == 2
    assert "campaign" in corr.summary.lower()


def test_correlation_excludes_self(tmp_path):
    store = _store(tmp_path)
    alert = _alert("A1", {"ips": ["10.0.0.1"]}, _T, host="h1")
    store.record(alert, _inv("A1"))
    corr = store.correlate(alert, _inv("A1"))
    assert corr.related_alerts == []

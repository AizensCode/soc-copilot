"""Unit tests for the SOC morning digest (no API, no network).

The digest data is a pure function of the store; these tests cover the
windowing semantics (investigated_at, not the alert's own timestamp),
latest-per-alert dedupe, the ruling joins, and the quiet-day path. The
LLM only narrates — its mechanics are tested against a fake client.

    uv run pytest tests/test_digest.py -v
"""
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from soc_copilot.digest import build_digest_data, render_quiet, write_briefing
from soc_copilot.history import AlertHistoryStore
from soc_copilot.models import Alert, Correlation, Investigation

_T = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _store(tmp_path) -> AlertHistoryStore:
    return AlertHistoryStore(tmp_path / "investigations.jsonl")


def _alert(alert_id: str, ip: str = "9.9.9.9") -> Alert:
    return Alert(
        alert_id=alert_id, timestamp=_T, source="edr", severity="high",
        title=f"alert {alert_id}", raw_log={}, indicators={"ips": [ip]},
    )


def _inv(
    alert_id: str,
    verdict: str = "true_positive",
    escalate: bool = False,
    campaign: bool = False,
) -> Investigation:
    return Investigation(
        alert_id=alert_id, verdict=verdict, confidence="high",
        hypothesis=f"hypothesis for {alert_id}",
        escalation_recommended=escalate,
        correlation=Correlation(
            is_campaign=campaign, window_hours=72, related_alerts=[],
            summary="s",
        ),
    )


def test_quiet_window_and_deterministic_rendering(tmp_path):
    data = build_digest_data(_store(tmp_path), since_hours=24)
    assert data["quiet"] is True
    assert data["counts"]["total"] == 0
    assert "quiet" in render_quiet(data)


def test_windowing_is_on_investigated_at_not_alert_timestamp(tmp_path):
    """An April alert investigated overnight belongs in today's digest;
    a record investigated last week does not, whatever its alert time."""
    store = _store(tmp_path)
    store.record(_alert("FRESH"), _inv("FRESH"))  # investigated_at = now

    week_old = {
        "alert_id": "STALE",
        "timestamp": _T.isoformat(),
        "investigated_at": (
            datetime.now(timezone.utc) - timedelta(days=7)
        ).isoformat(),
        "title": "old work", "verdict": "false_positive",
        "confidence": "high", "host": None, "iocs": [],
        "attack_techniques": [],
    }
    pre_upgrade = {
        "alert_id": "ANCIENT",
        "timestamp": _T.isoformat(),
        "title": "no investigated_at at all", "verdict": "inconclusive",
        "confidence": "low", "host": None, "iocs": [],
        "attack_techniques": [],
    }
    with store.path.open("a") as f:
        f.write(json.dumps(week_old) + "\n")
        f.write(json.dumps(pre_upgrade) + "\n")

    data = build_digest_data(store, since_hours=24)
    assert [e["alert_id"] for e in data["investigated"]] == ["FRESH"]
    # ...but the all-time accuracy record still counts every alert.
    assert data["accuracy_record"]["alerts_investigated_all_time"] == 3


def test_latest_verdict_wins_and_counts_add_up(tmp_path):
    store = _store(tmp_path)
    store.record(_alert("A1"), _inv("A1", "inconclusive"))
    store.record(_alert("A1"), _inv("A1", "false_positive"))
    store.record(_alert("A2"), _inv("A2", "true_positive", escalate=True))
    store.record(_alert("A3"), _inv("A3", "true_positive", campaign=True))

    data = build_digest_data(store, since_hours=24)
    assert data["counts"]["total"] == 3          # A1 deduped
    assert data["counts"]["false_positive"] == 1
    assert data["counts"]["true_positive"] == 2
    assert data["counts"]["escalations"] == 1
    assert data["counts"]["campaigns"] == 1
    by_id = {e["alert_id"]: e for e in data["investigated"]}
    assert by_id["A1"]["verdict"] == "false_positive"
    assert by_id["A2"]["escalation_recommended"] is True
    assert by_id["A3"]["is_campaign"] is True


def test_new_rulings_join_the_copilot_verdict(tmp_path):
    store = _store(tmp_path)
    store.record(_alert("A1"), _inv("A1", "true_positive"))
    store.record_disposition("A1", "false_positive", "thehive:case-1", "Pentest.")
    store.record_disposition("GHOST", "true_positive", "thehive:case-2")

    data = build_digest_data(store, since_hours=24)
    by_id = {r["alert_id"]: r for r in data["new_rulings"]}
    assert by_id["A1"]["agrees"] is False
    assert by_id["A1"]["copilot_verdict"] == "true_positive"
    assert by_id["GHOST"]["note"] == "no local investigation on record"
    # The ruled investigation itself carries the ruling too.
    [entry] = data["investigated"]
    assert entry["analyst_ruled"] == "false_positive"
    # And the store-wide disagreement list picks it up.
    [dis] = data["standing_disagreements"]
    assert (dis["alert_id"], dis["analyst_note"]) == ("A1", "Pentest.")


def test_rulings_synced_before_the_window_are_not_news(tmp_path):
    store = _store(tmp_path)
    store.record(_alert("A1"), _inv("A1"))
    store.record_disposition("A1", "true_positive", "thehive:case-1")
    # Rewrite the ruling's sync stamp to last week.
    line = json.loads(store.dispositions_path.read_text())
    line["recorded_at"] = (
        datetime.now(timezone.utc) - timedelta(days=7)
    ).isoformat()
    store.dispositions_path.write_text(json.dumps(line) + "\n")

    data = build_digest_data(store, since_hours=24)
    assert data["new_rulings"] == []
    # Not news, but still the standing ruling on the investigation.
    assert data["investigated"][0]["analyst_ruled"] == "true_positive"
    assert data["quiet"] is False  # the investigation is still in-window


class _FakeClient:
    def __init__(self):
        self.requests: list[dict] = []

        outer = self

        class _Messages:
            async def create(self, **kwargs):
                outer.requests.append(kwargs)
                return SimpleNamespace(
                    content=[
                        SimpleNamespace(type="thinking", thinking="…"),
                        SimpleNamespace(type="text", text="Briefing."),
                    ]
                )

        self.messages = _Messages()


async def test_briefing_narrates_only_the_assembled_data(tmp_path):
    store = _store(tmp_path)
    store.record(_alert("A1"), _inv("A1"))
    data = build_digest_data(store, since_hours=24)

    client = _FakeClient()
    assert await write_briefing(data, client=client) == "Briefing."
    [request] = client.requests
    sent = request["messages"][0]["content"]
    assert json.dumps(data, indent=2) in sent  # the data, verbatim


def test_auto_closed_alert_is_flagged_and_counted(tmp_path):
    """The queue must be able to tell 'the desk finished this by itself'
    from 'waiting on a human' — a standing closure flags its entry and
    carries the policy reason for the narration."""
    store = _store(tmp_path)
    store.record(_alert("AC"), _inv("AC", verdict="false_positive"))
    store.record_closure("AC", "high-confidence false positive")
    store.record(_alert("WAITING", ip="8.8.8.8"), _inv("WAITING"))

    data = build_digest_data(store, since_hours=24)
    by_id = {e["alert_id"]: e for e in data["investigated"]}
    assert by_id["AC"]["auto_closed"] is True
    assert by_id["AC"]["closure_reason"] == "high-confidence false positive"
    assert by_id["WAITING"]["auto_closed"] is False
    assert "closure_reason" not in by_id["WAITING"]
    assert data["counts"]["auto_closed"] == 1


def test_superseded_closure_is_not_presented_as_closed(tmp_path):
    """A closure a human later overrode is human work, not automation —
    the digest reuses the scorecard's standing-closure judgment, so the
    entry must NOT read as closed."""
    store = _store(tmp_path)
    store.record(_alert("SUP"), _inv("SUP", verdict="false_positive"))
    store.record_closure("SUP", "high-confidence false positive")
    # analyst overturns it AFTER the closure: the closure no longer stands
    store.record_disposition("SUP", "true_positive", "thehive:case-9")

    data = build_digest_data(store, since_hours=24)
    [entry] = data["investigated"]
    assert entry["auto_closed"] is False
    assert data["counts"]["auto_closed"] == 0
    assert entry["analyst_ruled"] == "true_positive"

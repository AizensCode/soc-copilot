"""Unit tests for the ruling→eval-case exporter (no API, no network).

    uv run pytest tests/test_evalcase.py -v
"""
import json
from datetime import datetime, timezone

import pytest

from src.evalcase import export_case, exportable_alert_ids
from src.history import AlertHistoryStore
from src.models import Alert, Investigation

_T = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _store(tmp_path) -> AlertHistoryStore:
    return AlertHistoryStore(tmp_path / "investigations.jsonl")


def _record(store, alert_id, verdict="true_positive"):
    store.record(
        Alert(
            alert_id=alert_id, timestamp=_T, source="edr", severity="high",
            title=f"alert {alert_id}", raw_log={"host": "web-01"},
            indicators={"ips": ["9.9.9.9"]},
        ),
        Investigation(
            alert_id=alert_id, verdict=verdict, confidence="high",
            hypothesis="h", escalation_recommended=True,
        ),
    )


def test_exported_case_carries_the_alert_and_the_human_label(tmp_path):
    store = _store(tmp_path)
    _record(store, "A1", "true_positive")
    store.record_disposition("A1", "true_positive", "thehive:case-7", "Confirmed.")

    path = export_case(store, "A1", dest_dir=tmp_path / "cases")
    case = json.loads(path.read_text())
    assert path.name == "A1.json"
    assert case["alert"]["raw_log"]["host"] == "web-01"
    Alert(**case["alert"])  # replayable as-is
    assert case["label"]["human_verdict"] == "true_positive"
    assert case["label"]["summary"] == "Confirmed."
    assert case["agreed_at_export"] is True


def test_disagreement_is_stamped_as_an_improvement_target(tmp_path):
    store = _store(tmp_path)
    _record(store, "A1", "true_positive")
    store.record_disposition("A1", "false_positive", "thehive:case-3", "Pentest.")

    case = json.loads(export_case(store, "A1", dest_dir=tmp_path / "c").read_text())
    assert case["agreed_at_export"] is False
    assert case["copilot_verdict_at_export"] == "true_positive"


def test_unruled_and_unknown_and_summary_only_are_refused(tmp_path):
    store = _store(tmp_path)
    _record(store, "UNRULED")
    with pytest.raises(ValueError, match="no analyst ruling"):
        export_case(store, "UNRULED", dest_dir=tmp_path / "c")
    with pytest.raises(ValueError, match="No investigation on record"):
        export_case(store, "GHOST", dest_dir=tmp_path / "c")

    old_style = {
        "alert_id": "OLD", "timestamp": _T.isoformat(), "title": "t",
        "verdict": "false_positive", "confidence": "high", "host": None,
        "iocs": [], "attack_techniques": [],
    }
    with store.path.open("a") as f:
        f.write(json.dumps(old_style) + "\n")
    store.record_disposition("OLD", "false_positive", "thehive:alert-status")
    with pytest.raises(ValueError, match="Re-investigate"):
        export_case(store, "OLD", dest_dir=tmp_path / "c")


def test_re_export_overwrites_with_the_latest_ruling(tmp_path):
    store = _store(tmp_path)
    _record(store, "A1", "true_positive")
    store.record_disposition("A1", "false_positive", "thehive:alert-status")
    export_case(store, "A1", dest_dir=tmp_path / "c")
    store.record_disposition("A1", "true_positive", "thehive:case-9", "Real.")

    case = json.loads(export_case(store, "A1", dest_dir=tmp_path / "c").read_text())
    assert case["label"]["human_verdict"] == "true_positive"
    assert case["agreed_at_export"] is True
    assert len(list((tmp_path / "c").glob("*.json"))) == 1


def test_exportable_ids_are_ruled_and_fully_recorded_only(tmp_path):
    store = _store(tmp_path)
    _record(store, "RULED")
    store.record_disposition("RULED", "true_positive", "x")
    _record(store, "UNRULED")
    old_style = {
        "alert_id": "OLD", "timestamp": _T.isoformat(), "title": "t",
        "verdict": "false_positive", "confidence": "high", "host": None,
        "iocs": [], "attack_techniques": [],
    }
    with store.path.open("a") as f:
        f.write(json.dumps(old_style) + "\n")
    store.record_disposition("OLD", "false_positive", "x")
    store.record_disposition("GHOST", "false_positive", "x")

    assert exportable_alert_ids(store) == ["RULED"]

"""Unit tests for the analyst feedback loop (no API, no network).

Covers the three layers separately: the disposition store (history),
the TheHive status/resolution mapping (casemgmt, MockTransport with
response shapes recorded from a live TheHive 5.7.5), and the prompt
rendering that puts ANALYST RULED in front of the model.

    uv run pytest tests/test_feedback.py -v
"""
import json
from datetime import datetime, timezone

import httpx

from soc_copilot.casemgmt import TheHiveClient, sync_dispositions
from soc_copilot.copilot import SOCCopilot
from soc_copilot.history import AlertHistoryStore
from soc_copilot.models import Alert, Investigation, PriorSighting

_T = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _store(tmp_path) -> AlertHistoryStore:
    return AlertHistoryStore(tmp_path / "investigations.jsonl")


def _alert(alert_id: str, iocs: list[str]) -> Alert:
    return Alert(
        alert_id=alert_id,
        timestamp=_T,
        source="edr",
        severity="high",
        title="t",
        raw_log={},
        indicators={"ips": iocs},
    )


def _inv(alert_id: str, verdict: str = "true_positive") -> Investigation:
    return Investigation(
        alert_id=alert_id,
        verdict=verdict,
        confidence="high",
        hypothesis="h",
        escalation_recommended=True,
    )


# --- disposition store -------------------------------------------------------


def test_sightings_carry_the_analyst_ruling(tmp_path):
    store = _store(tmp_path)
    store.record(_alert("A1", ["9.9.9.9"]), _inv("A1", "true_positive"))
    store.record_disposition(
        "A1", "false_positive", "thehive:case-7", "Sanctioned red team."
    )

    [sighting] = store.prior_sightings(_alert("A2", ["9.9.9.9"]))
    assert sighting.verdict == "true_positive"          # the copilot's opinion
    assert sighting.human_verdict == "false_positive"   # the human's ruling
    assert sighting.human_summary == "Sanctioned red team."


def test_unruled_sightings_have_no_human_verdict(tmp_path):
    store = _store(tmp_path)
    store.record(_alert("A1", ["9.9.9.9"]), _inv("A1"))
    [sighting] = store.prior_sightings(_alert("A2", ["9.9.9.9"]))
    assert sighting.human_verdict is None
    assert sighting.human_summary is None


def test_latest_ruling_wins(tmp_path):
    """A re-opened and re-ruled case appends; the reader takes the last."""
    store = _store(tmp_path)
    store.record(_alert("A1", ["9.9.9.9"]), _inv("A1"))
    store.record_disposition("A1", "false_positive", "thehive:alert-status")
    store.record_disposition("A1", "true_positive", "thehive:case-9", "It was real.")

    [sighting] = store.prior_sightings(_alert("A2", ["9.9.9.9"]))
    assert sighting.human_verdict == "true_positive"


def test_dispositions_live_beside_the_history_file(tmp_path):
    """Isolated stores must isolate dispositions too — the path derives
    from the investigations path, so harness/test stores never see the
    operator's real rulings."""
    store = _store(tmp_path)
    store.record_disposition("A1", "false_positive", "x")
    assert store.dispositions_path.parent == store.path.parent
    assert store.dispositions_path.name == "dispositions.jsonl"


# --- TheHive fetch + mapping -------------------------------------------------
# Response shapes recorded from a live TheHive 5.7.5 (2026-08-06): alert
# statuses New/InProgress/Pending/Ignored/FalsePositive/Duplicate/Imported;
# an Imported alert carries caseId; a closed case carries status
# TruePositive/FalsePositive/Indeterminate at stage Closed.

_ALERTS = [
    {"type": "soc-copilot", "sourceRef": "AL-1", "status": "FalsePositive", "stage": "Closed"},
    {"type": "soc-copilot", "sourceRef": "AL-2", "status": "Ignored", "stage": "Closed"},
    {"type": "soc-copilot", "sourceRef": "AL-3", "status": "Imported", "stage": "Imported", "caseId": "~101"},
    {"type": "soc-copilot", "sourceRef": "AL-4", "status": "Imported", "stage": "Imported", "caseId": "~102"},
    {"type": "soc-copilot", "sourceRef": "AL-5", "status": "New", "stage": "New"},
    {"type": "soc-copilot", "sourceRef": "AL-6", "status": "Duplicate", "stage": "Closed"},
    {"type": "other-feed", "sourceRef": "XX-1", "status": "FalsePositive", "stage": "Closed"},
]

_CASES = {
    "~101": {"number": 7, "status": "TruePositive", "stage": "Closed",
             "summary": "Confirmed compromise."},
    "~102": {"number": 8, "status": "InProgress", "stage": "InProgress"},
}


def _client(handler) -> TheHiveClient:
    return TheHiveClient(
        url="https://thehive.test:9000",
        api_key="k",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.startswith("/api/v1/query"):
        return httpx.Response(200, json=_ALERTS)
    case_id = request.url.path.rsplit("/", 1)[-1]
    return httpx.Response(200, json=_CASES[case_id])


async def test_fetch_dispositions_maps_the_live_status_vocabulary():
    got = {d["alert_id"]: d for d in await _client(_handler).fetch_dispositions()}

    assert got["AL-1"]["human_verdict"] == "false_positive"   # ruled at alert level
    assert got["AL-2"]["human_verdict"] == "false_positive"   # dismissed
    assert got["AL-2"]["source"] == "thehive:alert-dismissed"
    # Imported + case closed TruePositive -> confirmed, with the summary
    assert got["AL-3"]["human_verdict"] == "true_positive"
    assert got["AL-3"]["summary"] == "Confirmed compromise."
    assert got["AL-3"]["source"] == "thehive:case-7"
    # ownership without a ruling, workflow states, duplicates, and other
    # feeds' alerts all yield nothing
    for absent in ("AL-4", "AL-5", "AL-6", "XX-1"):
        assert absent not in got


async def test_sync_is_idempotent_on_unchanged_rulings(tmp_path):
    store = _store(tmp_path)
    changed, total = await sync_dispositions(_client(_handler), store)
    assert total == 3 and len(changed) == 3
    size_after_first = store.dispositions_path.read_text().count("\n")

    changed, total = await sync_dispositions(_client(_handler), store)
    assert total == 3 and changed == []   # nothing new -> nothing recorded
    assert store.dispositions_path.read_text().count("\n") == size_after_first
    assert store.dispositions()["AL-3"]["human_verdict"] == "true_positive"


# --- Elastic annotation ------------------------------------------------------


async def test_annotate_disposition_updates_each_matching_doc():
    """Search + per-doc _update (never _update_by_query — that action
    needs privileges a least-privilege SIEM key doesn't carry), with
    human_agrees computed against EACH doc's own verdict: a
    re-investigated alert shows which attempt the human agreed with."""
    from soc_copilot.elastic import ElasticAlertSource

    updates: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if request.url.path.endswith("/_search"):
            assert body["query"] == {"term": {"alert_id.keyword": "AL-3"}}
            return httpx.Response(200, json={"hits": {"hits": [
                {"_id": "d1", "_source": {"verdict": "inconclusive"}},
                {"_id": "d2", "_source": {"verdict": "true_positive"}},
            ]}})
        doc_id = request.url.path.rsplit("/", 1)[-1]
        updates[doc_id] = body["doc"]
        return httpx.Response(200, json={"result": "updated"})

    source = ElasticAlertSource(
        url="https://es.test:9200",
        api_key="k",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        results_index="soc-copilot-investigations",
    )
    n = await source.annotate_disposition("AL-3", "true_positive", "Confirmed.")

    assert n == 2
    assert updates["d1"]["human_verdict"] == "true_positive"
    assert updates["d1"]["human_agrees"] is False   # that run hedged
    assert updates["d2"]["human_agrees"] is True    # that run called it
    assert updates["d2"]["human_summary"] == "Confirmed."


# --- prompt rendering --------------------------------------------------------


def _sighting(**overrides) -> PriorSighting:
    base = dict(
        alert_id="AL-1",
        timestamp=_T,
        verdict="true_positive",
        confidence="high",
        title="old alert",
        matched_iocs=["9.9.9.9"],
    )
    base.update(overrides)
    return PriorSighting(**base)


def test_overturned_ruling_is_rendered_loudly():
    text = SOCCopilot._format_memory_context(
        [_sighting(human_verdict="false_positive",
                   human_summary="Sanctioned red team.")],
        None,
    )
    assert "ANALYST RULED: false_positive" in text
    assert "OVERTURNING" in text
    assert "Sanctioned red team." in text


def test_confirming_ruling_is_rendered_as_confirmation():
    text = SOCCopilot._format_memory_context(
        [_sighting(human_verdict="true_positive")], None
    )
    assert "ANALYST RULED: true_positive" in text
    assert "confirming" in text
    assert "OVERTURNING" not in text


def test_unruled_sighting_renders_without_ruling_language():
    text = SOCCopilot._format_memory_context([_sighting()], None)
    assert "ANALYST RULED" not in text

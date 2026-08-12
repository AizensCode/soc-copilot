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
    {"_id": "~a1", "type": "soc-copilot", "sourceRef": "AL-1", "status": "FalsePositive", "stage": "Closed"},
    {"_id": "~a2", "type": "soc-copilot", "sourceRef": "AL-2", "status": "Ignored", "stage": "Closed"},
    {"_id": "~a3", "type": "soc-copilot", "sourceRef": "AL-3", "status": "Imported", "stage": "Imported", "caseId": "~101"},
    {"_id": "~a4", "type": "soc-copilot", "sourceRef": "AL-4", "status": "Imported", "stage": "Imported", "caseId": "~102"},
    {"_id": "~a5", "type": "soc-copilot", "sourceRef": "AL-5", "status": "New", "stage": "New"},
    {"_id": "~a6", "type": "soc-copilot", "sourceRef": "AL-6", "status": "Duplicate", "stage": "Closed"},
    {"_id": "~x1", "type": "other-feed", "sourceRef": "XX-1", "status": "FalsePositive", "stage": "Closed"},
]

# The provenance ledger the copilot would hold if it had created all seven
# alerts (sourceRef -> the TheHive object id we recorded). Passed to
# fetch_dispositions so the mapping test exercises status vocabulary, not
# the provenance gate (which has its own tests below).
_LEDGER = {a["sourceRef"]: a["_id"] for a in _ALERTS}

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


def _seed_ledger(store, ledger=_LEDGER) -> None:
    """Record every alert in `ledger` as one this copilot created, so the
    provenance gate admits its rulings."""
    for source_ref, thehive_id in ledger.items():
        store.record_created_alert(source_ref, thehive_id)


async def test_fetch_dispositions_maps_the_live_status_vocabulary():
    accepted, rejected = await _client(_handler).fetch_dispositions(_LEDGER, set())
    got = {d["alert_id"]: d for d in accepted}

    assert got["AL-1"]["human_verdict"] == "false_positive"   # ruled at alert level
    assert got["AL-2"]["human_verdict"] == "false_positive"   # dismissed
    assert got["AL-2"]["source"] == "thehive:alert-dismissed"
    # Imported + case closed TruePositive -> confirmed, with the summary
    assert got["AL-3"]["human_verdict"] == "true_positive"
    assert got["AL-3"]["summary"] == "Confirmed compromise."
    assert got["AL-3"]["source"] == "thehive:case-7"
    # ownership without a ruling, workflow states, duplicates, and other
    # feeds' alerts all yield nothing — and none of these are provenance
    # rejections (they simply produce no ruling)
    for absent in ("AL-4", "AL-5", "AL-6", "XX-1"):
        assert absent not in got
    assert rejected == []


async def test_sync_is_idempotent_on_unchanged_rulings(tmp_path):
    store = _store(tmp_path)
    _seed_ledger(store)
    changed, total, rejected = await sync_dispositions(_client(_handler), store)
    assert total == 3 and len(changed) == 3 and rejected == []
    size_after_first = store.dispositions_path.read_text().count("\n")

    changed, total, rejected = await sync_dispositions(_client(_handler), store)
    assert total == 3 and changed == []   # nothing new -> nothing recorded
    assert store.dispositions_path.read_text().count("\n") == size_after_first
    assert store.dispositions()["AL-3"]["human_verdict"] == "true_positive"


# --- provenance: only rulings for alerts THIS copilot created are trusted ---


async def test_a_ruling_for_an_unhandled_alert_is_rejected_not_recorded(tmp_path):
    """The core gap this closes: a TheHive alert typed 'soc-copilot' is a
    self-asserted label. With NO local record — the copilot neither
    investigated nor created these alerts — every ruling must be rejected;
    a forged feed cannot inject a verdict for an alert we never worked."""
    store = _store(tmp_path)  # empty: no investigations, no ledger
    changed, total, rejected = await sync_dispositions(_client(_handler), store)
    assert changed == [] and total == 0
    assert store.dispositions() == {}                      # nothing recorded
    rejected_ids = {r["alert_id"] for r in rejected}
    assert rejected_ids == {"AL-1", "AL-2", "AL-3"}        # the 3 ruling-bearing
    assert all(r["reason"] == "no-local-record" for r in rejected)


async def test_a_ruling_on_an_investigated_but_uncased_alert_is_trusted(tmp_path):
    """The upgrade/transition floor (review catch): an alert the copilot
    INVESTIGATED but has no ledger entry for (e.g. cased before provenance
    tracking existed) is still ours to trust — rejecting it would mislabel
    the operator's own history as forged. AL-1 is in the investigation
    history but not the ledger; its ruling is recorded."""
    store = _store(tmp_path)
    store.record(_alert("AL-1", ["1.1.1.1"]), _inv("AL-1"))  # investigated, not cased
    changed, total, rejected = await sync_dispositions(_client(_handler), store)
    assert [c["alert_id"] for c in changed] == ["AL-1"]
    assert {r["alert_id"] for r in rejected} == {"AL-2", "AL-3"}  # never worked
    assert store.dispositions()["AL-1"]["human_verdict"] == "false_positive"


async def test_only_the_handled_subset_is_trusted(tmp_path):
    """A partial ledger: the copilot created AL-1 but not AL-2/AL-3, and
    never investigated them either. Only AL-1's ruling is recorded."""
    store = _store(tmp_path)
    store.record_created_alert("AL-1", "~a1")
    changed, total, rejected = await sync_dispositions(_client(_handler), store)
    assert total == 1
    assert [c["alert_id"] for c in changed] == ["AL-1"]
    assert {r["alert_id"] for r in rejected} == {"AL-2", "AL-3"}


async def test_a_spoofed_object_reusing_our_sourceref_is_rejected(tmp_path):
    """The subtler forgery: an attacker creates a SECOND soc-copilot alert
    reusing a real sourceRef we own, but it is a different TheHive object.
    The recorded id doesn't match, so its ruling is rejected as a spoof."""
    store = _store(tmp_path)
    store.record_created_alert("AL-1", "~different-object")  # ours had a diff id
    _, _, rejected = await sync_dispositions(_client(_handler), store)
    al1 = [r for r in rejected if r["alert_id"] == "AL-1"]
    assert al1 and al1[0]["reason"] == "thehive-id-mismatch"
    assert "AL-1" not in store.dispositions()


async def test_membership_alone_admits_when_no_id_was_recorded(tmp_path):
    """Tolerance: if we recorded the creation but TheHive returned no usable
    object id (empty), membership alone still admits the ruling — the id
    match is an extra check, not a hard requirement that would false-reject
    our own alerts."""
    store = _store(tmp_path)
    store.record_created_alert("AL-1", "")     # created, but no id captured
    changed, _, rejected = await sync_dispositions(_client(_handler), store)
    assert "AL-1" in {c["alert_id"] for c in changed}
    assert not any(r["alert_id"] == "AL-1" for r in rejected)


# --- the write side: creating an alert records provenance -------------------


class _FakeThehive:
    """A TheHiveClient stand-in whose create_alert returns a fixed id and
    never touches the network or settings."""
    _next_id = "~obj-123"

    def __init__(self, *a, **k):
        pass

    async def create_alert(self, alert, investigation):
        return self._next_id


async def test_maybe_open_case_records_the_provenance_ledger(tmp_path, monkeypatch):
    """The create->ledger wiring (review catch: it had no test, which is
    exactly why a removed ledger write could pass the suite). A successful
    create_alert must record (alert_id -> thehive id), or the alert's future
    ruling can never be trusted."""
    import soc_copilot.casemgmt as casemgmt
    from soc_copilot.main import _maybe_open_case

    monkeypatch.setattr(casemgmt, "TheHiveClient", _FakeThehive)
    store = _store(tmp_path)
    # escalated true_positive -> should_open_case fires
    case_id = await _maybe_open_case(
        _alert("ALRT-X", ["1.1.1.1"]), _inv("ALRT-X"), case=True, store=store
    )
    assert case_id == "~obj-123"
    assert store.created_alerts() == {"ALRT-X": "~obj-123"}

    # And the round trip: a ruling on that alert now syncs, because it is in
    # the ledger the create just wrote.
    def handler(request):
        if request.url.path.startswith("/api/v1/query"):
            return httpx.Response(200, json=[{
                "_id": "~obj-123", "type": "soc-copilot",
                "sourceRef": "ALRT-X", "status": "FalsePositive", "stage": "Closed",
            }])
        return httpx.Response(404)
    changed, total, rejected = await sync_dispositions(_client(handler), store)
    assert [c["alert_id"] for c in changed] == ["ALRT-X"] and rejected == []


async def test_maybe_open_case_survives_a_ledger_write_failure(
    tmp_path, monkeypatch, capsys
):
    """The never-fatal contract (review catch): a disk error writing the
    provenance ledger must not undo a case that already succeeded — the
    RuntimeError-only guard would have let an OSError escape and crash the
    caller, losing an investigation that was already pushed."""
    import soc_copilot.casemgmt as casemgmt
    from soc_copilot.main import _maybe_open_case

    monkeypatch.setattr(casemgmt, "TheHiveClient", _FakeThehive)
    store = _store(tmp_path)

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(store, "record_created_alert", boom)

    case_id = await _maybe_open_case(
        _alert("ALRT-Y", ["2.2.2.2"]), _inv("ALRT-Y"), case=True, store=store
    )
    assert case_id == "~obj-123"                    # the case was NOT lost
    assert "failed to record its provenance" in capsys.readouterr().out


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

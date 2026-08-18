"""What sharing a memory does and does NOT share.

Shared memory widens what every reader can see, and the readers are not
symmetric. Prior sightings, campaign correlation and the analyst-overturn
block can only make the desk LOUDER, and they read the whole shared
ledger — that is the sharing the item was for. Two readers act on a
record by doing LESS work: dedup borrows a verdict and skips the model
entirely, and resume delivers an interrupted run's conclusion. Those two
read the whole ledger too and then refuse anything they cannot attribute
to themselves.

Every test here is a refusal, and each one names the record that would
otherwise have bought silence.

    uv run pytest tests/test_shared_memory_safety.py -v
"""
from datetime import datetime, timedelta, timezone

import pytest

from soc_copilot.dedup import find_anchor, try_suppress
from soc_copilot.history import AlertHistoryStore
from soc_copilot.memory import DISPOSITIONS, INVESTIGATIONS, ElasticBackend
from soc_copilot.models import Alert, Investigation
from soc_copilot.resume import find_resumable
from tests.fake_memory import FakeMemoryIndex

INDEX = "soc-copilot-memory"
_T = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _alert(alert_id: str = "A-2", minutes_later: int = 0) -> Alert:
    return Alert(
        alert_id=alert_id,
        timestamp=_T + timedelta(minutes=minutes_later),
        source="siem", severity="medium",
        title="Vulnerability scan authentication burst",
        raw_log={"host": "qualys-scanner-02", "event_type": "auth_failure",
                 "service": "sshd"},
        indicators={"ips": ["10.20.8.15"]},
    )


def _inv(alert_id: str, **over) -> Investigation:
    fields = dict(
        alert_id=alert_id, verdict="false_positive", confidence="high",
        hypothesis="sanctioned scanner", escalation_recommended=False,
        attack_techniques=["T1110"],
    )
    fields.update(over)
    return Investigation(**fields)


def _shared_store(tmp_path, es: FakeMemoryIndex, writer="host-a"):
    es.create_index(INDEX)
    return AlertHistoryStore(
        backend=ElasticBackend(
            base_url="https://es.test:9200", api_key="k", index=INDEX,
            writer=writer, local_path=tmp_path / "local" / "inv.jsonl",
            client=es.client(), max_staleness=0.0,
        ),
        writer=writer,
    )


def _foreign_record(store, alert, inv, *, writer, now) -> None:
    """A record exactly like one this instance would write, from another
    writer. Written through the ledger so nothing about its SHAPE differs
    — the only difference is whose name is on it."""
    store.log(INVESTIGATIONS).append({
        "alert_id": alert.alert_id,
        "timestamp": alert.timestamp.isoformat(),
        "investigated_at": now.isoformat(),
        "title": alert.title,
        "verdict": inv.verdict,
        "confidence": inv.confidence,
        "host": alert.raw_log["host"],
        "iocs": alert.indicators["ips"],
        "attack_techniques": inv.attack_techniques,
        "duplicate_of": None,
        "writer": writer,
        "alert": alert.model_dump(mode="json"),
        "investigation": inv.model_dump(mode="json"),
    })


# --- dedup: another instance's verdict is never borrowed --------------------


def test_a_foreign_record_is_never_a_dedup_anchor(tmp_path):
    """One document in a shared index would otherwise suppress a real
    alert BEFORE any model sees it, and acknowledge it — a detection
    turned off by a write."""
    es = FakeMemoryIndex()
    store = _shared_store(tmp_path, es)
    now = datetime.now(timezone.utc)
    _foreign_record(
        store, _alert("A-1"), _inv("A-1"), writer="host-b", now=now
    )
    anchor, _ = find_anchor(store, _alert("A-2", minutes_later=5), now=now)
    assert anchor is None


def test_this_instances_own_record_still_anchors(tmp_path):
    """The refusal has to be about PROVENANCE, not about shared memory
    being unusable: a second alert of the same detection this instance
    just investigated is still suppressed."""
    es = FakeMemoryIndex()
    store = _shared_store(tmp_path, es)
    now = datetime.now(timezone.utc)
    _foreign_record(
        store, _alert("A-1"), _inv("A-1"), writer="host-a", now=now
    )
    anchor, _ = find_anchor(store, _alert("A-2", minutes_later=5), now=now)
    assert anchor is not None and anchor["alert_id"] == "A-1"


def test_an_unattributed_record_is_not_ours_in_shared_mode(tmp_path):
    """A record with no writer cannot be established as this desk's, and
    "cannot establish" resolves toward doing the work."""
    es = FakeMemoryIndex()
    store = _shared_store(tmp_path, es)
    now = datetime.now(timezone.utc)
    _foreign_record(
        store, _alert("A-1"), _inv("A-1"), writer="host-a", now=now
    )
    rec = store.log(INVESTIGATIONS).records()[0]
    del rec["writer"]
    anchor, _ = find_anchor(store, _alert("A-2", minutes_later=5), now=now)
    assert anchor is None


def test_a_local_store_never_asks_who_wrote_a_record(tmp_path):
    """The private file IS the boundary, so nothing about this changed
    for a desk that has not turned sharing on — including for the
    records it wrote before writers existed."""
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    now = datetime.now(timezone.utc)
    _foreign_record(
        store, _alert("A-1"), _inv("A-1"), writer="somebody-else", now=now
    )
    rec = store.log(INVESTIGATIONS).records()[0]
    del rec["writer"]
    anchor, _ = find_anchor(store, _alert("A-2", minutes_later=5), now=now)
    assert anchor is not None


def test_suppression_end_to_end_refuses_a_foreign_anchor(tmp_path):
    es = FakeMemoryIndex()
    store = _shared_store(tmp_path, es)
    now = datetime.now(timezone.utc)
    _foreign_record(
        store, _alert("A-1"), _inv("A-1"), writer="host-b", now=now
    )
    assert try_suppress(
        store, _alert("A-2", minutes_later=5), window_hours=24, now=now
    ) is None


# --- resume: only the run this loop interrupted -----------------------------


def test_resume_refuses_a_record_this_instance_did_not_write(tmp_path):
    """"Finish the run THIS loop interrupted" is the premise. Delivering
    someone else's record pushes a verdict this instance never reached
    and acknowledges the alert on the strength of it."""
    es = FakeMemoryIndex()
    store = _shared_store(tmp_path, es)
    alert = _alert("A-1")
    store.record_watch_progress(alert.alert_id, "d1", "started")
    _foreign_record(
        store, alert, _inv("A-1"), writer="host-b",
        now=datetime.now(timezone.utc),
    )
    assert find_resumable(store, alert) is None


def test_resume_still_finishes_this_instances_own_interrupted_run(tmp_path):
    es = FakeMemoryIndex()
    store = _shared_store(tmp_path, es)
    alert = _alert("A-1")
    store.record_watch_progress(alert.alert_id, "d1", "started")
    store.record(alert, _inv("A-1"))
    resumable = find_resumable(store, alert)
    assert resumable is not None
    assert resumable.investigation.verdict == "false_positive"


# --- rulings: you can correct yourself, not someone else --------------------


def _ruling(store, alert_id, verdict, writer, when):
    store.log(DISPOSITIONS).append({
        "alert_id": alert_id, "human_verdict": verdict,
        "source": "thehive", "summary": None,
        "recorded_at": when.isoformat(), "writer": writer,
    })


def test_a_later_ruling_supersedes_an_earlier_one_whoever_recorded_it(
    tmp_path,
):
    """There was a per-writer rule here — every writer's latest ruling
    read, and the one that BLOCKS taken — so that a shared ledger could
    not be used to cancel a block. It does not survive its own threat
    model: `writer` is a field in a document, and anything able to
    append the cancelling ruling can append it under the blocked
    writer's name. What it did stop was a real analyst, because rulings
    arrive through whichever instance ran --sync-feedback and an
    instance that sees another's correction first records nothing of its
    own. A defense that binds only the honest party is worse than none,
    so the ledger's integrity rests on who may write to the index."""
    es = FakeMemoryIndex()
    store = _shared_store(tmp_path, es)
    _ruling(store, "A-1", "true_positive", "host-a", _T)
    _ruling(store, "A-1", "false_positive", "host-b", _T + timedelta(hours=1))

    assert store.dispositions()["A-1"]["human_verdict"] == "false_positive"
    assert store.blocking_rulings() == {}


def test_the_gate_and_the_report_give_one_answer(tmp_path):
    """`blocking_rulings` and `dispositions` are two questions about one
    fact, so they must not disagree about what the analyst decided."""
    es = FakeMemoryIndex()
    store = _shared_store(tmp_path, es)
    _ruling(store, "A-1", "false_positive", "host-a", _T)
    _ruling(store, "A-2", "true_positive", "host-b", _T)
    assert set(store.blocking_rulings()) == {"A-2"}
    assert store.blocking_rulings()["A-2"] is store.dispositions()["A-2"]


def test_a_correction_still_reaches_a_ruling_recorded_before_the_upgrade(
    tmp_path,
):
    """`writer` only started being stamped when shared memory arrived, so
    bucketing a LOCAL desk's rulings by it would put every ruling
    recorded before the upgrade in a bucket of its own — and an analyst
    correcting one would find the correction unable to reach it. The
    private file is the boundary here, the same rule `wrote()` follows."""
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    store.log(DISPOSITIONS).append({                  # pre-upgrade line
        "alert_id": "A-1", "human_verdict": "true_positive",
        "source": "thehive", "summary": None,
        "recorded_at": _T.isoformat(),
    })
    store.record_disposition("A-1", "false_positive", "thehive")
    assert store.blocking_rulings() == {}


def test_a_prior_sighting_carries_the_latest_record_for_its_alert(tmp_path):
    """An alert can hold more than one record — a re-arrival after a
    failed push, an alert an analyst re-opened. Carrying the earliest
    reported a verdict the desk had since revised, and closure.py blocks
    exactly when a sighting's ruling DIFFERS from its verdict: revised to
    a true positive, ruled a false positive, the stale verdict AGREED
    with the ruling and the block never fired."""
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    alert = _alert("A-1")
    store.record(alert, _inv("A-1", verdict="false_positive"))
    store.record(alert, _inv("A-1", verdict="true_positive"))
    store.record_disposition("A-1", "false_positive", "thehive")

    [sighting] = store.prior_sightings(_alert("A-2"))
    assert sighting.verdict == "true_positive"
    assert sighting.human_verdict == "false_positive"


def test_a_single_writer_sees_exactly_the_old_behaviour(tmp_path):
    """The per-writer rules only ever diverge from latest-wins once a
    second writer exists — which is why no local desk changed."""
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    store.record_disposition("A-1", "true_positive", "thehive")
    store.record_disposition("A-1", "false_positive", "thehive")
    assert store.dispositions()["A-1"]["human_verdict"] == "false_positive"
    assert store.blocking_rulings() == {}


# --- retention ---------------------------------------------------------------


def test_rotation_refuses_the_shared_ledgers_and_says_whose_job_it_is(tmp_path):
    """Rotating the leftover local copies would be worse than doing
    nothing: the report would name files nothing reads any more while the
    real memory grew."""
    from soc_copilot.rotate import plan_rotation

    es = FakeMemoryIndex()
    store = _shared_store(tmp_path, es)
    store.record_closure("A-1", "auto")
    plan = plan_rotation(store, retention_days=90)
    assert any("shared ledgers" in note for note in plan.held_back)
    assert any("RUNBOOK" in note for note in plan.held_back)
    assert not any(fp.name == "investigations.jsonl" for fp in plan.files)


def test_rotation_still_ages_the_local_sidecars_in_shared_mode(tmp_path):
    """The local ledgers still grow one line per alert, so refusing the
    whole command would have traded one unbounded file for three."""
    from soc_copilot.rotate import plan_rotation

    es = FakeMemoryIndex()
    store = _shared_store(tmp_path, es)
    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    store.log("closures").append(
        {"alert_id": "OLD", "reason": "auto", "closed_at": old}
    )
    plan = plan_rotation(store, retention_days=90)
    assert [fp.name for fp in plan.files] == ["closures.jsonl"]


async def test_sync_feedback_finishes_in_shared_mode(tmp_path, monkeypatch, caplog):
    """Its last narration line named the dispositions FILE, which does
    not exist in shared mode — so the command failed after the sync had
    already succeeded, on a log line."""
    import logging
    from types import SimpleNamespace

    import soc_copilot.main as main_mod
    from soc_copilot.main import _run_sync_feedback

    es = FakeMemoryIndex()
    store = _shared_store(tmp_path, es)
    monkeypatch.setattr(main_mod, "open_store", lambda *a, **k: store,
                        raising=False)
    monkeypatch.setattr(
        "soc_copilot.history.open_store", lambda *a, **k: store
    )
    monkeypatch.setattr(
        "soc_copilot.casemgmt.TheHiveClient",
        lambda *a, **k: SimpleNamespace(),
    )

    async def _sync(client, store_):
        store_.record_disposition("A-1", "true_positive", "thehive")
        return ([{"alert_id": "A-1", "human_verdict": "true_positive",
                  "source": "thehive", "summary": None}], 1, [])

    monkeypatch.setattr("soc_copilot.casemgmt.sync_dispositions", _sync)
    with caplog.at_level(logging.INFO, logger="soc_copilot"):
        await _run_sync_feedback()
    assert "shared memory" in caplog.text


def test_the_investigations_file_is_not_silently_substituted(tmp_path):
    es = FakeMemoryIndex()
    store = _shared_store(tmp_path, es)
    with pytest.raises(RuntimeError, match="no local file"):
        store.path

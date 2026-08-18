"""Unit tests for where the desk's memory lives (soc_copilot/memory.py).

No cluster and no network: the Elasticsearch side runs against
tests/fake_memory.py through httpx.MockTransport.

    uv run pytest tests/test_memory.py -v
"""
import json
import random
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from soc_copilot.config import Settings
from soc_copilot.dedup import find_anchor
from soc_copilot.history import AlertHistoryStore
from soc_copilot.memory import (
    DISPOSITIONS,
    INVESTIGATIONS,
    ElasticBackend,
    ElasticLog,
    JsonlBackend,
    JsonlLog,
    migrate_to_shared,
    open_backend,
)
from soc_copilot.models import Alert
from tests.fake_memory import FakeMemoryIndex

INDEX = "soc-copilot-memory"
NOW = datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)


def _iso(offset_seconds: float) -> str:
    return (NOW + timedelta(seconds=offset_seconds)).isoformat()


def _log(es: FakeMemoryIndex, ledger: str = INVESTIGATIONS, **over) -> ElasticLog:
    kwargs = dict(
        base_url="https://es.test:9200", api_key="k", index=INDEX,
        ledger=ledger, writer="host-a", client=es.client(),
        max_staleness=0.0,
    )
    kwargs.update(over)
    return ElasticLog(**kwargs)


def _ready(es: FakeMemoryIndex | None = None) -> FakeMemoryIndex:
    es = es or FakeMemoryIndex()
    es.create_index(INDEX)
    return es


# --- the contract both logs owe their readers -------------------------------


@pytest.fixture(params=["jsonl", "elastic"])
def any_log(request, tmp_path):
    if request.param == "jsonl":
        return JsonlLog(tmp_path / "ledger.jsonl")
    return _log(_ready())


def test_every_log_hands_back_the_same_objects_across_calls(any_log):
    """The store's index memoizes derived values by ROW, so a record that
    changed identity between two reads would silently carry another
    record's fingerprint."""
    any_log.append({"alert_id": "A"})
    first = any_log.records()
    assert [r["alert_id"] for r in any_log.records()] == ["A"]
    assert any_log.records()[0] is first[0]


def test_every_log_rebinds_rather_than_mutates_on_append(any_log):
    """An iterator handed out before an append keeps walking its own
    snapshot — the store hands out `iter_records()` freely."""
    any_log.append({"alert_id": "A"})
    snapshot = any_log.records()
    any_log.append({"alert_id": "B"})
    assert [r["alert_id"] for r in any_log.records()] == ["A", "B"]
    assert [r["alert_id"] for r in snapshot] == ["A"]


def test_no_log_hands_the_callers_own_dict_back(any_log):
    """The file log round-trips every record through JSON. The index log
    must too, or the two backends disagree about any value JSON
    normalizes — and a caller that mutates a record after appending it
    could poison one backend's view and not the other's."""
    rec = {"alert_id": "A", "iocs": ["1.1.1.1"]}
    any_log.append(rec)
    stored = any_log.records()[0]
    assert stored == rec and stored is not rec
    rec["alert_id"] = "MUTATED"
    assert any_log.records()[0]["alert_id"] == "A"


def test_an_append_never_bumps_the_generation(any_log):
    """A bumped generation costs every derived structure a full rebuild;
    the ordinary case must not pay it."""
    any_log.append({"alert_id": "A"})
    any_log.records()
    before = any_log.generation
    any_log.append({"alert_id": "B"})
    any_log.records()
    assert any_log.generation == before


# --- tailing a shared ledger ------------------------------------------------


def test_an_append_waits_for_the_record_to_become_searchable():
    """Without refresh=wait_for, dedup's "has this really been
    investigated?" check can answer NO about a record written a moment
    earlier and suppress an alert whose verdict is already stored — the
    quiet direction, for a second of wall clock."""
    es = _ready()
    _log(es).append({"alert_id": "A"})
    creates = [r for r in es.requests if "_create" in r[1]]
    assert creates and "refresh=wait_for" in creates[0][1]


def test_a_just_written_record_is_readable_immediately():
    """`refresh=wait_for` makes the record searchable before append
    returns, so invalidating the view is enough — and leaves the CLUSTER
    ordering everything rather than this instance splicing its own
    record onto the end of a view another writer may already have moved
    past."""
    es = _ready()
    log = _log(es)
    log.records()                       # cold read
    log.append({"alert_id": "A"})
    assert [r["alert_id"] for r in log.records()] == ["A"]


def test_a_concurrent_write_before_our_own_is_still_a_plain_append():
    """The reason the local splice is gone. Our record used to go on the
    end with our timestamp, so a document another writer produced in
    between sorted BEFORE it and the next re-read was a REORDER — which
    bumps the generation and costs the query index a full O(history)
    rebuild, on most reads of a two-writer desk."""
    es = _ready()
    log = _log(es)
    log.records()
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "THEIRS"},
           written_at=_iso(-1))
    log.append({"alert_id": "OURS"})
    generation = log.generation
    assert [r["alert_id"] for r in log.records()] == ["THEIRS", "OURS"]
    assert log.generation == generation


def test_another_instances_write_is_picked_up_by_the_tail():
    es = _ready()
    log = _log(es)
    log.records()
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "B"}, written_at=_iso(1))
    assert [r["alert_id"] for r in log.records()] == ["B"]


def test_the_staleness_window_bounds_how_often_the_cluster_is_asked():
    """The store is read six or seven times per alert; a round trip per
    read would be the dominant per-alert cost for no freshness anyone
    acts on."""
    es = _ready()
    fake_time = [0.0]
    log = _log(es, max_staleness=5.0, clock=lambda: fake_time[0])
    log.records()
    assert es.searches == 1
    fake_time[0] = 1.0
    log.records()                       # inside the window
    assert es.searches == 1
    fake_time[0] = 99.0
    log.records()                       # past it
    assert es.searches == 2


def test_a_late_document_bumps_the_generation_so_readers_rebuild():
    """A document that lands with a written_at BEHIND one already read
    must not be spliced on the end — the store's "latest wins" would
    then resolve to arrival order rather than write order. The log
    announces it the same way a rewritten file is announced, which is
    why the query index needed no idea shared memory exists."""
    es = _ready()
    log = _log(es, lag_seconds=60.0)
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "SECOND"}, written_at=_iso(10))
    assert [r["alert_id"] for r in log.records()] == ["SECOND"]
    generation = log.generation

    es.put(INDEX, INVESTIGATIONS, {"alert_id": "FIRST"}, written_at=_iso(5))
    assert [r["alert_id"] for r in log.records()] == ["FIRST", "SECOND"]
    assert log.generation > generation


def test_a_document_later_than_the_lag_window_is_missed_and_that_is_stated():
    """The honest limit of tailing a log nobody sequences, pinned so it
    cannot quietly become a different limit."""
    es = _ready()
    log = _log(es, lag_seconds=60.0)
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "NOW"}, written_at=_iso(0))
    assert [r["alert_id"] for r in log.records()] == ["NOW"]
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "VERY_LATE"},
           written_at=_iso(-300))
    assert [r["alert_id"] for r in log.records()] == ["NOW"]


def test_a_pre_epoch_record_does_not_empty_the_view_on_the_next_read():
    """The tail's range floor and the local bisect must be the SAME
    value. Clamping the query floor to zero while the bisect used the
    real (negative) floor made the re-read return fewer rows than the
    window it replaces, which reads as "the prefix changed" and answers
    by replacing the window with the short answer: the desk's memory,
    emptied on the second read. Pre-epoch stamps are not hypothetical —
    an import whose source rows carry no timestamp sinks them to a
    floor."""
    es = _ready()
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "ANCIENT"},
           written_at="1969-01-01T00:00:00+00:00")
    log = _log(es)
    assert [r["alert_id"] for r in log.records()] == ["ANCIENT"]
    assert [r["alert_id"] for r in log.records()] == ["ANCIENT"]


def test_one_future_stamped_document_does_not_freeze_the_ledger():
    """The re-read floor used to be monotone in whatever the index
    CONTAINS. One document stamped in the future pushed it past every
    honest write that followed, the re-read returned only that document
    — which is exactly what a pure append looks like — and the ledger
    froze for the life of the process, with no bump, no error, and this
    instance's own writes still arriving through the local splice to make
    it look healthy. Downstream that is every new analyst ruling and
    every other instance's investigations going quietly missing from the
    overturn block.

    The non-adversarial trigger is a fast clock: a host two minutes ahead
    does it to itself on its first append."""
    es = _ready()
    log = _log(es, wall=lambda: NOW)
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "HONEST"}, written_at=_iso(0))
    assert [r["alert_id"] for r in log.records()] == ["HONEST"]

    es.put(INDEX, INVESTIGATIONS, {"alert_id": "FROM_THE_FUTURE"},
           written_at=(NOW + timedelta(days=3650)).isoformat())
    assert "FROM_THE_FUTURE" in [r["alert_id"] for r in log.records()]

    es.put(INDEX, INVESTIGATIONS, {"alert_id": "LATER_AND_HONEST"},
           written_at=_iso(1))
    assert "LATER_AND_HONEST" in [r["alert_id"] for r in log.records()]


def test_the_tail_pages_past_the_first_page():
    es = _ready()
    for i in range(7):
        es.put(INDEX, INVESTIGATIONS, {"alert_id": f"A{i}"},
               written_at=_iso(i))
    log = _log(es, page_size=3)
    assert [r["alert_id"] for r in log.records()] == [f"A{i}" for i in range(7)]


def test_the_lag_window_pages_when_it_holds_more_than_one_page():
    """The re-read window is a query like any other and can exceed a
    page. Stopping at the first page would make the re-read shorter than
    the window it replaces, which the caller reads as "the prefix
    changed" — a generation bump and a truncated view on every read."""
    es = _ready()
    log = _log(es, page_size=2, lag_seconds=3600.0)
    for i in range(5):
        es.put(INDEX, INVESTIGATIONS, {"alert_id": f"A{i}"},
               written_at=_iso(i))
    assert [r["alert_id"] for r in log.records()] == [f"A{i}" for i in range(5)]
    generation = log.generation
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "A5"}, written_at=_iso(5))
    assert [r["alert_id"] for r in log.records()] == [f"A{i}" for i in range(6)]
    assert log.generation == generation


def test_two_instances_converge_on_one_order():
    """The property the whole item is for: what each instance writes, the
    other reads, and both end up walking the same ledger in the same
    order — which is what makes "the latest record wins" mean the same
    thing on both desks."""
    es = _ready()
    a = _log(es, writer="host-a")
    b = _log(es, writer="host-b")
    a.records()
    b.records()

    a.append({"alert_id": "FROM-A-1"})
    b.append({"alert_id": "FROM-B-1"})
    a.append({"alert_id": "FROM-A-2"})

    seen_a = [r["alert_id"] for r in a.records()]
    seen_b = [r["alert_id"] for r in b.records()]
    assert seen_a == seen_b
    assert set(seen_a) == {"FROM-A-1", "FROM-B-1", "FROM-A-2"}


def test_repeated_reads_of_an_empty_ledger_never_bump_the_generation():
    """A generation bump costs every derived structure a full rebuild.
    An empty shared memory is the state a desk starts in."""
    es = _ready()
    log = _log(es)
    log.records()
    generation = log.generation
    log.records()
    log.records()
    assert log.generation == generation


def test_one_ledger_never_reads_another():
    es = _ready()
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "INV"}, written_at=_iso(0))
    es.put(INDEX, DISPOSITIONS, {"alert_id": "RULING"}, written_at=_iso(1))
    assert [r["alert_id"] for r in _log(es).records()] == ["INV"]
    assert [
        r["alert_id"] for r in _log(es, ledger=DISPOSITIONS).records()
    ] == ["RULING"]


def test_a_document_carrying_no_record_object_raises_rather_than_truncating():
    """`record` is stored-not-indexed, so the cluster validates nothing
    inside it. A silently skipped document reads as "never seen, never
    overturned" — the one answer memory must not invent."""
    es = _ready()
    es.docs[INDEX]["bad"] = {
        "uid": "bad", "ledger": INVESTIGATIONS, "writer": "x",
        "written_at": _iso(0), "record": "not an object",
    }
    with pytest.raises(RuntimeError, match="not an object"):
        _log(es).records()


def test_an_outage_raises_rather_than_reporting_an_empty_history(monkeypatch):
    """A store that answered "no prior sightings" because the cluster was
    unreachable would turn every gate that rests on memory off at exactly
    the moment nobody is watching."""
    from soc_copilot import httpio

    monkeypatch.setattr(httpio, "BACKOFF_SECONDS", 0)
    es = _ready()
    es.fail_always = httpx.ConnectError("connection refused")
    with pytest.raises(RuntimeError, match="unreachable"):
        _log(es).records()


def test_an_outage_on_append_raises_too(monkeypatch):
    from soc_copilot import httpio

    monkeypatch.setattr(httpio, "BACKOFF_SECONDS", 0)
    es = _ready()
    log = _log(es)
    log.records()
    es.fail_always = httpx.ConnectError("connection refused")
    with pytest.raises(RuntimeError, match="unreachable"):
        log.append({"alert_id": "A"})


def test_a_repeat_create_is_reported_not_raised():
    """Both the retry policy's second attempt and a re-run of an import
    land on an id that already exists."""
    es = _ready()
    log = _log(es)
    when = datetime(2026, 8, 18, tzinfo=timezone.utc)
    assert log.import_record({"alert_id": "A"}, "fixed-id", when) is True
    assert log.import_record({"alert_id": "A"}, "fixed-id", when) is False


# --- provisioning -----------------------------------------------------------


def test_the_index_is_created_with_record_stored_but_not_indexed():
    """A dynamically mapped `record` hits the field-count limit and then
    REJECTS appends: a desk that stops remembering without saying so."""
    es = FakeMemoryIndex()
    _log(es).ensure_index()
    mappings = es.indices[INDEX]["mappings"]
    assert mappings["dynamic"] == "strict"
    assert mappings["properties"]["record"] == {
        "type": "object", "enabled": False
    }


def test_an_auto_created_index_is_refused_rather_than_used():
    es = FakeMemoryIndex()
    es.create_index(INDEX, {"mappings": {"properties": {
        "record": {"properties": {"alert_id": {"type": "text"}}},
    }}})
    with pytest.raises(RuntimeError, match="stored-not-indexed"):
        _log(es).ensure_index()


def test_the_document_carries_exactly_the_mapped_fields():
    """The fake refuses an unmapped field the way `dynamic: strict` does,
    so a field added to the document without the mapping fails here
    instead of in production."""
    es = _ready()
    _log(es).append({"alert_id": "A"})
    [doc] = es.docs[INDEX].values()
    assert set(doc) == {"uid", "ledger", "writer", "written_at", "record"}


# --- the two backends answer every reader identically -----------------------


def _record(i: int, ioc: str, host: str, when: datetime, verdict: str) -> dict:
    return {
        "alert_id": f"A{i}",
        "timestamp": when.isoformat(),
        "investigated_at": when.isoformat(),
        "title": f"alert {i}",
        "verdict": verdict,
        "confidence": "high",
        "host": host,
        "iocs": [ioc],
        "attack_techniques": ["T1566.002"],
        "duplicate_of": None,
        "writer": "host-a",
        "alert": {}, "investigation": {},
    }


def _probe(ioc: str, host: str, when: datetime) -> Alert:
    return Alert(
        alert_id="PROBE", timestamp=when, source="siem", severity="high",
        title="probe", raw_log={"host": host},
        indicators={"ips": [ioc]},
    )


def test_both_backends_answer_every_reader_identically(tmp_path):
    """The claim the seam rests on: one implementation of every
    predicate, so a shared desk and a local desk cannot disagree about
    whether an alert is a campaign. Same records, same questions, same
    answers — the equivalence discipline the query index established,
    extended to the backend."""
    rng = random.Random(20260818)
    es = _ready()
    local = AlertHistoryStore(backend=JsonlBackend(tmp_path / "inv.jsonl"))
    shared = AlertHistoryStore(
        backend=ElasticBackend(
            base_url="https://es.test:9200", api_key="k", index=INDEX,
            writer="host-a", local_path=tmp_path / "shared" / "inv.jsonl",
            client=es.client(), max_staleness=0.0,
        ),
        writer="host-a",
    )

    for i in range(60):
        rec = _record(
            i,
            f"10.0.{rng.randrange(3)}.{rng.randrange(4)}",
            f"host-{rng.randrange(3)}",
            NOW - timedelta(hours=rng.randrange(96)),
            rng.choice(["true_positive", "false_positive", "inconclusive"]),
        )
        for store in (local, shared):
            store.log(INVESTIGATIONS).append(rec)
        if rng.random() < 0.3:
            ruling = {
                "alert_id": rec["alert_id"],
                "human_verdict": rng.choice(
                    ["true_positive", "false_positive"]
                ),
                "source": "thehive", "summary": None,
                "recorded_at": (NOW - timedelta(minutes=i)).isoformat(),
                "writer": "host-a",
            }
            for store in (local, shared):
                store.log(DISPOSITIONS).append(ruling)

    assert list(local.iter_records()) == list(shared.iter_records())
    assert local.dispositions() == shared.dispositions()
    assert local.blocking_rulings() == shared.blocking_rulings()
    # find_anchor is the reader that ACTS on a record by skipping work,
    # so an equivalence that left it out would omit the one place the
    # two backends disagreeing costs silence rather than a report.
    for i in range(0, 60, 7):
        probe = _probe(f"10.0.0.{i}", f"host-{i % 3}", NOW)
        assert find_anchor(local, probe, now=NOW) == find_anchor(
            shared, probe, now=NOW
        )
    for _ in range(25):
        alert = _probe(
            f"10.0.{rng.randrange(3)}.{rng.randrange(4)}",
            f"host-{rng.randrange(3)}",
            NOW - timedelta(hours=rng.randrange(96)),
        )
        assert local.prior_sightings(alert) == shared.prior_sightings(alert)
        assert local.correlate(alert) == shared.correlate(alert)
    for i in range(60):
        assert local.latest_record(f"A{i}") == shared.latest_record(f"A{i}")


# --- choosing a backend -----------------------------------------------------


def _cfg(tmp_path, **over) -> Settings:
    base = Settings(
        HISTORY_PATH=str(tmp_path / "investigations.jsonl"),
        HISTORY_BACKEND="elastic",
        ELASTIC_URL="https://es.test:9200",
        ELASTIC_API_KEY="k",
        ELASTIC_MEMORY_INDEX=INDEX,
        INSTANCE_ID="host-a",
    )
    return replace(base, **over)


def test_shared_memory_refuses_to_start_empty_beside_a_local_history(tmp_path):
    """Flipping the switch would otherwise be silent amnesia: every prior
    sighting and every analyst ruling the gates read, gone, in the quiet
    direction, from a configuration change."""
    es = _ready()
    local = tmp_path / "investigations.jsonl"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text(json.dumps({"alert_id": "A"}) + "\n")
    with pytest.raises(RuntimeError, match="--migrate-memory"):
        open_backend(_cfg(tmp_path), client=es.client())


def test_a_log_written_to_before_it_is_read_still_reads_everything():
    """`_keys` is populated by the local splice on append, so a log
    WRITTEN to before it is READ from would anchor its first ever read on
    its own new record and fetch only the lag window around it —
    discarding every older record in the shared ledger permanently, with
    a perfectly healthy-looking view of the last minute."""
    es = _ready()
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "OLD"},
           written_at=(NOW - timedelta(days=30)).isoformat())
    log = _log(es, lag_seconds=60.0)
    log.append({"alert_id": "NEW"})            # first touch is a WRITE
    assert [r["alert_id"] for r in log.records()] == ["OLD", "NEW"]


def test_the_refusal_covers_the_rulings_ledger_too(tmp_path):
    """A desk whose investigations migrated but whose rulings did not
    looks completely healthy — full history, sensible reports — while the
    one gate that lets a human overrule autonomous closure quietly
    matches nothing."""
    es = _ready()
    (tmp_path / "dispositions.jsonl").write_text(
        json.dumps({"alert_id": "A", "human_verdict": "true_positive"}) + "\n"
    )
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "A", "writer": "host-a"},
           written_at=_iso(0), writer="host-a")
    with pytest.raises(RuntimeError, match="no 'dispositions' records"):
        open_backend(_cfg(tmp_path), client=es.client())


def test_the_refusal_lifts_once_this_instance_is_represented(tmp_path):
    es = _ready()
    local = tmp_path / "investigations.jsonl"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text(json.dumps({"alert_id": "A"}) + "\n")
    (tmp_path / "dispositions.jsonl").write_text("")
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "A", "writer": "host-a"},
           written_at=_iso(0), writer="host-a")
    backend = open_backend(_cfg(tmp_path), client=es.client())
    assert backend.shared is True


def test_a_second_instance_joining_a_populated_desk_is_refused_too(tmp_path):
    """Emptiness only protects the FIRST desk to join. The second analyst
    to flip the switch finds a shared index full of someone else's
    records, sails past an emptiness check, and abandons their own
    rulings — the same loss, arriving later and quieter."""
    es = _ready()
    local = tmp_path / "investigations.jsonl"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text(json.dumps({"alert_id": "MINE"}) + "\n")
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "THEIRS", "writer": "host-b"},
           written_at=_iso(0), writer="host-b")
    with pytest.raises(RuntimeError, match="written by 'host-a'"):
        open_backend(_cfg(tmp_path), client=es.client())


def test_an_empty_desk_starts_shared_without_ceremony(tmp_path):
    es = _ready()
    assert open_backend(_cfg(tmp_path), client=es.client()).shared is True


def test_the_local_ledgers_keep_their_files_in_shared_mode(tmp_path):
    backend = open_backend(_cfg(tmp_path), client=_ready().client())
    assert INVESTIGATIONS not in backend.paths
    assert DISPOSITIONS not in backend.paths
    store = AlertHistoryStore(backend=backend)
    assert store.closures_path.name == "closures.jsonl"
    with pytest.raises(RuntimeError, match="no local file"):
        store.path


def test_a_local_configuration_never_reaches_the_cluster(tmp_path):
    backend = open_backend(_cfg(tmp_path, HISTORY_BACKEND="jsonl"))
    assert backend.shared is False


# --- migrating a local history into shared memory ---------------------------


def _local_with(tmp_path, investigations, rulings=(), **sidecars) -> JsonlBackend:
    backend = JsonlBackend(tmp_path / "investigations.jsonl")
    for rec in investigations:
        backend.log(INVESTIGATIONS).append(rec)
    for rec in rulings:
        backend.log(DISPOSITIONS).append(rec)
    for ledger, recs in sidecars.items():
        for rec in recs:
            backend.log(ledger).append(rec)
    return backend


def _shared(es: FakeMemoryIndex, tmp_path) -> ElasticBackend:
    return ElasticBackend(
        base_url="https://es.test:9200", api_key="k", index=INDEX,
        writer="host-a", local_path=tmp_path / "shared" / "inv.jsonl",
        client=es.client(), max_staleness=0.0,
    )


def test_migration_is_idempotent(tmp_path):
    """There is no transaction here, so an import that dies halfway has
    really written half; re-running has to be the fix rather than the
    thing that doubles the desk's memory."""
    es = _ready()
    local = _local_with(tmp_path, [
        _record(i, "10.0.0.1", "h", NOW - timedelta(hours=i), "false_positive")
        for i in range(4)
    ])
    shared = _shared(es, tmp_path)

    first = migrate_to_shared(local, shared, writer="host-a")
    assert first[INVESTIGATIONS] == (4, 0, 0)
    second = migrate_to_shared(local, shared, writer="host-a")
    assert second[INVESTIGATIONS] == (0, 4, 0)
    assert len(shared.log(INVESTIGATIONS).records()) == 4


def test_migration_preserves_file_order_when_every_stamp_is_identical(tmp_path):
    """Order is the semantics: "the latest ruling per alert wins" is
    decided by write time in shared memory. Records sharing a timestamp
    — or carrying none — must not resolve by document id, which for an
    import is a content hash."""
    es = _ready()
    when = NOW.isoformat()
    rulings = [
        {"alert_id": "A", "human_verdict": v, "source": "thehive",
         "summary": None, "recorded_at": when}
        for v in ("false_positive", "true_positive", "false_positive")
    ]
    local = _local_with(tmp_path, [], rulings)
    shared = _shared(es, tmp_path)
    migrate_to_shared(local, shared, writer="host-a")

    imported = shared.log(DISPOSITIONS).records()
    assert [r["human_verdict"] for r in imported] == [
        "false_positive", "true_positive", "false_positive"
    ]
    store = AlertHistoryStore(backend=shared)
    assert store.dispositions()["A"]["human_verdict"] == "false_positive"


def test_migration_keeps_order_through_a_clock_that_stepped_back(tmp_path):
    es = _ready()
    rulings = [
        {"alert_id": "A", "human_verdict": "true_positive",
         "source": "thehive", "summary": None,
         "recorded_at": NOW.isoformat()},
        {"alert_id": "A", "human_verdict": "false_positive",
         "source": "thehive", "summary": None,
         "recorded_at": (NOW - timedelta(hours=3)).isoformat()},
    ]
    local = _local_with(tmp_path, [], rulings)
    shared = _shared(es, tmp_path)
    migrate_to_shared(local, shared, writer="host-a")
    assert [
        r["human_verdict"] for r in shared.log(DISPOSITIONS).records()
    ] == ["true_positive", "false_positive"]


def test_migration_copies_only_the_shared_ledgers(tmp_path):
    """What this desk autonomously closed, what it created in TheHive and
    where its watch loop is are not facts a second instance inherits."""
    es = _ready()
    local = _local_with(
        tmp_path,
        [_record(0, "10.0.0.1", "h", NOW, "false_positive")],
        closures=[{"alert_id": "A0", "reason": "r", "closed_at": _iso(0)}],
        created_alerts=[{"alert_id": "A0", "thehive_id": "~1",
                         "created_at": _iso(0)}],
        watch_progress=[{"alert_id": "A0", "doc_id": "d", "phase": "started",
                         "at": _iso(0)}],
    )
    shared = _shared(es, tmp_path)
    result = migrate_to_shared(local, shared, writer="host-a")

    assert set(result) == {INVESTIGATIONS, DISPOSITIONS}
    ledgers = {d["ledger"] for d in es.docs[INDEX].values()}
    assert ledgers == {INVESTIGATIONS}


def test_migration_claims_writerless_records_and_counts_them(tmp_path):
    """Importing a pre-writer history is the operator asserting those
    records are this desk's own — which is exactly what re-enables dedup
    and resume over them, so the count is reported rather than silent."""
    es = _ready()
    legacy = _record(0, "10.0.0.1", "h", NOW, "false_positive")
    del legacy["writer"]
    local = _local_with(tmp_path, [legacy])
    shared = _shared(es, tmp_path)

    imported, already, stamped = migrate_to_shared(
        local, shared, writer="host-a"
    )[INVESTIGATIONS]
    assert (imported, already, stamped) == (1, 0, 1)
    assert shared.log(INVESTIGATIONS).records()[0]["writer"] == "host-a"


def test_an_import_refreshes_once_rather_than_per_record(tmp_path):
    """`wait_for` per document turns a 50k-record history into hours.
    An import has no reader waiting on each write, so it pays one
    refresh at the end — but it must pay that one, or the imported
    records are invisible until something else forces a refresh."""
    es = _ready()
    local = _local_with(tmp_path, [
        _record(i, "10.0.0.1", "h", NOW, "false_positive") for i in range(5)
    ])
    shared = _shared(es, tmp_path)
    migrate_to_shared(local, shared, writer="host-a")

    creates = [r for r in es.requests if "_create" in r[1]]
    assert len(creates) == 5
    assert all("refresh=false" in r[1] for r in creates)
    assert es.refreshes == 1


def test_a_dry_run_reports_what_is_already_there(tmp_path):
    """A dry run that calls every record new is the opposite of what an
    operator checking on a half-finished import wants to read."""
    es = _ready()
    local = _local_with(tmp_path, [
        _record(i, "10.0.0.1", "h", NOW, "false_positive") for i in range(3)
    ])
    shared = _shared(es, tmp_path)
    migrate_to_shared(local, shared, writer="host-a")
    assert migrate_to_shared(
        local, shared, writer="host-a", dry_run=True
    )[INVESTIGATIONS] == (0, 3, 0)


def test_a_dry_run_writes_nothing(tmp_path):
    es = _ready()
    local = _local_with(
        tmp_path, [_record(0, "10.0.0.1", "h", NOW, "false_positive")]
    )
    shared = _shared(es, tmp_path)
    assert migrate_to_shared(
        local, shared, writer="host-a", dry_run=True
    )[INVESTIGATIONS] == (1, 0, 0)
    assert es.docs.get(INDEX, {}) == {}
    assert es.refreshes == 0


def test_migration_keeps_a_repeated_record_rather_than_collapsing_it(tmp_path):
    """A content hash alone would turn two byte-identical lines into one
    document, quietly changing how many records the desk has and
    reporting the copy it dropped as "already present"."""
    es = _ready()
    twice = {"alert_id": "A", "human_verdict": "false_positive",
             "source": "thehive", "summary": None,
             "recorded_at": NOW.isoformat()}
    local = _local_with(tmp_path, [], [dict(twice), dict(twice)])
    shared = _shared(es, tmp_path)

    assert migrate_to_shared(
        local, shared, writer="host-a"
    )[DISPOSITIONS] == (2, 0, 2)
    assert len(shared.log(DISPOSITIONS).records()) == 2
    # ...and re-running still imports nothing.
    assert migrate_to_shared(
        local, shared, writer="host-a"
    )[DISPOSITIONS] == (0, 2, 2)


# --- structural guards ------------------------------------------------------


def test_every_ledger_is_placed_deliberately_by_both_backends(tmp_path):
    """A ledger added later must be given a home in BOTH backends. Miss
    the shared one and it silently stays local — the desk believes it
    shares something it does not."""
    from soc_copilot.memory import LEDGERS, SHARED_LEDGERS

    local = JsonlBackend(tmp_path / "inv.jsonl")
    shared = _shared(_ready(), tmp_path)
    for ledger in LEDGERS:
        assert isinstance(local.log(ledger), JsonlLog)
        assert ledger in local.paths
        expected = ElasticLog if ledger in SHARED_LEDGERS else JsonlLog
        assert isinstance(shared.log(ledger), expected), ledger
        assert (ledger in shared.paths) is (ledger not in SHARED_LEDGERS)
    assert SHARED_LEDGERS <= set(LEDGERS)


def test_the_store_never_opens_a_file_itself():
    """Structural, because the failure is invisible: a write method that
    opens a path directly still works perfectly on a local desk and
    silently keeps a LOCAL copy of a ledger the shared desk believes it
    shares. Every write goes through a ledger or this fails."""
    import ast
    from pathlib import Path

    import soc_copilot.history as history_mod

    tree = ast.parse(Path(history_mod.__file__).read_text())
    banned = {"open", "write_text", "write_bytes", "mkdir"}
    offenders = [
        f"line {node.lineno}: {ast.unparse(node.func)}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id in banned)
            or (isinstance(node.func, ast.Attribute) and node.func.attr in banned)
        )
    ]
    assert offenders == [], (
        "soc_copilot/history.py touches the filesystem directly: "
        + "; ".join(offenders)
    )


def test_a_partially_failed_search_raises_instead_of_shortening_memory():
    """Elasticsearch answers a search whose shards partly failed with
    HTTP 200 and the hits it MANAGED to collect. Reading only `hits`
    turns a degraded cluster into a shorter ledger — the re-read stops
    matching the window held, the log rebuilds from the short answer, and
    the desk runs with memory it does not know is missing. The quiet
    direction, arriving as a green status code."""
    es = _ready()
    for i in range(3):
        es.put(INDEX, INVESTIGATIONS, {"alert_id": f"A{i}"}, written_at=_iso(i))
    log = _log(es)
    assert len(log.records()) == 3

    es.failed_shards = 1
    with pytest.raises(RuntimeError, match="partial search"):
        log.records()
    assert len(log._records) == 3         # nothing was thrown away


def test_a_timed_out_search_raises_too():
    es = _ready()
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "A"}, written_at=_iso(0))
    es.timed_out = True
    with pytest.raises(RuntimeError, match="partial search"):
        _log(es).records()


def test_migration_is_idempotent_across_a_change_of_instance_id(tmp_path):
    """The document id is derived from the record as it is IN THE FILE,
    so re-running after INSTANCE_ID changed collides with the first
    import rather than duplicating every legacy record under a new
    identity — while still reporting the claim it makes."""
    es = _ready()
    legacy = _record(0, "10.0.0.1", "h", NOW, "false_positive")
    del legacy["writer"]
    local = _local_with(tmp_path, [legacy])
    shared = _shared(es, tmp_path)

    assert migrate_to_shared(
        local, shared, writer="host-a"
    )[INVESTIGATIONS] == (1, 0, 1)
    assert migrate_to_shared(
        local, shared, writer="host-a-renamed"
    )[INVESTIGATIONS] == (0, 1, 1)
    assert len(shared.log(INVESTIGATIONS).records()) == 1


def test_a_desk_that_was_sharing_refuses_to_fall_back_to_local_files(tmp_path):
    """The mirror image of the cold-start refusal, and the same loss in
    the same direction — except HISTORY_BACKEND DEFAULTS to jsonl, so
    this one arrives by LOSING a line rather than adding one."""
    es = _ready()
    open_backend(_cfg(tmp_path), client=es.client())          # ran shared

    with pytest.raises(RuntimeError, match="last ran on shared memory"):
        open_backend(_cfg(tmp_path, HISTORY_BACKEND="jsonl"))

    (tmp_path / ".shared-memory").unlink()                    # on purpose
    assert open_backend(
        _cfg(tmp_path, HISTORY_BACKEND="jsonl")
    ).shared is False


def test_a_read_after_our_own_append_stays_one_windowed_page():
    """Invalidating the VIEW after an append must not throw away the
    CURSOR. Clearing the cursor makes the next read page the whole
    ledger instead of the lag window — a local index rebuild traded for
    a full re-materialize over the network, on every single append."""
    es = _ready()
    # Spread far enough apart that the lag window holds only the tail:
    # with everything inside the window, "re-read the window" and
    # "re-read the ledger" are the same query and prove nothing.
    for i in range(12):
        es.put(INDEX, INVESTIGATIONS, {"alert_id": f"A{i}"},
               written_at=_iso(-3600 * (12 - i)))
    log = _log(es, page_size=5, lag_seconds=60.0)
    assert len(log.records()) == 12
    assert es.searches == 3                # cold: three pages

    searches = es.searches
    log.append({"alert_id": "OURS"})
    assert [r["alert_id"] for r in log.records()][-1] == "OURS"
    assert es.searches - searches == 1     # the window, not the ledger


def test_a_document_with_an_unusable_sort_value_is_refused():
    """`_materialize`'s shape check: a hit the cluster sorted some other
    way cannot be spliced against a (written_at, uid) cursor."""
    es = _ready()
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "A"}, written_at=_iso(0))
    log = _log(es)

    real_search = log._search
    log._search = lambda body: [
        {**hit, "sort": [hit["sort"][0]]} for hit in real_search(body)
    ]
    with pytest.raises(RuntimeError, match="expected"):
        log.records()


def test_a_cluster_that_never_stops_paging_is_given_up_on():
    """The _MAX_PAGES backstop. Unreachable against a healthy cluster,
    which is exactly why it needs a test: a search_after that never
    advances is an infinite loop inside a store read."""
    es = _ready()
    log = _log(es, page_size=1)
    es.put(INDEX, INVESTIGATIONS, {"alert_id": "A"}, written_at=_iso(0))
    log._search = lambda body: [{
        "_id": "stuck", "sort": [0, "stuck"],
        "_source": {"record": {"alert_id": "STUCK"}},
    }]
    with pytest.raises(RuntimeError, match="without exhausting"):
        log.records()


def test_wait_for_is_what_makes_an_append_readable(monkeypatch):
    """Behavioural, not a URL assertion: with the cluster holding
    unrefreshed writes back — which is what a real one does — an append
    without `refresh=wait_for` is simply not there on the next read, and
    dedup's "has this really been investigated?" check answers NO about
    a record it just wrote."""
    es = _ready()
    es.require_refresh = True
    log = _log(es)
    log.records()
    log.append({"alert_id": "A"})
    assert [r["alert_id"] for r in log.records()] == ["A"]

    # And the import path, which deliberately does NOT wait, is invisible
    # until the single refresh at the end of a migration.
    other = _log(es, ledger=DISPOSITIONS)
    other.import_record({"alert_id": "B"}, "uid-b", NOW)
    assert other.records() == []
    other.refresh_index()
    assert [r["alert_id"] for r in other.records()] == [{"alert_id": "B"}["alert_id"]]

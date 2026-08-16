"""Unit tests for the alert-history store (cross-alert memory).

These are deterministic and make NO API calls — the store is pure Python, so
its logic is validated without touching Anthropic. Run:

    uv run pytest tests/test_history.py -v
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from soc_copilot.history import AlertHistoryStore, alert_iocs
from soc_copilot.models import Alert, Investigation


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
    corr = store.correlate(alert)
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
    corr = store.correlate(now)
    assert len(corr.related_alerts) == 1
    assert any(s.startswith("related_ip:") for s in corr.related_alerts[0].signals)


def test_correlation_related_via_shared_host(tmp_path):
    store = _store(tmp_path)
    store.record(
        _alert("A1", {}, _T - timedelta(hours=1), host="prod-web-02.internal"),
        _inv("A1"),
    )
    now = _alert("A2", {}, _T, host="prod-web-02.internal")
    corr = store.correlate(now)
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
    corr = store.correlate(now, ["T1566.002 - Spearphishing Link"])
    assert corr.related_alerts == []


def test_correlation_technique_corroborates_infra_link(tmp_path):
    store = _store(tmp_path)
    store.record(
        _alert("A1", {"ips": ["185.220.101.10"]}, _T - timedelta(hours=1)),
        _inv("A1", techniques=["T1110.001 - Password Guessing"]),
    )
    now = _alert("A2", {"ips": ["185.220.101.47"]}, _T)  # same /24
    corr = store.correlate(now, ["T1110.003 - Password Spraying"])
    signals = corr.related_alerts[0].signals
    assert any(s.startswith("related_ip:") for s in signals)
    assert "shared_technique:T1110" in signals

    # Pre-investigation (no techniques): same campaign, minus the corroborating
    # technique signal — proves is_campaign is technique-independent.
    pre = store.correlate(now)
    assert len(pre.related_alerts) == 1
    assert not any(
        s.startswith("shared_technique") for s in pre.related_alerts[0].signals
    )


def test_correlation_outside_window_excluded(tmp_path):
    store = _store(tmp_path)
    store.record(
        _alert("A1", {"ips": ["10.0.0.1"]}, _T - timedelta(hours=100)),
        _inv("A1"),
    )
    now = _alert("A2", {"ips": ["10.0.0.1"]}, _T)
    corr = store.correlate(now, window_hours=72)
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
    corr = store.correlate(now)
    assert corr.is_campaign is True
    assert len(corr.related_alerts) == 2
    assert "campaign" in corr.summary.lower()


def test_correlation_excludes_self(tmp_path):
    store = _store(tmp_path)
    alert = _alert("A1", {"ips": ["10.0.0.1"]}, _T, host="h1")
    store.record(alert, _inv("A1"))
    corr = store.correlate(alert)
    assert corr.related_alerts == []


def test_correlate_matches_host_across_native_and_ecs_shapes(tmp_path):
    """An ECS-normalized alert (host as {"name": ...}) and a native alert
    (host as a plain string) about the same machine must correlate —
    memory cannot depend on which ingestion path an alert arrived by.
    """
    store = _store(tmp_path)
    ecs = Alert(
        alert_id="E1",
        timestamp=_T - timedelta(hours=1),
        source="elastic",
        severity="high",
        title="ecs-shaped alert",
        raw_log={"host": {"name": "web-01.internal"}},
        indicators={"ips": ["203.0.113.9"]},
    )
    store.record(ecs, _inv("E1"))

    native = _alert(
        "N1", {"ips": ["198.51.100.7"]}, _T, host="web-01.internal"
    )
    corr = store.correlate(native)
    assert len(corr.related_alerts) == 1
    assert "shared_host:web-01.internal" in corr.related_alerts[0].signals


def test_closure_events_roundtrip_latest_wins(tmp_path):
    """Autonomous closures are desk facts the scorecard reads back; the
    sidecar mirrors dispositions: append-only, latest per alert wins."""
    from soc_copilot.history import AlertHistoryStore

    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    assert store.closures() == {}
    store.record_closure("A1", "clean FP")
    store.record_closure("A1", "re-closed after reopen")
    store.record_closure("A2", None)
    closures = store.closures()
    assert set(closures) == {"A1", "A2"}
    assert closures["A1"]["reason"] == "re-closed after reopen"
    assert closures["A2"]["reason"] is None
    assert "closed_at" in closures["A1"]


def test_created_alerts_ledger_roundtrip_latest_wins(tmp_path):
    """The provenance ledger for the feedback loop: latest thehive id per
    alert_id wins (a re-push updates it), and an empty file reads as {}."""
    from soc_copilot.history import AlertHistoryStore

    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    assert store.created_alerts() == {}
    store.record_created_alert("AL-1", "~obj-1")
    store.record_created_alert("AL-2", "~obj-2")
    store.record_created_alert("AL-1", "~obj-1b")   # re-push: latest wins
    ledger = store.created_alerts()
    assert ledger == {"AL-1": "~obj-1b", "AL-2": "~obj-2"}


def test_cache_serves_parsed_records_without_reparsing_unchanged_file(tmp_path):
    """The summary index: an unchanged file is parsed once, not per read.

    Identity of the returned list is the proof — a re-parse would build a
    new list. This is what keeps a long-running watch from re-reading its
    whole history O(alerts x records) times per poll cycle.
    """
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store.record(_alert("A1", {"ips": ["1.1.1.1"]}, when), _inv("A1"))

    first = store._records_cache.records()
    second = store._records_cache.records()
    assert first is second                       # cached, not re-parsed
    assert [r["alert_id"] for r in first] == ["A1"]


def test_cache_invalidates_on_append_from_same_store(tmp_path):
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store.record(_alert("A1", {"ips": ["1.1.1.1"]}, when), _inv("A1"))
    assert len(list(store._iter_records())) == 1

    store.record(_alert("A2", {"ips": ["2.2.2.2"]}, when), _inv("A2"))
    assert [r["alert_id"] for r in store._iter_records()] == ["A1", "A2"]


def test_cache_sees_writes_from_another_store_instance(tmp_path):
    """The cache key is file state (mtime_ns, size), not this process's
    write history — a cron --sync-feedback appending beside a running
    watch must be visible on the watch's next read."""
    path = tmp_path / "investigations.jsonl"
    reader = AlertHistoryStore(path)
    writer = AlertHistoryStore(path)
    assert list(reader._iter_records()) == []    # caches emptiness

    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    writer.record(_alert("A1", {"ips": ["1.1.1.1"]}, when), _inv("A1"))
    assert [r["alert_id"] for r in reader._iter_records()] == ["A1"]

    writer.record_disposition("A1", "false_positive", "thehive:case-1")
    assert reader.dispositions()["A1"]["human_verdict"] == "false_positive"


def test_cache_reparse_rebinds_so_inflight_iterators_keep_their_snapshot(tmp_path):
    """An iterator handed out before a write walks its own snapshot —
    a re-parse rebinds the cached list, never mutates it in place."""
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store.record(_alert("A1", {"ips": ["1.1.1.1"]}, when), _inv("A1"))

    it = store._iter_records()
    assert next(it)["alert_id"] == "A1"
    store.record(_alert("A2", {"ips": ["2.2.2.2"]}, when), _inv("A2"))
    store._records_cache.records()               # force the re-parse
    assert list(it) == []                        # old snapshot: exhausted


def test_appending_reparses_only_the_new_lines(tmp_path):
    """The whole point of the offset: the watch loop's last act on every
    alert is an append, so a cache that re-parsed on any write re-parsed
    the ENTIRE history once per alert — O(history) per alert, forever.
    Counting json.loads calls is the only honest proof it is incremental;
    an assertion on the returned records would pass either way."""
    import json as _json

    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(50):
        store.record(_alert(f"A{i}", {"ips": [f"10.0.0.{i}"]}, when), _inv(f"A{i}"))
    assert len(list(store._iter_records())) == 50   # warm: full parse done

    calls = 0
    real_loads = _json.loads

    def counting_loads(s, *a, **k):
        nonlocal calls
        calls += 1
        return real_loads(s, *a, **k)

    import soc_copilot.history as hist

    hist.json.loads = counting_loads
    try:
        store.record(_alert("NEW", {"ips": ["9.9.9.9"]}, when), _inv("NEW"))
        records = list(store._iter_records())
    finally:
        hist.json.loads = real_loads

    assert len(records) == 51
    assert records[-1]["alert_id"] == "NEW"
    assert calls == 1                    # the appended line ONLY, not 51


def _write_lines(path, ids):
    path.write_text("".join(f'{{"alert_id": "{i}"}}\n' for i in ids))


def test_a_truncated_or_rewritten_file_is_never_served_from_a_stale_prefix(
    tmp_path,
):
    """Incremental parsing trusts that the prefix it already read is still
    there. Every writer here appends, but if a file is truncated or
    rewritten the cache must start over rather than splice new bytes onto
    a prefix that no longer exists."""
    from soc_copilot.history import _CachedJsonl

    path = tmp_path / "records.jsonl"
    _write_lines(path, ["A1", "A2", "A3"])
    cache = _CachedJsonl(path)
    assert [r["alert_id"] for r in cache.records()] == ["A1", "A2", "A3"]

    # Rewritten shorter: the old prefix is gone.
    _write_lines(path, ["A1"])
    assert [r["alert_id"] for r in cache.records()] == ["A1"]

    # Rewritten AND grown: size alone reads as a plain append, so only
    # re-checking the prefix stops the new tail being grafted onto records
    # that no longer exist.
    _write_lines(path, ["ZZ", "B1"])
    assert [r["alert_id"] for r in cache.records()] == ["ZZ", "B1"]

    # A genuine append after all that still parses incrementally.
    with path.open("a") as f:
        f.write('{"alert_id": "B2"}\n')
    assert [r["alert_id"] for r in cache.records()] == ["ZZ", "B1", "B2"]


def test_a_replaced_file_is_not_spliced_onto_the_old_one(tmp_path):
    """A file swapped in by rename keeps a plausible size but is a
    different inode — splicing onto the old prefix would invent history."""
    path = tmp_path / "investigations.jsonl"
    store = AlertHistoryStore(path)
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store.record(_alert("OLD1", {"ips": ["1.1.1.1"]}, when), _inv("OLD1"))
    store.record(_alert("OLD2", {"ips": ["2.2.2.2"]}, when), _inv("OLD2"))
    assert len(list(store._iter_records())) == 2

    replacement = tmp_path / "other.jsonl"
    other = AlertHistoryStore(replacement)
    other.record(_alert("NEW1", {"ips": ["3.3.3.3"]}, when), _inv("NEW1"))
    other.record(_alert("NEW2", {"ips": ["4.4.4.4"]}, when), _inv("NEW2"))
    other.record(_alert("NEW3", {"ips": ["5.5.5.5"]}, when), _inv("NEW3"))
    replacement.replace(path)

    assert [r["alert_id"] for r in store._iter_records()] == [
        "NEW1", "NEW2", "NEW3",
    ]


def test_a_corrupt_line_fails_the_same_way_on_every_call(tmp_path):
    """A bad line must never degrade into SILENT truncation.

    Incremental parsing made this a live hazard: commit the new file state
    before the parse and the failed read advances the cache anyway, so the
    next call takes the fast path and returns a short list with no error at
    all. That is far worse than a loud error — `dispositions()` quietly
    losing an analyst ruling makes an overturned verdict read as
    unchallenged, which is exactly what this store promises can't happen.
    """
    from soc_copilot.history import _CachedJsonl

    path = tmp_path / "records.jsonl"
    _write_lines(path, ["A1", "A2"])
    cache = _CachedJsonl(path)
    assert [r["alert_id"] for r in cache.records()] == ["A1", "A2"]

    with path.open("a") as f:                    # a torn write, then a clean one
        f.write('{"alert_id": "A3"\n')
        f.write('{"alert_id": "A4"}\n')

    for _ in range(3):                           # loud, and loud EVERY time
        with pytest.raises(json.JSONDecodeError):
            cache.records()

    # ...and it recovers once the file is repaired, rather than staying stuck.
    _write_lines(path, ["A1", "A2", "A3", "A4"])
    assert [r["alert_id"] for r in cache.records()] == ["A1", "A2", "A3", "A4"]


def test_a_corrupt_line_never_reports_an_empty_history(tmp_path):
    """The reset branch is the nastier half: it clears the cache before
    parsing, so a failed whole-file re-parse could leave the store
    reporting NO history at all — with no error on the second call."""
    from soc_copilot.history import _CachedJsonl

    path = tmp_path / "records.jsonl"
    _write_lines(path, ["A1", "A2", "A3"])
    cache = _CachedJsonl(path)
    assert len(cache.records()) == 3

    path.write_text('{"alert_id": "B1"}\n{"alert_id": OOPS}\n')   # rewritten badly
    for _ in range(3):
        with pytest.raises(json.JSONDecodeError):
            cache.records()


def test_a_half_written_line_is_never_parsed(tmp_path):
    """Reading while a writer is mid-append must not raise: only bytes up
    to the last newline are consumed, and the record appears once the
    writer finishes its line."""
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store.record(_alert("A1", {"ips": ["1.1.1.1"]}, when), _inv("A1"))
    assert len(list(store._iter_records())) == 1

    torn = '{"alert_id": "A2", "verdict": "false_p'
    with store.path.open("a") as f:
        f.write(torn)
    assert [r["alert_id"] for r in store._iter_records()] == ["A1"]  # no crash

    with store.path.open("a") as f:                # writer completes it
        f.write('ositive", "timestamp": "x", "iocs": [], "duplicate_of": null}\n')
    assert [r["alert_id"] for r in store._iter_records()] == ["A1", "A2"]


def test_appending_rebinds_so_inflight_iterators_keep_their_snapshot(tmp_path):
    """The snapshot contract has to survive the incremental path too: an
    append extends the cache by REBINDING, never mutating in place, so an
    iterator handed out earlier cannot see records appended after it."""
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store.record(_alert("A1", {"ips": ["1.1.1.1"]}, when), _inv("A1"))

    it = store._iter_records()
    assert next(it)["alert_id"] == "A1"
    store.record(_alert("A2", {"ips": ["2.2.2.2"]}, when), _inv("A2"))
    store._records_cache.records()               # force the incremental parse
    assert list(it) == []                        # old snapshot: exhausted


def test_cache_handles_file_deletion_as_empty_store(tmp_path):
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store.record(_alert("A1", {"ips": ["1.1.1.1"]}, when), _inv("A1"))
    assert len(list(store._iter_records())) == 1

    store.path.unlink()
    assert list(store._iter_records()) == []
    # and a recreated file is picked up again (key was reset, not stuck)
    store.record(_alert("A3", {"ips": ["3.3.3.3"]}, when), _inv("A3"))
    assert [r["alert_id"] for r in store._iter_records()] == ["A3"]


# --- the watch-loop progress ledger -----------------------------------------

def _brute_progress(store, alert_id):
    """The obvious implementation: rebuild the whole latest-per-alert map
    every call. The incremental view must agree with it exactly."""
    out = {}
    for line in store.watch_progress_path.read_text().splitlines():
        rec = json.loads(line)
        out[rec["alert_id"]] = rec
    return out.get(alert_id)


def test_progress_ledger_records_the_latest_phase_per_alert(tmp_path):
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    assert store.watch_progress("A1") is None

    store.record_watch_progress("A1", "d1", "started")
    assert store.watch_progress("A1")["phase"] == "started"

    store.record_watch_progress("A1", "d1", "completed")
    assert store.watch_progress("A1")["phase"] == "completed"
    assert store.watch_progress("A1")["doc_id"] == "d1"

    # Append-only and last-wins: a re-opened alert simply starts again.
    store.record_watch_progress("A1", "d1", "started")
    assert store.watch_progress("A1")["phase"] == "started"


def test_progress_view_matches_a_full_rebuild_while_appending(tmp_path):
    """The view is folded incrementally (it is read once per alert per
    cycle, and rebuilding the whole map per call measured 6.9ms over a
    50k-alert ledger). Incremental means it can drift; this pins it to
    the brute rebuild across interleaved reads and writes, the same
    equivalence discipline the record index is held to."""
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    ids = [f"A{i}" for i in range(25)]
    for round_no in range(4):
        for alert_id in ids:
            phase = "started" if round_no % 2 == 0 else "completed"
            store.record_watch_progress(alert_id, f"d-{alert_id}", phase)
            # Read DURING the writes, not only at the end: a fold that
            # only ever ran once would pass an end-state-only check.
            assert store.watch_progress(alert_id) == _brute_progress(
                store, alert_id
            )
    for alert_id in ids + ["never-seen"]:
        assert store.watch_progress(alert_id) == _brute_progress(store, alert_id)


def test_progress_view_rebuilds_when_the_ledger_is_rotated(tmp_path):
    """Rotation (the supported offline history rotation) replaces the
    file. A view that kept folding onto a stale prefix would report
    alerts as in-flight that the new file has never heard of — and an
    alert wrongly believed in-flight is exactly what the resume path
    must never see."""
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    store.record_watch_progress("A1", "d1", "started")
    assert store.watch_progress("A1")["phase"] == "started"

    # Archived away and replaced with a different, shorter ledger.
    store.watch_progress_path.write_text(
        json.dumps({"alert_id": "B9", "doc_id": "d9", "phase": "started",
                    "at": "2026-06-01T12:00:00+00:00"}) + "\n"
    )
    assert store.watch_progress("A1") is None
    assert store.watch_progress("B9")["phase"] == "started"


def test_progress_ledger_ignores_malformed_lines(tmp_path):
    """A hand-edited or truncated ledger must not crash the watch loop:
    a line without an alert_id is skipped, and the alerts around it
    still resolve."""
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    store.record_watch_progress("A1", "d1", "started")
    with store.watch_progress_path.open("a") as f:
        f.write(json.dumps({"phase": "started"}) + "\n")       # no alert_id
        f.write(json.dumps(["not", "a", "dict"]) + "\n")
    store.record_watch_progress("A2", "d2", "completed")

    assert store.watch_progress("A1")["phase"] == "started"
    assert store.watch_progress("A2")["phase"] == "completed"


def test_progress_fold_advances_its_cursor_and_never_refolds(tmp_path):
    """The fold's COST, not its answer, is what this pins. Two mutants
    that make it O(history) per call — restarting the range at 0, or
    never advancing the cursor — produce byte-identical results, so no
    correctness test can reach them; the cursor is the only observable
    difference. Only the second is killable this way, and the first is
    left honestly unpinned: the fold's correctness is fully tested, its
    flatness rests on the recorded measurement (6.9ms -> 0.0013ms per
    read over a 50k-alert ledger) rather than on an assertion."""
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    for i in range(5):
        store.record_watch_progress(f"A{i}", "d", "started")

    store.watch_progress("A0")
    assert store._watch_progress_seen == 5      # folded everything once
    store.watch_progress("A0")
    assert store._watch_progress_seen == 5      # and nothing again

    store.record_watch_progress("A5", "d", "started")
    store.watch_progress("A5")
    assert store._watch_progress_seen == 6      # only the new line

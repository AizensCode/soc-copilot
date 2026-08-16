"""The store's query index (no API, no network).

The design rule under test: indexes only PRESELECT candidate rows, and
every reader re-applies its original per-record predicates — so the one
way an index can be WRONG is incompleteness (a candidate the full scan
would have found, missing). These tests hold the indexed readers equal
to brute-force reimplementations of the original full scans, over
randomized stores that mix well-formed records, raw hand-written lines
(pre-field shapes), duplicates, clock steps, and missing keys — then
re-check after appends, file replacement, and truncation, which is
where a stale index would first lie.

    uv run pytest tests/test_history_index.py -v
"""
import json
import random
from datetime import datetime, timedelta, timezone

from soc_copilot.dedup import _record_fingerprint, find_anchor, fingerprint
from soc_copilot.history import (
    DEFAULT_WINDOW_HOURS,
    AlertHistoryStore,
    _CachedJsonl,
    _ipv4s,
    _parent_tcodes,
    _same_24,
    alert_host,
    alert_iocs,
)
from soc_copilot.models import Alert, Investigation

_BASE = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)

# Third octets VARY so the pool contains same-/16-different-/24 pairs:
# a /24 check widened to /16 by a mutant must produce extra matches the
# brute reference rejects (review catch: an all-third-octet-zero pool
# made that mutant invisible).
_IPS = [f"10.{n}.{m}.{h}" for n in (1, 2) for m in (0, 1) for h in (5, 6, 7, 8)]
_DOMAINS = [f"evil{i}.example.com" for i in range(12)]
_HASHES = [f"{'ab' * 30}{i:04d}" for i in range(8)]
_POOL = _IPS + _DOMAINS + _HASHES
_HOSTS = [f"host-{i}" for i in range(6)]
# 10.1.0.42 as a JSON number — the shape a hand-imported record can
# carry, which ip_address() (and so the original _same_24 scan) accepts.
_INT_IOC = 10 * 2**24 + 1 * 2**16 + 0 * 2**8 + 42


def _alert(alert_id, iocs, host, ts):
    raw_log = {"host": host, "event": "probe"} if host else {"event": "probe"}
    return Alert(
        alert_id=alert_id, timestamp=ts, source="edr", severity="medium",
        title=f"alert {alert_id}", raw_log=raw_log,
        indicators={"iocs": iocs},
    )


def _inv(alert_id, verdict="false_positive", techniques=()):
    return Investigation(
        alert_id=alert_id, verdict=verdict, confidence="high",
        hypothesis="h", escalation_recommended=False,
        attack_techniques=list(techniques),
    )


def _populate(store: AlertHistoryStore, rng: random.Random, n: int) -> None:
    """Write n records: most through store.record() (fingerprint-able),
    some as raw JSONL lines with awkward shapes (missing keys, clock
    steps, duplicates) — the field the index has to be honest over."""
    store.path.parent.mkdir(parents=True, exist_ok=True)
    inv_at = _BASE
    for i in range(n):
        ts = _BASE + timedelta(hours=rng.uniform(-200, 200))
        inv_at += timedelta(minutes=rng.uniform(0.1, 3))
        if rng.random() < 0.05:
            inv_at -= timedelta(minutes=5)          # the clock stepped back
        alert_id = f"ALRT-{rng.randrange(int(n * 0.8) + 1)}"
        iocs = rng.sample(_POOL, rng.randrange(0, 4))
        host = rng.choice(_HOSTS + [None])
        if rng.random() < 0.7:
            a = _alert(alert_id, iocs, host, ts)
            v = rng.choice(["false_positive", "true_positive", "inconclusive"])
            store.record(a, _inv(alert_id, v, rng.sample(
                ["T1566.001", "T1059", "T1071.004"], rng.randrange(0, 2))))
            # store.record stamps investigated_at=now(); rewrite the line's
            # timestamp deterministically so windows are reproducible.
            _rewrite_last(store, inv_at)
        else:
            # A few records carry a NUMERIC alert_id (hand-imported
            # shape). Those get no IOCs/host: a numeric-id record that
            # MATCHED a query crashed PriorSighting construction in the
            # original scan too (equivalently), so they exist here to
            # exercise the id index — the overturn-join test owns the
            # behavioral pin.
            int_id = rng.random() < 0.06
            rec = {
                "alert_id": rng.randrange(1000) if int_id else alert_id,
                "timestamp": ts.isoformat(),
                "verdict": "false_positive",
                "confidence": "high",
                "title": f"raw {alert_id}",
            }
            if not int_id and rng.random() < 0.7:
                rec["iocs"] = (
                    iocs + [_INT_IOC] if rng.random() < 0.15 else iocs
                )
            if not int_id and host and rng.random() < 0.7:
                rec["host"] = host
            if rng.random() < 0.8:
                rec["investigated_at"] = inv_at.isoformat()
            if rng.random() < 0.3:
                rec["duplicate_of"] = f"ALRT-{rng.randrange(n)}"
            with store.path.open("a") as f:
                f.write(json.dumps(rec) + "\n")


def _rewrite_last(store: AlertHistoryStore, inv_at: datetime) -> None:
    lines = store.path.read_text().splitlines()
    rec = json.loads(lines[-1])
    rec["investigated_at"] = inv_at.isoformat()
    lines[-1] = json.dumps(rec)
    store.path.write_text("\n".join(lines) + "\n")


# --- brute-force references: the ORIGINAL full scans, verbatim --------------


def _brute_prior_sightings(store, alert):
    current = set(alert_iocs(alert))
    if not current:
        return []
    out, seen = [], set()
    for rec in store._iter_records():
        if rec["alert_id"] == alert.alert_id or rec["alert_id"] in seen:
            continue
        matched = sorted(current & set(rec.get("iocs", [])))
        if not matched:
            continue
        seen.add(rec["alert_id"])
        out.append(
            (rec["alert_id"], datetime.fromisoformat(rec["timestamp"]), matched)
        )
    out.sort(key=lambda s: s[1], reverse=True)
    return out


def _brute_correlate_ids(store, alert, techniques, window_hours):
    current_iocs = set(alert_iocs(alert))
    current_ips = _ipv4s(list(current_iocs))
    current_host = alert_host(alert)
    current_techs = _parent_tcodes(techniques or [])
    window = timedelta(hours=window_hours)
    related, seen = [], set()
    for rec in store._iter_records():
        if rec["alert_id"] == alert.alert_id or rec["alert_id"] in seen:
            continue
        rec_time = datetime.fromisoformat(rec["timestamp"])
        if abs(alert.timestamp - rec_time) > window:
            continue
        rec_iocs = set(rec.get("iocs", []))
        signals = [f"shared_ioc:{s}" for s in sorted(current_iocs & rec_iocs)]
        rec_ips = _ipv4s(list(rec_iocs))
        for a in current_ips:
            for b in rec_ips:
                if _same_24(a, b):
                    signals.append(f"related_ip:{b}/24")
        rec_host = rec.get("host")
        if current_host and rec_host and current_host == rec_host:
            signals.append(f"shared_host:{current_host}")
        if not signals:
            continue
        for code in sorted(
            current_techs & _parent_tcodes(rec.get("attack_techniques", []))
        ):
            signals.append(f"shared_technique:{code}")
        seen.add(rec["alert_id"])
        related.append((rec["alert_id"], rec_time, tuple(signals)))
    related.sort(key=lambda r: r[1], reverse=True)
    return related


def _brute_find_anchor(store, alert, window_hours, now):
    cutoff = now - timedelta(hours=window_hours)
    fp = fingerprint(alert)
    anchor, anchor_at = None, None
    for rec in store._iter_records():
        if rec["alert_id"] == alert.alert_id or rec.get("duplicate_of"):
            continue
        investigated_at = rec.get("investigated_at")
        if not investigated_at:
            continue
        when = datetime.fromisoformat(investigated_at)
        if when < cutoff:
            continue
        if _record_fingerprint(rec) != fp:
            continue
        anchor, anchor_at = rec, when
    if anchor is None:
        return None, 0
    suppressions = 0
    for rec in store._iter_records():
        if not rec.get("duplicate_of"):
            continue
        investigated_at = rec.get("investigated_at")
        if not investigated_at:
            continue
        if datetime.fromisoformat(investigated_at) < anchor_at:
            continue
        if _record_fingerprint(rec) == fp:
            suppressions += 1
    return anchor, suppressions


def _probes(rng):
    """Alerts chosen to exercise every candidate path: exact-IOC overlap,
    /24 adjacency only (a NEW ip in an indexed net), an int-IOC's /24,
    host-only overlap, everything-at-once, and no overlap at all."""
    return [
        _alert("PROBE-ioc", rng.sample(_POOL, 3), None, _BASE),
        _alert("PROBE-net", ["10.2.0.99"], None, _BASE),     # /24 neighbor only
        _alert("PROBE-intnet", ["10.1.0.200"], None, _BASE), # int IOC's /24
        _alert("PROBE-host", ["203.0.113.7"], rng.choice(_HOSTS), _BASE),
        _alert("PROBE-all", rng.sample(_IPS, 2) + ["10.2.1.250"],
               rng.choice(_HOSTS), _BASE + timedelta(hours=30)),
        _alert("PROBE-none", ["198.51.100.1"], None, _BASE),
        _alert("PROBE-empty", [], None, _BASE),
    ]


def _assert_equivalent(store, rng):
    """Hold indexed == brute-force for every probe, and COUNT what
    matched by signal kind — an equivalence where both sides return []
    proves nothing, so callers assert the counts are non-trivial
    (review catch: the assertion could have gone vacuous silently)."""
    counts = {"sightings": 0, "shared_ioc": 0, "related_ip": 0,
              "shared_host": 0}
    for probe in _probes(rng):
        got_s = [
            (s.alert_id, s.timestamp, s.matched_iocs)
            for s in store.prior_sightings(probe)
        ]
        assert got_s == _brute_prior_sightings(store, probe), probe.alert_id
        counts["sightings"] += len(got_s)
        got = store.correlate(probe, ["T1566.002"], DEFAULT_WINDOW_HOURS)
        got_c = [
            (r.alert_id, r.timestamp, tuple(r.signals))
            for r in got.related_alerts
        ]
        assert got_c == _brute_correlate_ids(
            store, probe, ["T1566.002"], DEFAULT_WINDOW_HOURS
        ), probe.alert_id
        for _, _, signals in got_c:
            for sig in signals:
                kind = sig.split(":", 1)[0]
                if kind in counts:
                    counts[kind] += 1
    return counts


def test_indexed_readers_equal_the_full_scans_across_seeds(tmp_path):
    totals = {"sightings": 0, "shared_ioc": 0, "related_ip": 0,
              "shared_host": 0}
    for seed in (1, 7, 42):
        store = AlertHistoryStore(tmp_path / f"s{seed}" / "inv.jsonl")
        _populate(store, random.Random(seed), 120)
        for kind, n in _assert_equivalent(store, random.Random(seed + 1)).items():
            totals[kind] += n
    # Every signal kind actually occurred — the equivalence bit on
    # something, each candidate path included.
    assert all(n > 0 for n in totals.values()), totals


def test_find_anchor_equals_the_full_scan(tmp_path):
    rng = random.Random(3)
    store = AlertHistoryStore(tmp_path / "inv.jsonl")
    _populate(store, rng, 120)
    # Probe with the same shape as a recorded alert -> same fingerprint;
    # 'now' near the end of the deterministic investigated_at ramp keeps
    # a real window boundary inside the data. EVERY eligible twin is
    # compared (review catch: an unconditional break reduced this test
    # to a single probe), and the tallies prove both outcomes occurred.
    compared = anchored = empty = 0
    now = _BASE + timedelta(minutes=400)
    for rec in list(store._iter_records())[-60:]:
        raw = rec.get("alert")
        if not raw:
            continue
        twin = Alert(**{**raw, "alert_id": "PROBE-twin"})
        # Window 24h spans the whole generated ramp (anchored outcome);
        # window 1h ends ~2.5h before `now` (empty outcome) — both sides
        # of the bisect boundary are exercised for every twin.
        for window_hours in (24, 1):
            got = find_anchor(store, twin, window_hours, now=now)
            want = _brute_find_anchor(store, twin, window_hours, now)
            assert (got[0] is None) == (want[0] is None)
            if got[0] is not None:
                assert got[0]["alert_id"] == want[0]["alert_id"]
                assert got[0] is want[0]    # same record object, not a copy
                anchored += 1
            else:
                empty += 1
            assert got[1] == want[1]
            compared += 1
    assert compared >= 40 and anchored > 0 and empty > 0, (
        compared, anchored, empty,
    )


def test_equivalence_survives_appends_replacement_and_truncation(tmp_path):
    rng = random.Random(11)
    store = AlertHistoryStore(tmp_path / "inv.jsonl")
    _populate(store, rng, 60)
    _assert_equivalent(store, random.Random(12))     # index is now warm

    _populate(store, rng, 30)                        # append after indexing
    _assert_equivalent(store, random.Random(12))

    # Rotation: an entirely different file under the same name.
    store.path.unlink()
    _populate(store, random.Random(99), 40)
    _assert_equivalent(store, random.Random(12))

    # Truncation: keep a strict prefix — the tail-verify resets the cache,
    # the generation bump must reset the index with it.
    lines = store.path.read_text().splitlines()
    store.path.write_text("\n".join(lines[:10]) + "\n")
    _assert_equivalent(store, random.Random(12))


def test_generation_bumps_on_reset_never_on_append(tmp_path):
    path = tmp_path / "x.jsonl"
    cache = _CachedJsonl(path)
    assert cache.records() == []
    path.write_text('{"alert_id": "A"}\n')
    cache.records()
    g = cache.generation
    with path.open("a") as f:
        f.write('{"alert_id": "B"}\n')
    cache.records()
    assert cache.generation == g                     # append: same prefix
    path.write_text('{"alert_id": "C"}\n')           # rewrite: new content
    assert [r["alert_id"] for r in cache.records()] == ["C"]
    assert cache.generation > g                      # reset announced


def test_rows_since_bisect_respects_a_clock_step_back(tmp_path):
    """A record written after a clock step carries an EARLIER
    investigated_at than its predecessor. The bisect runs over the
    cumulative max, so the window start can never land past such a row —
    it must still be found by find_anchor's exact filter."""
    store = AlertHistoryStore(tmp_path / "inv.jsonl")
    t = _BASE
    a1 = _alert("A1", ["10.1.0.5"], "host-1", t)
    store.record(a1, _inv("A1"))
    _rewrite_last(store, t + timedelta(minutes=10))
    a2 = _alert("A2", ["10.1.0.5"], "host-1", t)     # same fingerprint shape
    store.record(a2, _inv("A2"))
    _rewrite_last(store, t + timedelta(minutes=4))   # stepped BACK before A1
    index = store._index()
    # Preselect from just after A1's stamp must still include the
    # stepped-back row (cummax holds it at A1's time).
    assert index.rows_since(t + timedelta(minutes=5)) <= 1

    twin = Alert(**{**a2.model_dump(mode="json"), "alert_id": "PROBE"})
    now = t + timedelta(minutes=20)
    got = find_anchor(store, twin, 24, now=now)
    want = _brute_find_anchor(store, twin, 24, now)
    assert got[0] is not None and got[0]["alert_id"] == want[0]["alert_id"]


def test_latest_record_and_has_real_record_use_the_id_index(tmp_path):
    from soc_copilot.dedup import _has_real_record

    store = AlertHistoryStore(tmp_path / "inv.jsonl")
    a = _alert("A1", ["10.1.0.5"], "host-1", _BASE)
    store.record(a, _inv("A1", "inconclusive"))
    store.record(a, _inv("A1", "false_positive"))    # later record wins
    assert store.latest_record("A1")["verdict"] == "false_positive"
    assert store.latest_record("NOPE") is None
    assert _has_real_record(store, "A1") is True
    assert _has_real_record(store, "NOPE") is False
    # A duplicate-only id is not a REAL record.
    dup = {"alert_id": "D1", "duplicate_of": "A1"}
    with store.path.open("a") as f:
        f.write(json.dumps(dup) + "\n")
    assert _has_real_record(store, "D1") is False


def test_naive_ancient_timestamp_no_longer_crashes_the_window_scan(tmp_path):
    """A hand-imported record with a NAIVE investigated_at used to raise
    TypeError inside find_anchor (naive vs aware comparison) on every
    cycle. Indexed as UTC, an ancient one now sits before the window
    start and is skipped; only an in-window naive row still surfaces the
    original error. Deliberate, documented divergence."""
    store = AlertHistoryStore(tmp_path / "inv.jsonl")
    ancient = {
        "alert_id": "OLD", "timestamp": "2020-01-01T00:00:00+00:00",
        "investigated_at": "2020-01-01T00:00:00",    # naive!
    }
    with store.path.open("a") as f:
        f.write(json.dumps(ancient) + "\n")
    a = _alert("NEW", ["10.1.0.5"], None, _BASE)
    store.record(a, _inv("NEW"))
    twin = Alert(**{**a.model_dump(mode="json"), "alert_id": "PROBE"})
    got, _ = find_anchor(
        store, twin, 24, now=_BASE + timedelta(minutes=5)
    )
    assert got is not None and got["alert_id"] == "NEW"


# --- the review's catches, pinned individually -------------------------------


def test_net24_is_a_24_over_the_readers_whole_domain():
    """/24, not /16 (the mutant an all-third-octet-zero pool hid), and
    the same input domain as the readers' predicates: ip_address()
    accepts ints, so _net24 must too — building the network from the
    raw value crashed correlate on hand-imported numeric IOCs the
    original _same_24 scan handled (review catch)."""
    from soc_copilot.history import _net24

    assert _net24("10.1.0.5") == "10.1.0.0"
    assert _net24("10.1.1.5") == "10.1.1.0"      # /16 mutant collides these
    assert _net24(_INT_IOC) == "10.1.0.0"        # int form, dotted-quad key
    assert _net24("evil.example.com") is None
    assert _net24("2001:db8::1") is None
    assert _net24(None) is None
    assert _net24([1, 2]) is None


def test_numeric_ioc_records_correlate_exactly_as_the_full_scan_did(tmp_path):
    """Both review-confirmed failure shapes, end to end: the record
    whose ONLY link is the int IOC's /24 (it silently vanished from the
    candidates), and the record reachable via host whose rec_nets
    computation crashed correlate outright."""
    store = AlertHistoryStore(tmp_path / "inv.jsonl")
    store.path.parent.mkdir(parents=True, exist_ok=True)
    rec = {
        "alert_id": "IMPORTED-1",
        "timestamp": _BASE.isoformat(),
        "verdict": "false_positive", "confidence": "high",
        "title": "hand-imported", "host": "host-1",
        "iocs": [_INT_IOC],
    }
    with store.path.open("a") as f:
        f.write(json.dumps(rec) + "\n")

    only_net = _alert("P1", ["10.1.0.9"], None, _BASE)       # /24-only link
    via_host = _alert("P2", ["203.0.113.9"], "host-1", _BASE)
    results = {}
    for probe in (only_net, via_host):
        got = store.correlate(probe, None, DEFAULT_WINDOW_HOURS)
        want = _brute_correlate_ids(store, probe, None, DEFAULT_WINDOW_HOURS)
        assert [
            (r.alert_id, r.timestamp, tuple(r.signals))
            for r in got.related_alerts
        ] == want, probe.alert_id
        assert want and want[0][0] == "IMPORTED-1"           # not vacuous
        results[probe.alert_id] = got
    assert (f"related_ip:{_INT_IOC}/24"
            in results["P1"].related_alerts[0].signals)


def test_overturn_block_joins_rulings_on_non_string_alert_ids(tmp_path):
    """The analyst-overturn block joined rulings to records via a plain
    dict lookup, which matches numeric ids; a string-only id index
    silently skipped exactly that join — and a suppression the analyst
    had overturned went through (review catch, dedup-safety)."""
    from soc_copilot.dedup import _fingerprint_overturned, fingerprint

    store = AlertHistoryStore(tmp_path / "inv.jsonl")
    a = _alert("ANCHOR", ["10.1.0.5"], "host-1", _BASE)
    store.record(a, _inv("ANCHOR"))
    # Hand-edit the record's TOP-LEVEL alert_id to a JSON number (the
    # embedded alert dump keeps the fingerprint intact) and rule it.
    lines = store.path.read_text().splitlines()
    rec = json.loads(lines[-1])
    rec["alert_id"] = 5
    store.path.write_text("\n".join(lines[:-1] + [json.dumps(rec)]) + "\n")
    with store.dispositions_path.open("a") as f:
        f.write(json.dumps({"alert_id": 5, "human_verdict": "true_positive"})
                + "\n")
    assert _fingerprint_overturned(store, fingerprint(a)) == 5


def test_memo_dies_with_the_generation(tmp_path):
    """Fingerprints are memoized BY ROW NUMBER; after a rotation the
    same row number names a different record, so a surviving memo would
    hand dedup a wrong anchor — the memo must die with the generation
    (review catch: deleting the clear passed the whole suite)."""
    store = AlertHistoryStore(tmp_path / "inv.jsonl")
    a = _alert("A1", ["10.1.0.5"], "host-1", _BASE)
    store.record(a, _inv("A1"))
    now = _BASE + timedelta(minutes=5)
    twin_a = Alert(**{**a.model_dump(mode="json"), "alert_id": "PA"})
    got, _ = find_anchor(store, twin_a, 24, now=now)
    assert got is not None and got["alert_id"] == "A1"       # memo is warm

    # Rotate: a DIFFERENT record now occupies row 0. The replacement
    # must differ in LENGTH: a same-size same-tail rewrite on a reused
    # inode legitimately passes the cache's O(1) prefix check (its
    # documented probabilistic limit — the supported rotation is
    # offline), and this test pins the memo, not that limit.
    store.path.unlink()
    b = _alert("B1", ["10.2.0.5"], "host-2", _BASE)
    binv = Investigation(
        alert_id="B1", verdict="false_positive", confidence="high",
        hypothesis="an entirely different, deliberately longer hypothesis",
        escalation_recommended=False,
    )
    store.record(b, binv)
    got, _ = find_anchor(store, twin_a, 24, now=now)
    assert got is None                       # A's fingerprint matches nothing
    twin_b = Alert(**{**b.model_dump(mode="json"), "alert_id": "PB"})
    got, _ = find_anchor(store, twin_b, 24, now=now)
    assert got is not None and got["alert_id"] == "B1"


def test_correlate_ts_fallback_fails_as_loudly_as_the_scan_did(tmp_path):
    """A candidate record with a garbage timestamp indexes as ts=None
    and must then fail through the ORIGINAL fromisoformat expression —
    deleting the fallback would swap the scan's loud ValueError for a
    silent skip or a TypeError (review catch: branch was untested)."""
    import pytest

    store = AlertHistoryStore(tmp_path / "inv.jsonl")
    store.path.parent.mkdir(parents=True, exist_ok=True)
    rec = {"alert_id": "BAD-TS", "timestamp": "not-a-date",
           "iocs": ["10.1.0.5"]}
    with store.path.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    probe = _alert("P", ["10.1.0.5"], None, _BASE)
    with pytest.raises(ValueError):
        store.correlate(probe, None, DEFAULT_WINDOW_HOURS)
    with pytest.raises(ValueError):
        _brute_correlate_ids(store, probe, None, DEFAULT_WINDOW_HOURS)


def test_a_malformed_line_degrades_to_an_unindexed_row_not_a_crash(tmp_path):
    """One bad line must not crash EVERY indexed reader at build time
    (the full scans crashed only the queries that touched the record —
    the index must not widen that blast radius). A non-dict line and a
    non-iterable iocs value both index as nothing; unrelated queries
    keep working, and the parallel arrays stay aligned with rows."""
    store = AlertHistoryStore(tmp_path / "inv.jsonl")
    store.path.parent.mkdir(parents=True, exist_ok=True)
    with store.path.open("a") as f:
        f.write(json.dumps([1, 2, 3]) + "\n")            # non-dict line
        f.write(json.dumps({"alert_id": "N1", "iocs": 5}) + "\n")
    a = _alert("A1", ["10.1.0.5"], "host-1", _BASE)
    store.record(a, _inv("A1"))
    assert store.latest_record("A1")["alert_id"] == "A1"
    sightings = store.prior_sightings(
        _alert("P", ["10.1.0.5"], None, _BASE)
    )
    assert [s.alert_id for s in sightings] == ["A1"]
    index = store._index()
    assert len(index.ts) == len(index.inv_cummax) == len(index.rows) == 3


def test_a_raising_add_never_double_indexes_on_retry(tmp_path, monkeypatch):
    """Defense in depth for sync()'s per-row commit: _add is total over
    JSON shapes today, but if it EVER raises mid-batch, the retry must
    resume after the rows that succeeded — a per-batch commit re-indexed
    them, duplicating postings and misaligning the parallel arrays
    (review catch). The fault is injected, since no real input can
    trigger it anymore."""
    import pytest

    from soc_copilot.history import _RecordIndex

    store = AlertHistoryStore(tmp_path / "inv.jsonl")
    for i in range(3):
        store.record(_alert(f"A{i}", ["10.1.0.5"], "host-1", _BASE),
                     _inv(f"A{i}"))

    real_add = _RecordIndex._add
    calls = {"n": 0}

    def flaky_add(self, row, rec):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("injected mid-batch failure")
        return real_add(self, row, rec)

    monkeypatch.setattr(_RecordIndex, "_add", flaky_add)
    with pytest.raises(RuntimeError):
        store._index()
    monkeypatch.setattr(_RecordIndex, "_add", real_add)

    index = store._index()                       # the retry
    assert len(index.ts) == len(index.inv_cummax) == len(index.rows) == 3
    assert all(
        rows == sorted(set(rows)) for rows in index.ioc_rows.values()
    ), index.ioc_rows

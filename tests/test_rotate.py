"""Unit tests for history rotation (no API, no network).

Rotation is the only operation in this repo that REMOVES data from the
live store, so the properties worth pinning are conservative ones: that
nothing is deleted, that a record whose age cannot be established is
never aged out, that the two files the safety gates read are held back
unless asked for, and that a concurrent writer aborts the whole thing
rather than silently losing the records it wrote.

    uv run pytest tests/test_rotate.py -v
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from soc_copilot.history import AlertHistoryStore
from soc_copilot.rotate import (
    DEFAULT_RETENTION_DAYS,
    ConcurrentWriteError,
    apply_rotation,
    plan_rotation,
)

_NOW = datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc)


def _store(tmp_path) -> AlertHistoryStore:
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    store.path.parent.mkdir(parents=True, exist_ok=True)
    return store


def _write(path, records) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


def _aged(days: int) -> str:
    return (_NOW - timedelta(days=days)).isoformat()


def _investigations(store, ages) -> None:
    _write(store.path, [
        {"alert_id": f"A{i}", "investigated_at": _aged(d), "verdict": "benign"}
        for i, d in enumerate(ages)
    ])


# --- the plan ---------------------------------------------------------------

def test_records_split_at_the_cutoff(tmp_path):
    store = _store(tmp_path)
    _investigations(store, [200, 150, 100, 30, 5, 0])

    plan = plan_rotation(store, retention_days=90, now=_NOW)

    [fp] = plan.files
    assert len(fp.archived) == 3        # 200, 150, 100 days old
    assert len(fp.retained) == 3        # 30, 5, 0
    assert plan.cutoff == _NOW - timedelta(days=90)


def test_a_record_whose_age_is_unknown_is_never_aged_out(tmp_path):
    """Aging a record out requires knowing it is old. A malformed line, or
    one from before investigated_at existed (the dev store has 22 of
    those), establishes nothing except that something upstream wrote a
    line this module does not understand — so it stays, and is counted."""
    store = _store(tmp_path)
    store.path.write_text(
        json.dumps({"alert_id": "OLD", "investigated_at": _aged(300)}) + "\n"
        + json.dumps({"alert_id": "NO-FIELD"}) + "\n"
        + json.dumps({"alert_id": "BAD-TIME", "investigated_at": "whenever"}) + "\n"
        + json.dumps({"alert_id": "NULL-TIME", "investigated_at": None}) + "\n"
        + "{not json at all\n"
        + json.dumps(["not", "a", "dict"]) + "\n"
    )

    [fp] = plan_rotation(store, retention_days=90, now=_NOW).files

    assert len(fp.archived) == 1
    assert fp.unclassifiable == 5
    assert len(fp.retained) == 5


def test_blank_lines_are_dropped_rather_than_counted(tmp_path):
    store = _store(tmp_path)
    store.path.write_text(
        json.dumps({"alert_id": "A", "investigated_at": _aged(300)}) + "\n"
        "\n   \n"
        + json.dumps({"alert_id": "B", "investigated_at": _aged(1)}) + "\n"
    )
    [fp] = plan_rotation(store, retention_days=90, now=_NOW).files
    assert (len(fp.archived), len(fp.retained), fp.unclassifiable) == (1, 1, 0)


def test_a_naive_timestamp_is_read_as_utc(tmp_path):
    store = _store(tmp_path)
    naive = (_NOW - timedelta(days=300)).replace(tzinfo=None).isoformat()
    _write(store.path, [{"alert_id": "A", "investigated_at": naive}])

    [fp] = plan_rotation(store, retention_days=90, now=_NOW).files
    assert len(fp.archived) == 1        # compared, not crashed


def test_each_file_is_split_on_its_own_timestamp_field(tmp_path):
    """The five files stamp different keys — there is no shared
    "timestamp". Reading the wrong one would make every record
    unclassifiable and rotation a very quiet no-op."""
    store = _store(tmp_path)
    _investigations(store, [300, 1])
    _write(store.closures_path, [
        {"alert_id": "A", "closed_at": _aged(300), "reason": "fp"},
        {"alert_id": "B", "closed_at": _aged(1), "reason": "fp"},
    ])
    _write(store.watch_progress_path, [
        {"alert_id": "A", "phase": "completed", "at": _aged(300)},
        {"alert_id": "B", "phase": "completed", "at": _aged(1)},
    ])

    plan = plan_rotation(store, retention_days=90, now=_NOW)

    assert {f.name for f in plan.files} == {
        "investigations.jsonl", "closures.jsonl", "watch_progress.jsonl",
    }
    for fp in plan.files:
        assert (len(fp.archived), fp.unclassifiable) == (1, 0), fp.name


def test_missing_and_empty_files_are_skipped_not_crashed(tmp_path):
    store = _store(tmp_path)
    _investigations(store, [300])
    store.closures_path.write_text("")          # exists, empty
    # watch_progress.jsonl never created at all

    plan = plan_rotation(store, retention_days=90, now=_NOW)
    assert [f.name for f in plan.files] == ["investigations.jsonl"]


def test_a_file_with_nothing_old_enough_is_not_rotated(tmp_path):
    """Only files that would actually move appear in the plan, so an
    operator reading the report sees the work, not the inventory."""
    store = _store(tmp_path)
    _investigations(store, [10, 5, 1])
    assert plan_rotation(store, retention_days=90, now=_NOW).files == []


# --- the asymmetry: what is deliberately held back --------------------------

def test_analyst_rulings_and_provenance_are_held_back_by_default(tmp_path):
    """The two files that fail the OTHER way. A disposition is what
    closure.py reads to REFUSE an autonomous close after a human
    overturned the copilot; archive it and the desk becomes more willing
    to close what a human already called real. created_alerts is what
    lets a synced ruling be trusted at all. Both grow at human speed, so
    there is no operational reason to trim them and one very good reason
    not to."""
    store = _store(tmp_path)
    _investigations(store, [300])
    _write(store.dispositions_path, [
        {"alert_id": "A", "human_verdict": "true_positive",
         "recorded_at": _aged(300)},
    ])
    _write(store.created_alerts_path, [
        {"alert_id": "A", "thehive_id": "TH-1", "created_at": _aged(300)},
    ])

    plan = plan_rotation(store, retention_days=90, now=_NOW)

    assert [f.name for f in plan.files] == ["investigations.jsonl"]
    # And it SAYS so, naming the cost — silence would let an operator
    # believe a retention policy had been applied to these files.
    assert len(plan.held_back) == 2
    joined = " ".join(plan.held_back)
    assert "dispositions.jsonl" in joined and "created_alerts.jsonl" in joined
    assert "overturned" in joined and "provenance" in joined


def test_human_records_rotate_only_when_asked_for_explicitly(tmp_path):
    store = _store(tmp_path)
    _investigations(store, [300])
    _write(store.dispositions_path, [
        {"alert_id": "A", "human_verdict": "true_positive",
         "recorded_at": _aged(300)},
    ])
    _write(store.created_alerts_path, [
        {"alert_id": "A", "thehive_id": "TH-1", "created_at": _aged(300)},
    ])

    plan = plan_rotation(
        store, retention_days=90, now=_NOW, include_human_records=True,
    )

    assert {f.name for f in plan.files} == {
        "investigations.jsonl", "dispositions.jsonl", "created_alerts.jsonl",
    }
    assert plan.held_back == []          # nothing withheld, nothing to warn


def test_held_back_notes_name_only_files_that_exist(tmp_path):
    """A warning about a file the operator does not have is noise."""
    store = _store(tmp_path)
    _investigations(store, [300])
    _write(store.dispositions_path, [
        {"alert_id": "A", "recorded_at": _aged(300)},
    ])
    plan = plan_rotation(store, retention_days=90, now=_NOW)
    assert len(plan.held_back) == 1
    assert "dispositions.jsonl" in plan.held_back[0]


# --- applying it ------------------------------------------------------------

def test_rotation_moves_records_and_deletes_nothing(tmp_path):
    store = _store(tmp_path)
    _investigations(store, [300, 200, 10, 1])
    before = store.path.read_text().splitlines()

    plan = plan_rotation(store, retention_days=90, now=_NOW)
    archive = apply_rotation(plan)

    live = store.path.read_text().splitlines()
    archived = (archive / "investigations.jsonl").read_text().splitlines()
    # Every original line is in exactly one of the two, in original order.
    assert archived + live == before
    assert len(archived) == 2 and len(live) == 2


def test_the_store_reads_correctly_after_rotation(tmp_path):
    """The caches carry a generation counter for exactly this: the file
    shrank, so the already-parsed prefix is no longer what the file says
    and everything must be re-read."""
    store = _store(tmp_path)
    _write(store.watch_progress_path, [
        {"alert_id": "OLD", "phase": "completed", "at": _aged(300)},
        {"alert_id": "NEW", "phase": "started", "at": _aged(1)},
    ])
    assert store.watch_progress("OLD")["phase"] == "completed"   # warm cache

    apply_rotation(plan_rotation(store, retention_days=90, now=_NOW))

    assert store.watch_progress("OLD") is None       # rotated away
    assert store.watch_progress("NEW")["phase"] == "started"


def test_a_file_left_empty_by_rotation_is_written_empty_not_removed(tmp_path):
    """An empty file and a missing one are different states to every
    reader in the store; rotation must not turn one into the other."""
    store = _store(tmp_path)
    _investigations(store, [300, 200])

    apply_rotation(plan_rotation(store, retention_days=90, now=_NOW))

    assert store.path.exists()
    assert store.path.read_text() == ""


def test_the_archive_is_written_before_any_live_file_is_replaced(tmp_path):
    """Order is the safety argument: a crash between the two leaves an
    archive nobody acted on, never a truncated history."""
    store = _store(tmp_path)
    _investigations(store, [300])
    _write(store.closures_path, [{"alert_id": "A", "closed_at": _aged(300)}])
    plan = plan_rotation(store, retention_days=90, now=_NOW)

    seen: list[tuple[str, bool]] = []
    real_replace = __import__("os").replace

    def spy(src, dst):
        # At every replace, the whole archive must already be on disk.
        seen.append((
            str(dst),
            all((plan.archive_dir / f.name).exists() for f in plan.files),
        ))
        return real_replace(src, dst)

    import soc_copilot.rotate as rotate_mod

    original = rotate_mod.os.replace
    rotate_mod.os.replace = spy
    try:
        apply_rotation(plan)
    finally:
        rotate_mod.os.replace = original

    assert len(seen) == 2
    assert all(archive_complete for _, archive_complete in seen)


def test_a_concurrent_writer_aborts_the_whole_rotation(tmp_path):
    """The watch loop appending between the read and the replace would
    lose those records. The race is detected by re-stating every file
    BEFORE touching any of them, so an abort leaves the store exactly as
    it was — not half-rotated."""
    store = _store(tmp_path)
    _investigations(store, [300, 1])
    _write(store.closures_path, [{"alert_id": "A", "closed_at": _aged(300)}])
    plan = plan_rotation(store, retention_days=90, now=_NOW)
    before_investigations = store.path.read_text()
    before_closures = store.closures_path.read_text()

    # The loop completes an alert while rotation is mid-flight.
    with store.path.open("a") as f:
        f.write(json.dumps({"alert_id": "LIVE", "investigated_at": _aged(0)}) + "\n")

    with pytest.raises(ConcurrentWriteError, match="watch loop is running"):
        apply_rotation(plan)

    # Untouched — including the file that was NOT the one that grew.
    assert store.path.read_text().startswith(before_investigations)
    assert store.closures_path.read_text() == before_closures
    assert not plan.archive_dir.exists()      # no half-written archive left


def test_rotation_with_nothing_to_do_writes_no_archive_directory(tmp_path):
    store = _store(tmp_path)
    _investigations(store, [1])
    plan = plan_rotation(store, retention_days=90, now=_NOW)
    apply_rotation(plan)
    assert not plan.archive_dir.exists()


def test_two_rotations_do_not_collide(tmp_path):
    """Archive directories are stamped, so a second rotation the same day
    does not overwrite the first."""
    store = _store(tmp_path)
    _investigations(store, [300, 200])

    first = apply_rotation(plan_rotation(
        store, retention_days=90, now=_NOW,
    ))
    _investigations(store, [400])
    second = apply_rotation(plan_rotation(
        store, retention_days=90, now=_NOW + timedelta(seconds=5),
    ))

    assert first != second
    assert first.exists() and second.exists()


def test_the_default_retention_keeps_a_full_quarter(tmp_path):
    """Every window anything in this repo reads — the correlation window
    (hours), the digest (a day), the scorecard (weeks) — sits well inside
    the default, so rotating on defaults cannot silently change a verdict
    the desk would otherwise reach."""
    assert DEFAULT_RETENTION_DAYS >= 90
    store = _store(tmp_path)
    _investigations(store, [89, 80, 30])
    assert plan_rotation(store, now=_NOW).files == []


# --- the CLI seam -----------------------------------------------------------

def _configure_store(monkeypatch, tmp_path):
    import dataclasses

    import soc_copilot.config as config_mod

    monkeypatch.setattr(
        config_mod, "settings",
        dataclasses.replace(
            config_mod.Settings(),
            HISTORY_PATH=str(tmp_path / "investigations.jsonl"),
        ),
    )


def _args(**over):
    from types import SimpleNamespace

    base = dict(days=90, dry_run=False, include_human_records=False)
    base.update(over)
    return SimpleNamespace(**base)


async def test_dry_run_reports_the_move_and_changes_nothing(
    tmp_path, monkeypatch, capsys
):
    """The report an operator approves must be the report of what then
    happens, which is why --dry-run and the real run share one planner."""
    from soc_copilot.main import _run_rotate_history

    store = _store(tmp_path)
    _investigations(store, [300, 1])
    before = store.path.read_text()
    _configure_store(monkeypatch, tmp_path)

    await _run_rotate_history(_args(dry_run=True))

    out = capsys.readouterr().out
    assert "investigations.jsonl: 1 archived, 1 retained" in out
    assert "Dry run" in out
    assert store.path.read_text() == before
    assert not (tmp_path / "archive").exists()


async def test_the_runner_archives_and_reports_the_destination(
    tmp_path, monkeypatch, capsys
):
    from soc_copilot.main import _run_rotate_history

    store = _store(tmp_path)
    _investigations(store, [300, 200, 1])
    _configure_store(monkeypatch, tmp_path)

    await _run_rotate_history(_args())

    out = capsys.readouterr().out
    assert "Archived 2 record(s) to" in out
    assert len(store.path.read_text().splitlines()) == 1
    [archive] = list((tmp_path / "archive").iterdir())
    assert len(
        (archive / "investigations.jsonl").read_text().splitlines()
    ) == 2


async def test_the_runner_warns_about_what_it_held_back(
    tmp_path, monkeypatch, caplog
):
    """Silence here would let an operator believe a retention policy had
    been applied to files this command deliberately left alone."""
    from soc_copilot.main import _run_rotate_history

    store = _store(tmp_path)
    _investigations(store, [300])
    _write(store.dispositions_path, [
        {"alert_id": "A", "human_verdict": "true_positive",
         "recorded_at": _aged(300)},
    ])
    _configure_store(monkeypatch, tmp_path)

    await _run_rotate_history(_args(dry_run=True))

    assert "HELD BACK" in caplog.text
    assert "dispositions.jsonl" in caplog.text
    assert "--include-human-records" in caplog.text


async def test_a_quiet_store_says_so_and_still_warns(
    tmp_path, monkeypatch, capsys, caplog
):
    """Nothing old enough is the common case on a young desk. It must not
    look like a failure — and the held-back warning still belongs, since
    the operator's retention question is unanswered either way."""
    from soc_copilot.main import _run_rotate_history

    store = _store(tmp_path)
    _investigations(store, [1])
    _write(store.dispositions_path, [{"alert_id": "A", "recorded_at": _aged(300)}])
    _configure_store(monkeypatch, tmp_path)

    await _run_rotate_history(_args())

    assert "Nothing to rotate" in capsys.readouterr().out
    assert "HELD BACK" in caplog.text


async def test_a_concurrent_writer_exits_nonzero_without_changing_anything(
    tmp_path, monkeypatch, caplog
):
    """The operator must be able to tell from the exit code that their
    retention job did NOT run, rather than reading a success message over
    a store that was never rotated."""
    import soc_copilot.rotate as rotate_mod
    from soc_copilot.main import _run_rotate_history

    store = _store(tmp_path)
    _investigations(store, [300, 1])
    before = store.path.read_text()
    _configure_store(monkeypatch, tmp_path)

    real_apply = rotate_mod.apply_rotation

    def apply_after_an_append(plan):
        with store.path.open("a") as f:
            f.write(json.dumps(
                {"alert_id": "LIVE", "investigated_at": _aged(0)}
            ) + "\n")
        return real_apply(plan)

    monkeypatch.setattr(
        "soc_copilot.rotate.apply_rotation", apply_after_an_append
    )

    with pytest.raises(SystemExit) as exc:
        await _run_rotate_history(_args())

    assert exc.value.code == 1
    assert "watch loop is running" in caplog.text
    assert store.path.read_text().startswith(before)


def test_rotation_is_detected_by_the_store_even_in_the_cache_worst_case(tmp_path):
    """Archiving a record from the MIDDLE of a file leaves the first 64
    bytes byte-identical, which is the adversarial shape for the store
    cache's documented PROBABILISTIC prefix check. os.replace mints a new
    inode, so the (dev, ino) comparison fires first and that check is never
    reached.

    Stated precisely, because the first draft of this docstring claimed
    more than it could: the probabilistic path ALSO catches this shape (I
    checked — an in-place shrink is detected, because the tail bytes are
    no longer at the offset the cache consumed to). So the new inode is
    defence in depth here, not the thing that saves it. What os.replace is
    load-bearing for is crash atomicity: a reader can never observe a
    half-written file."""
    store = _store(tmp_path)
    _write(store.path, [
        {"alert_id": "KEEP", "investigated_at": _aged(1), "pad": "x" * 80},
        {"alert_id": "OLD", "investigated_at": _aged(300), "pad": "y" * 80},
    ])
    first_64_before = store.path.read_bytes()[:64]
    inode_before = store.path.stat().st_ino
    assert [r["alert_id"] for r in store.log("investigations").records()] == [
        "KEEP", "OLD",
    ]                                        # cache warmed on the old file

    apply_rotation(plan_rotation(store, retention_days=90, now=_NOW))

    assert store.path.read_bytes()[:64] == first_64_before   # worst case held
    assert store.path.stat().st_ino != inode_before
    assert [r["alert_id"] for r in store.log("investigations").records()] == ["KEEP"]


# --- the review's confirmed findings, each with its oracle ------------------

def test_a_ruled_investigation_row_is_pinned_and_the_gate_survives(tmp_path):
    """THE finding, and the one that made the whole asymmetry decorative.
    closure.py's overturn gate does not read dispositions.jsonl — it reads
    investigation.prior_sightings, and history.prior_sightings builds those
    by walking the INVESTIGATIONS index and only then joining the ruling
    on. Archiving the investigation row left the carefully retained ruling
    with nothing to attach to, and a documented BLOCK became an
    autonomous close. Three review lenses found it independently; this is
    the end-to-end reproduction, now asserting the fixed behavior."""
    from soc_copilot.closure import should_auto_close
    from soc_copilot.models import Alert, Investigation

    store = _store(tmp_path)
    _write(store.path, [{
        "alert_id": "A-100", "investigated_at": _aged(200),
        "timestamp": _aged(200), "verdict": "false_positive",
        "confidence": "high", "iocs": ["9.9.9.9"], "host": None,
        "attack_techniques": [], "title": "old one",
    }])
    _write(store.dispositions_path, [{
        "alert_id": "A-100", "human_verdict": "true_positive",
        "source": "thehive", "recorded_at": _aged(198),
    }])
    fresh = Alert(
        alert_id="A-900", timestamp=_NOW, source="edr", severity="high",
        title="t", raw_log={}, indicators={"ips": ["9.9.9.9"]},
    )

    def gate():
        inv = Investigation(
            alert_id="A-900", verdict="false_positive", confidence="high",
            hypothesis="h", escalation_recommended=False,
            prior_sightings=store.prior_sightings(fresh),
        )
        return should_auto_close(inv)

    assert gate()[0] is False                       # blocked before
    plan = plan_rotation(store, retention_days=90, now=_NOW)
    assert plan.files == []                         # the row is PINNED
    apply_rotation(plan)
    close, why = gate()
    assert close is False, "the overturn gate must survive rotation"
    assert "overturned" in why


def test_pinning_is_reported_so_the_count_is_not_a_mystery(tmp_path):
    store = _store(tmp_path)
    _write(store.path, [
        {"alert_id": "RULED", "investigated_at": _aged(300)},
        {"alert_id": "PLAIN", "investigated_at": _aged(300)},
    ])
    _write(store.dispositions_path, [
        {"alert_id": "RULED", "recorded_at": _aged(299)},
    ])

    [fp] = plan_rotation(store, retention_days=90, now=_NOW).files
    assert fp.pinned == 1
    assert len(fp.archived) == 1        # only the unruled row moves


def test_pinning_applies_to_investigations_not_the_sidecars(tmp_path):
    """A closure or progress row for a ruled alert carries no precedent —
    only the investigation row does, because that is what the IOC index
    preselects and the ruling joins onto."""
    store = _store(tmp_path)
    _write(store.path, [{"alert_id": "RULED", "investigated_at": _aged(300)}])
    _write(store.closures_path, [
        {"alert_id": "RULED", "closed_at": _aged(300), "reason": "fp"},
    ])
    _write(store.dispositions_path, [
        {"alert_id": "RULED", "recorded_at": _aged(299)},
    ])

    plan = plan_rotation(store, retention_days=90, now=_NOW)
    assert [f.name for f in plan.files] == ["closures.jsonl"]


def test_the_main_file_is_found_by_its_configured_name(tmp_path):
    """HISTORY_PATH is env-overridable, so the store's main file is not
    necessarily called investigations.jsonl. Hardcoding that name meant a
    custom path silently skipped the PII-heaviest file in the store while
    the command reported success (review catch, two lenses)."""
    store = AlertHistoryStore(tmp_path / "alerts.jsonl")
    store.path.parent.mkdir(parents=True, exist_ok=True)
    _write(store.path, [{"alert_id": "A", "investigated_at": _aged(300)}])

    [fp] = plan_rotation(store, retention_days=90, now=_NOW).files
    assert fp.name == "alerts.jsonl"
    assert len(fp.archived) == 1


def test_a_torn_final_line_stays_torn(tmp_path):
    """A file whose last line has no newline is a writer interrupted
    mid-append. The store's reader consumes whole lines only and ignores
    the remnant until the writer finishes it. Newline-terminating it here
    made it a COMPLETE line that fails to parse — converting a
    self-healing state into a permanently fatal store read (review catch,
    two lenses)."""
    store = _store(tmp_path)
    store.path.write_bytes(
        json.dumps({"alert_id": "OLD", "investigated_at": _aged(300)}).encode()
        + b"\n"
        + json.dumps({"alert_id": "NEW", "investigated_at": _aged(1)}).encode()
        + b"\n"
        + b'{"alert_id": "TORN", "investigated'      # no newline
    )

    apply_rotation(plan_rotation(store, retention_days=90, now=_NOW))

    after = store.path.read_bytes()
    assert after.endswith(b'{"alert_id": "TORN", "investigated')
    assert not after.endswith(b"\n")
    # And the store still reads, ignoring the remnant exactly as before.
    assert [r["alert_id"] for r in store.log("investigations").records()] == ["NEW"]


def test_a_file_ending_without_a_newline_is_not_given_one(tmp_path):
    """The same property for a COMPLETE final record that simply lacks a
    trailing newline: rotation must not rewrite bytes it was not asked to
    change."""
    store = _store(tmp_path)
    line = json.dumps({"alert_id": "NEW", "investigated_at": _aged(1)})
    store.path.write_bytes(
        json.dumps({"alert_id": "OLD", "investigated_at": _aged(300)}).encode()
        + b"\n" + line.encode()
    )
    apply_rotation(plan_rotation(store, retention_days=90, now=_NOW))
    assert store.path.read_bytes() == line.encode()


def test_retained_bytes_that_are_not_utf8_survive_verbatim(tmp_path):
    """Decoding with errors="replace" and writing the result back
    substitutes U+FFFD for every invalid byte, permanently corrupting a
    RETAINED record while the command reports that nothing was deleted
    (review catch). The payload is never re-encoded."""
    store = _store(tmp_path)
    latin1 = b'{"alert_id": "NEW", "host": "caf\xe9-srv", "investigated_at": "'
    latin1 += _aged(1).encode() + b'"}'
    store.path.write_bytes(
        json.dumps({"alert_id": "OLD", "investigated_at": _aged(300)}).encode()
        + b"\n" + latin1 + b"\n"
    )

    apply_rotation(plan_rotation(store, retention_days=90, now=_NOW))

    assert store.path.read_bytes() == latin1 + b"\n"
    assert b"\xe9" in store.path.read_bytes()       # not turned into U+FFFD


def test_two_rotations_in_the_same_second_do_not_overwrite_each_other(tmp_path):
    """The stamp has one-second granularity. Sharing a directory meant the
    second rotation opened every archive file in "w" mode and permanently
    deleted records the FIRST had already moved out of the live file — the
    one operation that promises nothing is deleted was the one that could
    delete without a trace (review catch, two lenses)."""
    store = _store(tmp_path)
    _write(store.path, [{"alert_id": "FIRST", "investigated_at": _aged(300)}])
    first = apply_rotation(plan_rotation(store, retention_days=90, now=_NOW))

    _write(store.path, [{"alert_id": "SECOND", "investigated_at": _aged(300)}])
    second = apply_rotation(plan_rotation(store, retention_days=90, now=_NOW))

    assert first != second
    assert b"FIRST" in (first / "investigations.jsonl").read_bytes()
    assert b"SECOND" in (second / "investigations.jsonl").read_bytes()


def test_the_concurrency_guard_covers_a_file_that_is_not_first(tmp_path):
    """The earlier test grew investigations.jsonl, which is FIRST in plan
    order — so it proved only "abort before the first replace" and a
    mutant folding the size check into the replace loop survived it
    (review catch). Growing the LAST file is what distinguishes the
    separate pre-pass from an interleaved check."""
    store = _store(tmp_path)
    _investigations(store, [300])
    _write(store.closures_path, [{"alert_id": "C", "closed_at": _aged(300)}])
    _write(store.watch_progress_path, [
        {"alert_id": "W", "phase": "completed", "at": _aged(300)},
    ])
    plan = plan_rotation(store, retention_days=90, now=_NOW)
    assert [f.name for f in plan.files][-1] == "watch_progress.jsonl"
    untouched = {f.name: f.path.read_bytes() for f in plan.files}

    with store.watch_progress_path.open("a") as f:      # the LAST file grows
        f.write(json.dumps({"alert_id": "LIVE", "at": _aged(0)}) + "\n")

    with pytest.raises(ConcurrentWriteError):
        apply_rotation(plan)

    # The two files BEFORE it in plan order must not have been replaced.
    assert store.path.read_bytes() == untouched["investigations.jsonl"]
    assert store.closures_path.read_bytes() == untouched["closures.jsonl"]


def test_an_append_between_the_stat_and_the_read_is_still_caught(tmp_path):
    """size_at_read is stamped BEFORE the read, so an append landing in
    that window inflates the re-stat past it and aborts. Pinned because
    swapping those two statements is invisible to every other test and
    silently destroys the appended record."""
    store = _store(tmp_path)
    _investigations(store, [300, 1])
    real_read_bytes = type(store.path).read_bytes

    def read_then_append(self):
        data = real_read_bytes(self)
        if self.name == "investigations.jsonl":
            with self.open("a") as f:
                f.write(json.dumps(
                    {"alert_id": "LIVE", "investigated_at": _aged(0)}
                ) + "\n")
        return data

    from pathlib import Path as _P

    original = _P.read_bytes
    _P.read_bytes = read_then_append
    try:
        plan = plan_rotation(store, retention_days=90, now=_NOW)
    finally:
        _P.read_bytes = original

    with pytest.raises(ConcurrentWriteError):
        apply_rotation(plan)
    assert b"LIVE" in store.path.read_bytes()       # never lost


async def test_a_partway_failure_does_not_claim_the_store_is_untouched(
    tmp_path, monkeypatch, caplog
):
    """The replaces run in sequence, so a failure on the second of three
    leaves the first ALREADY rotated. The earlier message told the
    operator the live files were untouched, which would have steered them
    to delete the archive holding the only surviving copy of those
    records (review catch)."""
    from soc_copilot.main import _run_rotate_history

    store = _store(tmp_path)
    _investigations(store, [300, 1])
    _write(store.closures_path, [{"alert_id": "C", "closed_at": _aged(300)}])
    _configure_store(monkeypatch, tmp_path)
    # Make the SECOND file's temp path unwritable: a real OSError, raised
    # after investigations.jsonl has already been replaced.
    (tmp_path / "closures.jsonl.rotating").mkdir()

    with pytest.raises(SystemExit) as exc:
        await _run_rotate_history(_args())

    assert exc.value.code == 1
    assert "may ALREADY be rotated" in caplog.text
    assert "Do not delete" in caplog.text
    assert "were NOT replaced" not in caplog.text


async def test_the_report_names_rows_pinned_by_a_ruling(
    tmp_path, monkeypatch, capsys
):
    """A retained count an operator cannot explain is a retention report
    they cannot sign off. Pinned rows are named separately from
    unclassifiable ones because the reasons are different."""
    from soc_copilot.main import _run_rotate_history

    store = _store(tmp_path)
    _write(store.path, [
        {"alert_id": "RULED", "investigated_at": _aged(300)},
        {"alert_id": "PLAIN", "investigated_at": _aged(300)},
    ])
    _write(store.dispositions_path, [
        {"alert_id": "RULED", "recorded_at": _aged(299)},
    ])
    _configure_store(monkeypatch, tmp_path)

    await _run_rotate_history(_args(dry_run=True))

    assert "1 pinned by an analyst ruling" in capsys.readouterr().out

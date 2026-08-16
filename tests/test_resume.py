"""Unit tests for the cross-restart resume policy (soc_copilot/resume.py).

The policy decides whether an alert that is STILL OPEN in Elastic but
already has an investigation on disk should be finished from that record
or investigated afresh. Every gate here fails toward a fresh look,
because the two mistakes are not symmetric: resuming when we should not
answers an analyst's deliberate re-open with a stale verdict, while
refusing to resume when we could have costs one model call.

    uv run pytest tests/test_resume.py -v
"""
import json
from datetime import datetime, timedelta, timezone

from soc_copilot.history import AlertHistoryStore
from soc_copilot.models import Alert, Investigation, Telemetry
from soc_copilot.resume import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    RESUME_WINDOW_MINUTES,
    find_resumable,
)

_T = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _alert(alert_id: str = "A1") -> Alert:
    return Alert(
        alert_id=alert_id, timestamp=_T, source="edr", severity="high",
        title=f"alert {alert_id}", raw_log={"outcome": "failure"},
        indicators={"ips": ["9.9.9.9"]},
    )


def _inv(alert_id: str = "A1", **over) -> Investigation:
    fields = dict(
        alert_id=alert_id, verdict="false_positive", confidence="high",
        hypothesis="benign scanner", escalation_recommended=False,
        attack_techniques=["T1110"],
        telemetry=Telemetry(
            model="claude-sonnet-5", cost_usd=0.031, duration_seconds=47.2
        ),
    )
    fields.update(over)
    return Investigation(**fields)


def _store(tmp_path) -> AlertHistoryStore:
    return AlertHistoryStore(tmp_path / "investigations.jsonl")


def _interrupted(store: AlertHistoryStore, alert: Alert, inv=None) -> None:
    """The exact state a crash leaves: the watch loop claimed the alert
    ("started"), the investigation was recorded, and nothing marked it
    completed. Tests must build this rather than just calling record(),
    because a bare record is what a one-shot `--from-elastic` run leaves
    and is deliberately NOT resumable."""
    store.record_watch_progress(alert.alert_id, "d1", "started")
    store.record(alert, inv or _inv(alert.alert_id))


def _rewrite_last(store: AlertHistoryStore, **fields) -> None:
    """Patch fields on the last written record. Used only where the test
    needs a record shape the writer cannot produce (a naive or corrupt
    timestamp); everything else controls time via find_resumable's `now`
    so the record stays exactly what history.record() writes."""
    lines = store.path.read_text().splitlines()
    rec = json.loads(lines[-1])
    rec.update(fields)
    lines[-1] = json.dumps(rec)
    store.path.write_text("\n".join(lines) + "\n")


# --- the resume itself -----------------------------------------------------

def test_a_recent_record_is_resumed_with_its_conclusion_intact(tmp_path):
    """The whole point: the verdict the crashed process paid for comes
    back whole — including the telemetry, because that money really was
    spent and the results row must keep saying so."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)

    found = find_resumable(store, alert)
    assert found is not None
    investigation, reason = found.investigation, found.reason
    assert investigation.verdict == "false_positive"
    assert investigation.confidence == "high"
    assert investigation.attack_techniques == ["T1110"]
    assert investigation.telemetry.cost_usd == 0.031
    assert investigation.telemetry.duration_seconds == 47.2
    # The reason is what an operator reads at 03:00; it must name the
    # alert and say plainly that no new model call happened.
    assert "A1" in reason and "twice" in reason


def test_an_alert_never_investigated_has_nothing_to_resume(tmp_path):
    store = _store(tmp_path)
    store.record(_alert("OTHER"), _inv("OTHER"))
    assert find_resumable(store, _alert("A1")) is None


def test_the_latest_record_is_the_one_resumed(tmp_path):
    """Append-only history: a re-investigated alert has several records
    and the interrupted run wrote the last one."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert, _inv(hypothesis="first look"))
    _interrupted(store, alert, _inv(hypothesis="second look", verdict="true_positive"))

    investigation = find_resumable(store, alert).investigation
    assert investigation.hypothesis == "second look"
    assert investigation.verdict == "true_positive"


# --- the gates, each failing toward a fresh look ---------------------------

def test_a_record_older_than_the_window_gets_a_fresh_look(tmp_path):
    """The window bounds how stale a delivered conclusion may be. (It is
    NOT what distinguishes a crash from a re-open — the progress ledger
    is; an earlier draft leaned on the window for that and three review
    lenses broke it.) Past the window the copilot pays for a real
    investigation rather than delivering a conclusion nobody has looked
    at in half an hour."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)
    later = datetime.now(timezone.utc) + timedelta(
        minutes=RESUME_WINDOW_MINUTES + 1
    )
    assert find_resumable(store, alert, now=later) is None


def test_the_window_boundary_still_resumes(tmp_path):
    """Just inside the window is inside it — pinned so a mutant flipping
    > to >= has somewhere to die."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)
    edge = datetime.now(timezone.utc) + timedelta(
        minutes=RESUME_WINDOW_MINUTES, seconds=-2
    )
    assert find_resumable(store, alert, now=edge) is not None


def test_an_analyst_ruling_blocks_the_resume(tmp_path):
    """A human touching the record is exactly the signal that their
    judgment, not the interrupted machine's, is what matters now — even
    seconds after the investigation, and even when they AGREED."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)
    store.record_disposition("A1", "false_positive", source="thehive")
    assert find_resumable(store, alert) is None


def test_a_future_stamped_record_is_refused(tmp_path):
    """A record stamped ahead of `now` means the clock stepped, not that
    a run just finished. Resuming against an unknown time base would let
    a backwards clock step keep a stale verdict resumable indefinitely."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)
    earlier = datetime.now(timezone.utc) - timedelta(
        seconds=CLOCK_SKEW_TOLERANCE_SECONDS + 30
    )
    assert find_resumable(store, alert, now=earlier) is None


def test_ordinary_clock_jitter_still_resumes(tmp_path):
    """The skew tolerance exists so NTP slew and clock-read ordering
    don't cost a model call; a second or two ahead is not a stepped
    clock."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)
    jitter = datetime.now(timezone.utc) - timedelta(seconds=5)
    assert find_resumable(store, alert, now=jitter) is not None


def test_a_zero_window_disables_resuming_entirely(tmp_path):
    """RESUME_WINDOW_MINUTES=0 is the documented off switch: a perfectly
    resumable record is still investigated afresh."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)
    assert find_resumable(store, alert, window_minutes=0) is None
    assert find_resumable(store, alert, window_minutes=-5) is None
    # The explicit guard's ONLY non-redundant case, and the reason it is
    # not dead code: a record stamped at or a hair ahead of `now` has
    # age <= 0, which no `age > window * 60` comparison can reject once
    # the window is 0. Without the off switch, RESUME_WINDOW_MINUTES=0
    # would still resume precisely the freshest records — the ones a
    # crash-restart produces (mutation catch: the first version of this
    # test only used records already a moment old, so the mutant that
    # deleted the guard survived).
    fresh = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert find_resumable(store, alert, window_minutes=0, now=fresh) is None
    # ...and the same record at the same `now` IS resumable with a real
    # window, so the None above is the off switch and nothing else.
    assert find_resumable(store, alert, window_minutes=30, now=fresh) is not None


def test_a_record_with_no_investigated_at_gets_a_fresh_look(tmp_path):
    """Records written before investigated_at existed carry no age, and
    an ageless record cannot be shown to be inside the window."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)
    _rewrite_last(store, investigated_at=None)
    assert find_resumable(store, alert) is None


def test_an_unparseable_timestamp_gets_a_fresh_look(tmp_path):
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)
    _rewrite_last(store, investigated_at="last tuesday")
    assert find_resumable(store, alert) is None


def test_a_naive_timestamp_is_read_as_utc(tmp_path):
    """The store only ever writes aware UTC, but a hand-edited or
    third-party line might not. Reading it as UTC keeps the comparison
    from raising — and skews the age in whichever direction the writer's
    offset ran, both of which fail toward a fresh look."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)
    naive = datetime.now(timezone.utc).replace(tzinfo=None)
    _rewrite_last(store, investigated_at=naive.isoformat())
    assert find_resumable(store, alert) is not None


def test_an_unreconstructable_investigation_gets_a_fresh_look(tmp_path):
    """Half-parsing a verdict and pushing it would be worse than paying
    for a new one."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)
    _rewrite_last(store, investigation={"verdict": "nonsense-not-a-verdict"})
    assert find_resumable(store, alert) is None

    _rewrite_last(store, investigation="not even a dict")
    assert find_resumable(store, alert) is None


def test_a_record_whose_investigation_names_another_alert_is_refused(tmp_path):
    """Only reachable via a corrupted or hand-edited line — and the one
    shape where resuming would deliver a conclusion reached about a
    DIFFERENT alert, which is the worst outcome this module has."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)
    _rewrite_last(
        store, investigation=_inv("SOMEONE-ELSE").model_dump(mode="json")
    )
    assert find_resumable(store, alert) is None


def test_a_suppressed_record_is_never_resumed(tmp_path):
    """A duplicate_of record is a POINTER to an anchor, not a conclusion
    this copilot reached. Replaying it would re-borrow the anchor's
    verdict while skipping every gate dedup applies to that borrow —
    above all the fingerprint-overturn block. The reviewer's
    reproduction is the case that matters: an analyst overturns the
    anchor DURING the outage being recovered from, so try_suppress
    refuses the borrow at the very instant a resume would have delivered
    it, and with --auto-close the alert closes on a verdict the analyst
    just rejected. Falling through to try_suppress re-applies every gate
    and still costs no model call when it agrees.

    This test asserted the opposite when first written (review catch)."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert, _inv(duplicate_of="ANCHOR-1"))
    assert find_resumable(store, alert) is None


# --- the progress ledger: what makes "interrupted" a fact, not a guess ----

def test_a_record_with_no_progress_marker_is_not_resumable(tmp_path):
    """A bare history record is what a one-shot `soc-copilot
    --from-elastic` run leaves behind: it investigates and records, and
    never touches alert status, so all its alerts stay open with a fresh
    record and no ruling. Under the old inference the watch service
    would then push and acknowledge — and under --auto-close, close —
    all of them from that dry run's verdicts, logging a crash that never
    happened (review catch)."""
    store, alert = _store(tmp_path), _alert()
    store.record(alert, _inv())          # investigated, but not BY the loop
    assert find_resumable(store, alert) is None


def test_a_completed_alert_is_not_resumable_when_it_comes_back(tmp_path):
    """The sharpest catch of the review, and the one the module's
    original premise got backwards. "If step 2 completed, the alert
    would not be in the open queue" inverts the implication: completing
    means the alert LEFT the queue then, not that it cannot be back now.
    An analyst re-opening a worked alert put it right back, and the
    resume answered their demand for a second look with the stale
    verdict, re-acknowledged it, opened a SECOND TheHive case and paged
    again. A completed marker ends that: the re-open gets a fresh
    look."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)
    assert find_resumable(store, alert) is not None      # mid-flight

    store.record_watch_progress("A1", "d1", "completed")
    assert find_resumable(store, alert) is None          # then re-opened


def test_a_re_interrupted_alert_is_resumable_again(tmp_path):
    """Append-only, last-wins: an alert worked, re-opened, and then
    interrupted AGAIN is a genuine crash the second time too. The gate
    reads the latest phase, not whether a completion has ever existed."""
    store, alert = _store(tmp_path), _alert()
    _interrupted(store, alert)
    store.record_watch_progress("A1", "d1", "completed")
    _interrupted(store, alert, _inv(hypothesis="the second look"))

    found = find_resumable(store, alert)
    assert found is not None
    assert found.investigation.hypothesis == "the second look"


def test_the_resumed_precedent_is_recomputed_not_replayed(tmp_path):
    """The conclusion is frozen; the analyst precedent that GATES
    autonomous action is not. closure.should_auto_close reads the
    overturn signal off investigation.prior_sightings — a snapshot taken
    inside the interrupted investigate() call, which by construction
    cannot carry a ruling that arrived during the outage. Replaying it
    verbatim made the project's only human-in-the-loop check on
    autonomous closure vacuous on this path (review catch), and the
    watch loop syncs dispositions BEFORE its first poll, so the copilot
    demonstrably held the correction in hand while closing anyway."""
    from soc_copilot.closure import should_auto_close

    store, alert = _store(tmp_path), _alert()
    # A prior sighting on the shared IOC, investigated false_positive.
    prior = _alert("PRIOR")
    store.record(prior, _inv("PRIOR"))
    # Now this alert. The real investigate() computes prior_sightings and
    # then records the Investigation carrying them, so the stored snapshot
    # is whatever the store said at that moment — here, unruled.
    snapshot = store.prior_sightings(alert)
    assert [p.human_verdict for p in snapshot] == [None]
    _interrupted(store, alert, _inv(prior_sightings=snapshot))
    stale = Investigation(**json.loads(
        store.path.read_text().splitlines()[-1]
    )["investigation"])
    assert should_auto_close(stale)[0] is True       # would have closed

    # During the outage, the analyst overturns the prior.
    store.record_disposition("PRIOR", "true_positive", source="thehive")

    resumed = find_resumable(store, alert).investigation
    assert [p.human_verdict for p in resumed.prior_sightings] == ["true_positive"]
    close, why = should_auto_close(resumed)
    assert close is False
    assert "overturned" in why

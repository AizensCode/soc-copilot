"""Cross-restart dedupe — finishing an interrupted run instead of redoing it.

Acknowledgement in Elastic is the copilot's real dedupe: a worked alert
leaves the `status:open` query, so the next poll never sees it again. The
watch loop's in-memory `seen` set is only a second guard for the sliver
of time before a status write is visible, and it dies with the process.

That leaves one durable gap, and it is the expensive one. `_work_alert`
writes in a deliberate order — the history record lands inside
`copilot.investigate*()`, then push_investigation, then set_alert_status
— so a crash, a SIGKILL after the drain grace expires, or the watchdog's
own exit(2) can land AFTER the model was paid for and BEFORE the alert
was acknowledged. The alert is still open; the verdict is on disk. On
restart the loop re-fetched it and bought the same conclusion a second
time, and (if the push had landed) indexed a second results row that
double-counted the cost in every dashboard.

The fix is not a persistent blacklist. "Never work an alert_id twice"
would trade a costly failure for a silent one: the copilot would skip
the alert WITHOUT acknowledging it, so nothing would ever move it out
of `status:open`. It would be re-fetched and re-skipped on every poll
for as long as it stayed among the ten most recent open alerts, then
quietly age out of the query and sit open in Elastic forever, worked by
nobody. And the desk would report itself healthy throughout: a cycle
that skips every alert records no failures, and the watchdog counts a
cycle with nothing completed and nothing failed as a quiet queue, not a
sick one (verified against CycleReport.sick — `failed > 0` is required).
An expensive duplicate investigation at least announces itself in the
cost telemetry; an alert nobody worked and nobody was told about does
not. What the interrupted run actually needs is to be FINISHED: replay
the Elastic effects it never delivered, using the conclusion already on
disk, and let the alert leave the queue the normal way.

So this module is a completion, not a suppression, and its gates say so.
Each one fails toward a fresh investigation — the safe direction, since
the cost of being wrong here is one model call, while the cost of being
wrong the other way is an analyst's deliberate re-open silently answered
with a stale verdict:

- Only when the watch loop's own progress ledger says this alert was
  STARTED and never COMPLETED. This is the gate that makes "interrupted"
  a fact rather than a guess, and everything below is a sanity check on
  top of it.
- Only an alert this copilot already investigated, matched on alert_id.
- Only within RESUME_WINDOW_MINUTES of that investigation — a bound on
  how stale a delivered conclusion may be, not (any longer) the thing
  that distinguishes a crash from a re-open.
- Never a SUPPRESSED record: a duplicate_of record is a pointer to an
  anchor, not a conclusion this copilot reached, and replaying it would
  skip every gate dedup applies to that borrow.
- Never once an analyst has ruled on the alert: a human touching the
  record is exactly the signal that their judgment, not the copilot's
  interrupted one, is what matters now.
- Never from a record that will not parse back into the Investigation
  that produced it.

What is NOT frozen is the precedent that gates autonomous action. The
resumed Investigation's prior_sightings are recomputed at delivery time,
because closure.should_auto_close reads the analyst-overturn signal off
them and a snapshot taken before the outage cannot carry a ruling that
arrived during it.

A resume writes NO new history record. The record already exists — the
interrupted run wrote it before it died — and appending a second one
would double-count that investigation's cost and duration in the digest,
the scorecard, and every eval that reads the store. The log line is the
resume's only trace, and that is the honest amount: nothing new was
concluded, so nothing new is recorded.
"""
from datetime import datetime, timezone
from typing import NamedTuple

from .history import AlertHistoryStore
from .models import Alert, Investigation


class Resumable(NamedTuple):
    """A conclusion an interrupted run already paid for, ready to deliver.

    `investigated_at` rides along because the caller needs it to ask
    Elastic a precise question — "did THIS run already index its result?"
    — rather than the ambiguous "does this alert have any results doc?".
    """

    investigation: Investigation
    investigated_at: datetime
    reason: str

# Long enough to cover a supervised restart with room to spare (systemd
# waits RestartSec=60; a docker policy restart is immediate; the watchdog
# adds up to one poll interval), short enough that an analyst re-opening
# an alert during their shift falls outside it. Set to 0 to disable
# resuming entirely — every re-opened alert then gets a fresh look, at
# the price of paying twice for an interrupted one.
RESUME_WINDOW_MINUTES = 30

# A record stamped in the future is a clock that stepped, not a run that
# just finished. A little jitter is normal (NTP slew, a record written
# microseconds before `now` was taken on a different clock read); beyond
# that, refuse rather than resume against an unknown time base.
CLOCK_SKEW_TOLERANCE_SECONDS = 60


def _investigated_at(rec: dict) -> datetime | None:
    """The record's write time as an aware UTC datetime, or None if it
    is missing or unparseable. A naive stamp is read as UTC because that
    is the only thing this store ever writes (history.record uses
    datetime.now(timezone.utc)); if some other producer wrote local time,
    reading it as UTC skews the age in one direction or the other and
    both directions fail the window checks below — toward a fresh look."""
    raw = rec.get("investigated_at")
    if not isinstance(raw, str):
        return None
    try:
        when = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def find_resumable(
    store: AlertHistoryStore,
    alert: Alert,
    window_minutes: int = RESUME_WINDOW_MINUTES,
    now: datetime | None = None,
) -> Resumable | None:
    """The conclusion an interrupted run already paid for on THIS alert,
    ready to be delivered, or None when the alert deserves a fresh look.

    The reason is written for an operator reading the log at 03:00 and
    wondering why an alert was acknowledged without a model call.
    """
    if window_minutes <= 0:
        return None
    now = now or datetime.now(timezone.utc)

    # THE gate: the watch loop's own progress ledger must say this alert
    # was started and never completed. Everything else here is a sanity
    # check on the record; this is the only thing that establishes an
    # interruption actually happened. Two review lenses independently
    # broke the earlier version, which inferred interruption from "recent
    # record + alert still open" — an inference that is false for a
    # one-shot `--from-elastic` run (records, never sets status) and false
    # for an alert an analyst RE-OPENS after a completed run. The second
    # is the dangerous one: it made a deliberate demand for a second look
    # answered with the stale verdict, re-acknowledged, with a WARNING
    # asserting a crash that never happened.
    progress = store.watch_progress(alert.alert_id)
    if progress is None or progress.get("phase") != "started":
        return None

    # latest_record joins the analyst's ruling in under "ruling" — the
    # same lookup answers "did we investigate this?" and "has a human
    # since had their say?", so the two gates cost one read.
    rec = store.latest_record(alert.alert_id)
    if rec is None:
        return None
    if rec.get("ruling"):
        return None
    if rec.get("duplicate_of"):
        # A suppressed record is a POINTER to an anchor, not a conclusion
        # this copilot reached. Replaying it would re-borrow the anchor's
        # verdict while skipping every gate dedup applies to that borrow —
        # above all the fingerprint-overturn block, which refuses a
        # conclusion an analyst has overturned anywhere in its history.
        # An analyst can (and in the reviewer's reproduction did) overturn
        # the anchor during the very outage being recovered from, so
        # try_suppress would refuse the borrow at the same instant this
        # delivered it (review catch). Falling through re-runs try_suppress,
        # which re-applies its gates and costs no model call when it still
        # agrees.
        return None

    when = _investigated_at(rec)
    if when is None:
        return None
    age = (now - when).total_seconds()
    if age > window_minutes * 60:
        return None
    if age < -CLOCK_SKEW_TOLERANCE_SECONDS:
        return None

    raw = rec.get("investigation")
    if not isinstance(raw, dict):
        return None
    try:
        investigation = Investigation(**raw)
    except Exception:
        # A record we cannot reconstruct is a record we cannot deliver.
        # Falling through to a real investigation is strictly better than
        # pushing a half-parsed verdict.
        return None
    if investigation.alert_id != alert.alert_id:
        # The index keys on the record's own alert_id, so this can only
        # happen to a hand-edited or corrupted line. Refuse to deliver a
        # conclusion reached about a different alert.
        return None

    # The conclusion is frozen; the PRECEDENT that gates autonomous action
    # is not. closure.should_auto_close blocks a close when a prior
    # sighting carries an analyst ruling that overturned the copilot — and
    # it reads that ruling off investigation.prior_sightings, a snapshot
    # taken inside the interrupted investigate() call. Replaying the
    # snapshot verbatim made the project's ONLY human-in-the-loop check on
    # autonomous closure vacuous on this path: the watch loop syncs
    # dispositions before its first poll, so the copilot could hold the
    # analyst's correction in hand and auto-close anyway (review catch —
    # structurally the same bug dedup.py's docstring records as a prior
    # catch, reintroduced on a new path). Recomputing costs one indexed
    # lookup and is exactly what a fresh investigation would have seen.
    investigation.prior_sightings = store.prior_sightings(alert)

    return Resumable(investigation, when, (
        f"resuming the interrupted run of {alert.alert_id}: investigated "
        f"{when.isoformat()} ({int(age)}s ago) with verdict "
        f"{investigation.verdict}/{investigation.confidence}, but the "
        f"Elastic writes never landed — delivering that conclusion "
        f"instead of paying for it twice"
    ))

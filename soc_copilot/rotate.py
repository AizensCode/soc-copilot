"""History rotation — retention, not performance, and never a delete.

The runbook has documented rotation as "stop the service, move
data/history/*.jsonl to an archive, start" since the store existed. That
procedure is correct and it is also a trap, because the five files are
NOT symmetric and moving them together quietly disarms two safety gates.
This module makes the operation first-class and asymmetric.

Rotation is no longer about size. After the index work the store parses
appends in well under a millisecond at 100k records and the memory scans
run in fractions of one, so nothing here is a performance fix. What does
force the issue is RETENTION: an investigation record contains usernames,
mailbox addresses, hostnames and source IPs, and an organization with a
retention policy needs a way to age that out on a schedule rather than
by hand at 2am.

WHAT ROTATES, AND WHY THE REST DOES NOT:

- investigations.jsonl, closures.jsonl, watch_progress.jsonl rotate by
  age. Losing old investigations costs prior-sighting context and dedup
  anchors, and both fail toward a FRESH investigation — the copilot pays
  for a look it could have skipped. Losing old closures undercounts the
  automation rate. Losing progress markers makes nothing resumable. Every
  one of those is the safe direction.

- dispositions.jsonl and created_alerts.jsonl are held back unless the
  operator asks for them explicitly, because they fail the OTHER way. A
  disposition is an analyst's ruling that blocks an autonomous close;
  created_alerts is the provenance ledger that lets a synced TheHive
  ruling be trusted at all. Both grow at human speed, not alert speed, so
  there is no operational reason to trim them and one very good reason
  not to.

- AND the investigation rows those rulings point at are PINNED, retained
  regardless of age. This is the part the first version got wrong, and it
  made the whole asymmetry decorative. closure.py's overturn gate does
  not read dispositions.jsonl: it reads investigation.prior_sightings,
  and history.prior_sightings builds those by walking the INVESTIGATIONS
  index and only then joining the ruling on. Archive the investigation
  row and the carefully retained ruling has nothing to attach to — the
  sighting never exists. Reproduced end to end before the fix: a ruled
  true-positive precedent went from "analyst ruling on A-100 overturned
  the copilot's false_positive ... human review required" (blocked) to
  "high-confidence false positive with no escalation" (auto-closed), on
  the documented default invocation. Three review lenses found it
  independently, and the CLI was printing a warning that the gate had
  been preserved by the same run that disarmed it.
  dedup._fingerprint_overturned resolves rulings through the same index
  and is restored by the same pin.

NOTHING IS DELETED. Rotation splits each file at the cutoff: the old part
is written to a timestamped archive directory under the history root, the
recent part is rewritten in place. The archive is fully written and synced
BEFORE any live file is replaced, and each live file is replaced by an
atomic os.replace of a temp file in the same directory, so a crash at any
point leaves either the original file or the complete new one — never a
truncated history.

Lines that cannot be classified — malformed JSON, or a record with no
usable timestamp — are RETAINED, never archived. Aging out a record
requires knowing it is old, and a record whose age cannot be established
is not proof of anything except that something upstream wrote a line this
module does not understand.

Run it with the watch loop STOPPED. The store tolerates file replacement
(the caches carry a generation counter for exactly this), but a loop
appending between the moment this reads a file and the moment it replaces
it would lose those records. That window is guarded — every file's size is
re-checked immediately before its replace and the whole rotation aborts,
untouched, if anything grew — but a guard that detects the race is not the
same as not racing.
"""
import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .history import AlertHistoryStore

# Ninety days is a policy default, not a safe one derived from the
# readers — an earlier comment here claimed it was "well past every window
# anything in this repo reads", which is false: build_scorecard takes no
# window at all and prior_sightings applies no age filter, so BOTH read the
# entire store (review catch). What bounds the damage is the pin on ruled
# rows below, not the number. The windowed readers that do exist sit well
# inside it (correlation in hours, dedup and resume in hours/minutes, the
# digest in a day).
DEFAULT_RETENTION_DAYS = 90

# The record file's own time field. The FILENAME is not hardcoded: the
# main store is whatever HISTORY_PATH names (config.py makes it
# env-overridable), and only the four sidecars have fixed names via
# history.py's with_name(). Spelling it "investigations.jsonl" here meant
# a custom HISTORY_PATH skipped the PII-heaviest file in the store while
# the command reported success (review catch, two lenses).
INVESTIGATIONS_FIELD = "investigated_at"
SIDECAR_ROTATABLE = {
    "closures.jsonl": "closed_at",
    "watch_progress.jsonl": "at",
}
# Held back by default; see the module docstring for what each one costs.
HUMAN_RECORD = {
    "dispositions.jsonl": "recorded_at",
    "created_alerts.jsonl": "created_at",
}
HELD_BACK_REASON = {
    "dispositions.jsonl": (
        "analyst rulings — closure.py reads these to REFUSE an autonomous "
        "close when a human overturned the copilot on a related indicator; "
        "archiving them makes the desk more willing to close what a human "
        "already called real"
    ),
    "created_alerts.jsonl": (
        "the provenance ledger that lets a synced TheHive ruling be trusted "
        "at all; archiving it makes later rulings on those cases arrive "
        "un-provenanced and be rejected"
    ),
}


@dataclass
class FilePlan:
    """What rotation would do to one file."""

    path: Path
    field: str
    retained: list[bytes] = field(default_factory=list)
    archived: list[bytes] = field(default_factory=list)
    unclassifiable: int = 0
    pinned: int = 0
    # A final line with no terminating newline: the writer was interrupted
    # mid-append. Carried separately and written back WITHOUT a newline —
    # see plan_rotation.
    torn_tail: bytes = b""
    size_at_read: int = 0

    @property
    def name(self) -> str:
        return self.path.name


@dataclass
class RotationPlan:
    cutoff: datetime
    archive_dir: Path
    files: list[FilePlan] = field(default_factory=list)
    held_back: list[str] = field(default_factory=list)

    @property
    def archived_total(self) -> int:
        return sum(len(f.archived) for f in self.files)

    @property
    def retained_total(self) -> int:
        return sum(len(f.retained) for f in self.files)

    @property
    def unclassifiable_total(self) -> int:
        return sum(f.unclassifiable for f in self.files)

    @property
    def pinned_total(self) -> int:
        return sum(f.pinned for f in self.files)


def _parse(line: bytes) -> dict | None:
    """The record a line holds, or None if it is not a JSON object.

    Decoding is for INSPECTION only — the original bytes are what get
    written back. Decoding with errors="replace" and rewriting the result
    would silently substitute U+FFFD for every byte that is not valid
    UTF-8, permanently corrupting a retained record while the command
    reports that nothing was deleted (review catch).
    """
    try:
        rec = json.loads(line.decode("utf-8", errors="replace"))
    except (ValueError, TypeError):
        return None
    return rec if isinstance(rec, dict) else None


def _record_time(rec: dict | None, field_name: str) -> datetime | None:
    """The record's own timestamp, or None when it cannot be established —
    which is the only answer that matters, since an unclassifiable line is
    retained rather than aged out."""
    if rec is None:
        return None
    raw = rec.get(field_name)
    if not isinstance(raw, str):
        return None
    try:
        when = datetime.fromisoformat(raw)
    except ValueError:
        return None
    # Naive stamps are read as UTC — the only thing this store writes. A
    # writer using local time skews the age in one direction or the other,
    # and both directions are survivable here because the archive is not a
    # delete (history.py's resume path documents the same reasoning).
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def plan_rotation(
    store: AlertHistoryStore,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    now: datetime | None = None,
    include_human_records: bool = False,
) -> RotationPlan:
    """Work out what rotation would move, without touching anything.

    Pure with respect to the filesystem apart from reads, so --dry-run and
    the real run plan identically and the report an operator approves is
    the report of what then happens.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=retention_days)
    root = Path(store.path).parent
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    plan = RotationPlan(cutoff=cutoff, archive_dir=root / "archive" / stamp)

    targets = {store.path.name: INVESTIGATIONS_FIELD}
    targets.update(SIDECAR_ROTATABLE)
    if include_human_records:
        targets.update(HUMAN_RECORD)
    else:
        plan.held_back = [
            f"{name}: {HELD_BACK_REASON[name]}"
            for name in HUMAN_RECORD
            if (root / name).exists()
        ]

    # The rows an analyst ruling POINTS AT. This is what makes holding
    # dispositions.jsonl back mean anything: closure.py's overturn gate
    # does not read dispositions, it reads investigation.prior_sightings,
    # and history.prior_sightings builds those by walking the
    # INVESTIGATIONS index and only then joining the ruling on. Archive the
    # investigation row and the carefully retained ruling has nothing to
    # attach to — the sighting never exists, and a documented BLOCK on
    # autonomous closure silently becomes an auto-close. Three review
    # lenses found that independently; reproduced end to end before this
    # fix (should_auto_close flipped from "analyst ruling ... overturned"
    # to "high-confidence false positive"). dedup._fingerprint_overturned
    # resolves rulings through the same index and is restored by the same
    # pin.
    ruled_ids = set(store.dispositions()) if not include_human_records else set()

    for name, field_name in targets.items():
        path = root / name
        if not path.exists():
            continue
        fp = FilePlan(path=path, field=field_name,
                      size_at_read=path.stat().st_size)
        raw = path.read_bytes()
        lines = raw.split(b"\n")
        # split() always yields a final element: b"" when the file ended
        # with a newline, otherwise the torn remnant of an interrupted
        # append. The store's reader ignores a torn tail until the writer
        # completes it (it consumes whole lines only); newline-terminating
        # it here would turn that self-healing state into a permanent
        # JSONDecodeError for the whole store (review catch, two lenses).
        fp.torn_tail = lines.pop()
        is_investigations = name == store.path.name
        for line in lines:
            if not line.strip():
                continue
            rec = _parse(line)
            when = _record_time(rec, field_name)
            if is_investigations and rec is not None and rec.get("alert_id") in ruled_ids:
                fp.pinned += 1
                fp.retained.append(line)
            elif when is None:
                fp.unclassifiable += 1
                fp.retained.append(line)      # never age out the unknown
            elif when < cutoff:
                fp.archived.append(line)
            else:
                fp.retained.append(line)
        if fp.archived:
            plan.files.append(fp)
    return plan


def _fsync_dir(path: Path) -> None:
    """Make a directory's own entries durable.

    fsync on a file makes its CONTENTS durable; the entry naming it lives
    in the parent directory and needs its own fsync. os.replace is atomic
    with respect to readers either way — that is what protects a crashed
    rotation from a truncated history — but atomic is not the same as
    durable, and rotation is the one operation here that moves data out of
    the file everything else reads.

    Best-effort: some filesystems refuse O_RDONLY fsync on a directory,
    and failing the whole rotation over a durability nicety would be a
    worse outcome than the weaker guarantee.
    """
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class ConcurrentWriteError(RuntimeError):
    """A history file grew while rotation was reading it — the watch loop
    is running. Raised BEFORE any live file is replaced, so the store is
    left exactly as it was."""


def apply_rotation(plan: RotationPlan) -> Path:
    """Execute the plan. Returns the archive directory.

    Order is the whole safety argument:
      1. every archive file is written and fsynced,
      2. every live file's size is re-checked against what was read,
      3. only then is each live file replaced, atomically.
    A crash before 3 leaves an archive nobody has acted on; a crash during
    3 leaves each individual file either whole-old or whole-new.
    """
    if not plan.files:
        return plan.archive_dir

    # exist_ok=False, with a suffix on collision. The stamp has one-second
    # granularity, so two rotations in the same second shared a directory
    # and the second opened every archive file in "w" mode — permanently
    # deleting records the FIRST rotation had already moved out of the live
    # file. The one operation that promises nothing is deleted was the one
    # that could delete without a trace (review catch, two lenses).
    base = plan.archive_dir
    for attempt in range(1, 100):
        try:
            plan.archive_dir.mkdir(parents=True, exist_ok=False)
            break
        except FileExistsError:
            plan.archive_dir = base.with_name(f"{base.name}-{attempt + 1}")
    else:
        raise RuntimeError(
            f"could not find an unused archive directory beside {base}"
        )
    for fp in plan.files:
        target = plan.archive_dir / fp.name
        with target.open("wb") as f:
            f.write(b"\n".join(fp.archived) + b"\n")
            f.flush()
            os.fsync(f.fileno())
    # fsync the archive DIRECTORY too: fsyncing a file makes its contents
    # durable, not the directory entry that names it. Without this a power
    # loss can leave archive files whose data survived but whose names did
    # not — while the live files, replaced below, are already trimmed.
    _fsync_dir(plan.archive_dir)

    # Re-stat every file BEFORE touching any of them: an abort must leave
    # the store untouched, not half-rotated.
    for fp in plan.files:
        if fp.path.stat().st_size != fp.size_at_read:
            shutil.rmtree(plan.archive_dir, ignore_errors=True)
            raise ConcurrentWriteError(
                f"{fp.name} grew while rotation was reading it "
                f"({fp.size_at_read} -> {fp.path.stat().st_size} bytes): the "
                f"watch loop is running. Nothing was changed; stop the "
                f"service and run this again."
            )

    for fp in plan.files:
        tmp = fp.path.with_suffix(fp.path.suffix + ".rotating")
        with tmp.open("wb") as f:
            # Bytes, never re-encoded text: decoding with errors="replace"
            # and writing the result back substitutes U+FFFD for every byte
            # that is not valid UTF-8, corrupting a RETAINED record while
            # the command reports that nothing was deleted (review catch).
            if fp.retained:
                f.write(b"\n".join(fp.retained) + b"\n")
            # The torn tail of an interrupted append goes back exactly as
            # it was found — unterminated. The store's reader consumes
            # whole lines only and ignores it until the writer finishes;
            # adding the newline would make it a complete line that fails
            # to parse, turning a self-healing state into a permanently
            # fatal store read (review catch, two lenses).
            f.write(fp.torn_tail)
            f.flush()
            os.fsync(f.fileno())
        # Atomic within the directory — and it mints a NEW INODE, which
        # is what makes the store's cache detect the rewrite. That cache
        # falls back to a documented PROBABILISTIC 64-byte prefix check
        # when the inode is unchanged, and rotation can produce exactly
        # the adversarial input for it: archiving a record from the MIDDLE
        # of a file leaves the first 64 bytes byte-identical. Replacing
        # in place would have walked into that; os.replace never reaches
        # the check at all.
        os.replace(tmp, fp.path)
    _fsync_dir(plan.files[0].path.parent)
    return plan.archive_dir

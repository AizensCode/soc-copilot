"""Where the desk's memory LIVES, as opposed to what it means.

The copilot's cross-alert memory (soc_copilot/history.py) is a set of
queries: prior sightings on a shared indicator, campaign correlation,
dedup's most-recent-same-fingerprint anchor, the latest record for an
alert. Those queries were written against a JSONL file, and until now the
file and the queries were the same object.

They are separated here so a desk can share one memory. Two analysts
running `--ask` and two watch instances on one queue each kept a private
history: the same IP could be ruled a false positive on one host and
re-investigated from scratch on the next, and neither instance could see
the analyst ruling that would have blocked the other's autonomous
closure. Sharing is the point of the item.

THE SEAM IS THE LOG, NOT THE QUERY. Every backend here is an append-only
ledger of records with a cursor, and `AlertHistoryStore` runs exactly the
same Python predicates over whatever the ledger hands it. The tempting
alternative — push `prior_sightings` down into an Elasticsearch query,
`correlate` into a second one — was rejected on the rule this project
already set for the query index: a faster path is only allowed when it
is PROVABLY equivalent to the scan, and the way that rule was kept was
by having one implementation of each predicate and randomized
equivalence tests over it. Two query implementations would mean the
shared desk and the local desk can disagree about whether an alert is a
campaign, with no single place to look for the answer. One log-tailing
backend keeps one implementation of every predicate and lets the same
equivalence tests cover both backends.

The cost of that choice, stated plainly: every instance holds the whole
shared history in memory, and a cold start reads all of it. That is not
a regression — the JSONL store already parses its entire file into
memory, because that is what the query index needs — but it does mean
shared memory scales the way the local store scales, and the retention
command (`--rotate-history`) is the pressure valve for both.

Two ledger implementations:

- `JsonlLog` — one append-only JSONL file, parsing only the bytes
  appended since it last looked. This is the zero-dependency default and
  its incremental-read machinery is untouched by this module's arrival.
- `ElasticLog` — one Elasticsearch index, tailed the same way: read only
  the documents written since the last look, splice them onto the prefix
  already held, and rebuild from scratch when the prefix turns out not
  to be what it was. The two logs verify that prefix in different
  coordinates — the file re-reads its last 64 bytes, the index re-reads
  its last few minutes — and for the same reason.

What is shared and what is not is a SAFETY decision, not a deployment
one, and it lives in history.py where the readers are: the investigations
and dispositions ledgers are shared (evidence and ground truth, both
worth more the more of the desk contributes), while the ledgers that
record what THIS instance did or trusts stay local. See
`AlertHistoryStore` and `SHARED_LEDGERS` below.
"""
import hashlib
import json
import socket
import time
import uuid
from bisect import bisect_left
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol

import httpx

from . import httpio

# The five ledgers the history store keeps. Names are stable: they are
# the JSONL filenames and the `ledger` keyword in shared memory.
INVESTIGATIONS = "investigations"
DISPOSITIONS = "dispositions"
CLOSURES = "closures"
CREATED_ALERTS = "created_alerts"
WATCH_PROGRESS = "watch_progress"

LEDGERS = (
    INVESTIGATIONS, DISPOSITIONS, CLOSURES, CREATED_ALERTS, WATCH_PROGRESS,
)

# Which ledgers a shared backend actually shares. The rest stay local
# even in shared mode — see AlertHistoryStore for why each one is where
# it is. Kept here because the backend has to know which index to build.
SHARED_LEDGERS = frozenset({INVESTIGATIONS, DISPOSITIONS})

# Dropped beside the local ledgers the first time a desk runs on shared
# memory, and refused-on by the local backend afterwards. See
# `_refuse_silent_revert`.
SHARED_MARKER = ".shared-memory"

# How many trailing bytes of the already-parsed prefix to re-verify before
# splicing an append onto it. Enough to catch a rewritten file, O(1) to read.
_PREFIX_CHECK_BYTES = 64


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MILLISECOND = timedelta(milliseconds=1)


def _to_millis(when: datetime) -> int:
    """Exact integer millis. Elasticsearch's `date` type keeps
    milliseconds and nothing finer, so this is the real resolution of
    every ordering decision shared memory makes — which is why the two
    writers of `written_at` (live appends, migration) each take care to
    stay distinct at THIS granularity rather than at Python's."""
    return (when - _EPOCH_UTC) // _MILLISECOND


def _from_millis(millis: int) -> datetime:
    return _EPOCH_UTC + millis * _MILLISECOND


class HistoryLog(Protocol):
    """One append-only ledger of JSON records.

    Three contracts every implementation owes its readers, because the
    store's incremental structures (the query index, the watch-progress
    fold) are built on them:

    - `records()` returns the records in a stable total order, oldest
      first, and the SAME dict objects across calls. Callers treat them
      as read-only.
    - The returned list is REBOUND, never mutated in place, so an
      iterator handed out earlier keeps walking its own snapshot.
    - `generation` is bumped whenever the list is REBUILT rather than
      extended. A reader that has folded a prefix may keep it only while
      the generation is unchanged.
    """

    def append(self, rec: dict) -> bool: ...

    def records(self) -> list[dict]: ...

    @property
    def generation(self) -> int: ...


class JsonlLog:
    """Append-only JSONL file with a parsed-record cache.

    Every read of the store used to re-read and re-parse the whole file
    from disk. In watch mode the same file is walked many times per poll
    cycle — queue prioritization, memory lookups inside each
    investigation, dedup's anchor scan — so the cost was
    O(alerts x records) json.loads per cycle, growing with every day the
    desk runs.

    Caching alone did NOT fix that, which is the point of the byte offset
    below. A cache keyed only on (mtime, size) is invalidated by any
    write — and the watch loop's own last act on every alert is to append
    a record, so the next alert re-parsed the entire history. Measured
    before this change: ~2ms per alert against 1k records, ~506ms against
    100k, growing without bound.

    So the cache parses only what was APPENDED since it last looked,
    tracking the byte offset it has consumed. Cost per alert becomes
    O(new lines) instead of O(history). This is sound only because every
    writer in this project appends and nothing rewrites in place; the
    guards below detect when that assumption breaks (a different file, a
    truncation, any shrink) and fall back to a full re-parse rather than
    trusting a prefix that may have changed underneath.

    A half-written final line is never parsed: only bytes up to the last
    newline are consumed, so a reader that catches a writer mid-append
    sees the record on the next read, never a JSON error.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        # (st_dev, st_ino, st_mtime_ns, st_size) of the last look: an
        # exact match means nothing at all has happened to the file.
        self._state: tuple[int, int, int, int] | None = None
        self._offset = 0          # bytes consumed, always at a line boundary
        self._tail = b""          # last bytes consumed, to verify the prefix
        self._records: list[dict] = []
        # Bumped every time the record list is REBUILT rather than extended
        # (file replaced, truncated, or gone). Derived structures — the
        # store's query index — key their own validity on this: same
        # generation means their prefix of the list is still exactly what
        # they indexed, so they only need to index the new tail.
        self._generation = 0

    @property
    def generation(self) -> int:
        return self._generation

    def append(self, rec: dict) -> bool:
        """Append one record. A plain line-append, which is exactly the
        property the incremental read above depends on."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        return True

    def records(self) -> list[dict]:
        try:
            st = self.path.stat()
        except OSError:  # missing file: an empty store, not an error
            if self._state is not None or self._records:
                self._generation += 1    # a real wipe, not a repeat look
            self._state, self._offset = None, 0
            self._tail, self._records = b"", []
            return self._records
        state = (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)
        if state == self._state:
            return self._records
        reset = (
            self._state is None
            or state[:2] != self._state[:2]   # replaced (rename, recreate)
        )
        with self.path.open("rb") as f:
            if not reset and self._tail:
                # Splicing new bytes onto a prefix assumes the prefix is
                # still those bytes. Appending is all this project does,
                # but a file rewritten in place would otherwise graft a
                # new tail onto stale records — a corrupted view the old
                # read-everything code could not produce. Re-reading the
                # last few bytes we consumed is an O(1) check that the
                # ground has not moved. It subsumes truncation too: a file
                # shorter than our offset cannot return those bytes there,
                # so an explicit size check would be unreachable (mutation
                # testing proved it dead — no test could tell it apart).
                # The check is PROBABILISTIC, and honestly so: a rewrite
                # that reuses the inode and preserves both the byte at
                # our offset boundary and the exact final 64 bytes passes
                # it (observed in a test where two same-shape records
                # differed only mid-line). The supported rotation —
                # offline, see deploy/RUNBOOK.md — sidesteps the window
                # entirely; a same-size in-place rewrite under a running
                # process is outside the append-only contract.
                f.seek(self._offset - len(self._tail))
                reset = f.read(len(self._tail)) != self._tail
            # Everything below is staged in locals and committed to self
            # only once the parse has SUCCEEDED. Committing earlier would
            # advance the cache past a parse that never happened, and the
            # next call's fast path would then serve a silently TRUNCATED
            # history — a lost analyst ruling reading as "never overturned"
            # is far worse than the loud, repeatable error a bad line used
            # to cause (review catch: three lenses, independently).
            offset = 0 if reset else self._offset
            f.seek(offset)
            chunk = f.read()
        # stat-then-read is deliberate: a write landing between the two
        # leaves NEWER content cached under the OLDER state, so the next
        # read picks it up — never stale data, at worst one read late.
        consumed = chunk.rfind(b"\n") + 1     # whole lines only
        if consumed <= 0:
            # Nothing complete to add. Leave _state uncommitted so the next
            # call looks again: the file is mid-append, and the rest of that
            # line must not be skipped once the writer finishes it.
            if reset:
                self._generation += 1
                self._offset, self._records, self._tail = 0, [], b""
                self._state = state
            return self._records
        fresh = [
            json.loads(line)
            for line in chunk[:consumed].decode().splitlines()
            if line.strip()
        ]
        base = [] if reset else self._records
        if reset:
            self._generation += 1
        # Rebind rather than extend, so an iterator handed out before this
        # append keeps walking the snapshot it started on.
        self._records = base + fresh if fresh else base
        self._offset = offset + consumed
        self._tail = (
            (b"" if reset else self._tail) + chunk[:consumed]
        )[-_PREFIX_CHECK_BYTES:]
        self._state = state
        return self._records


# --- shared memory over Elasticsearch ---------------------------------------

# How long a shared log may serve its cached view before it asks the
# cluster for anything new. Every read of the store would otherwise be a
# round trip, and the store is read six or seven times per alert. Five
# seconds is far below the interval anything acts on (the watch loop
# polls in tens of seconds) and far above the cost of a round trip.
DEFAULT_MAX_STALENESS_SECONDS = 5.0

# How far back before its own tail a shared log re-reads on every look.
#
# A document written by another instance can land with a `written_at`
# BEHIND one this instance has already read, and a cursor that only ever
# moves forward would step over it permanently. Two things put it there:
# a write that took longer to become searchable, and CLOCK SKEW, which is
# the one that sets this number.
#
# The guarantee, stated exactly: a document written by another instance
# is seen if this lag exceeds the sum of the two hosts' clock errors.
# Ordering here is by wall-clock timestamps from writers nobody
# sequences, so that bound is not an implementation detail to be tuned
# away — it is what tailing such a log costs. Five minutes is far beyond
# what NTP-synced hosts drift and still only a few seconds of documents
# to re-read; a desk whose hosts can drift further than this needs its
# clocks fixed, and `--memory-status` measures the skew so the answer is
# not "memory is quietly incomplete".
DEFAULT_LAG_SECONDS = 300.0

# Documents per search page, and a backstop on pages so a mis-sorted
# response cannot spin forever.
_PAGE_SIZE = 1000
_MAX_PAGES = 10_000

# `record` is stored but NOT indexed. This is load-bearing, not tidiness:
# a record carries the full alert and investigation dumps, which between
# them can introduce hundreds of distinct field paths, and a dynamically
# mapped index hits `index.mapping.total_fields.limit` (1000 by default)
# and then starts REJECTING writes — the desk would silently stop
# remembering. Nothing here queries inside a record either: the seam is
# the log, so every predicate runs in Python over `_source`.
_MAPPING = {
    "mappings": {
        "dynamic": "strict",
        "properties": {
            "uid": {"type": "keyword"},
            "ledger": {"type": "keyword"},
            # Informational: readers take a record's provenance from the
            # `writer` INSIDE the record, which travels with it through
            # an export or an import. This copy exists so an operator can
            # query the index by writer without unpacking `record`, and
            # is written from the same value.
            "writer": {"type": "keyword"},
            "written_at": {"type": "date"},
            "record": {"type": "object", "enabled": False},
        },
    }
}


class ElasticLog:
    """One append-only ledger held in an Elasticsearch index, tailed.

    The read discipline is the JsonlLog's, in different coordinates. That
    log tracks a byte offset and re-verifies the last 64 bytes of the
    prefix before splicing an append onto it; this one tracks a
    (written_at, uid) cursor and re-reads the last `lag_seconds` of the
    prefix before splicing. Both are asking the same question — "is what
    I already hold still what the log says?" — and both answer a "no" the
    same way: bump the generation and let every derived structure rebuild.

    Ordering is by (written_at, uid), which is total and deterministic
    across writers: `uid` is generated client-side, used as the document
    `_id`, and indexed as a keyword purely to be the sort tiebreaker
    (sorting on `_id` itself needs fielddata Elasticsearch would rather
    not build). "Last one wins" semantics in the store therefore mean
    "latest written_at wins", which is the only ordering a shared log
    can offer — the local file's line order does not survive two writers.

    Reads FAIL LOUDLY. A store that answered "no prior sightings" because
    the cluster was unreachable would turn every safety gate that rests on
    memory off at exactly the moment nobody is watching, so an outage
    raises and the watch loop's own sick-cycle handling (and its
    dead-man's switch) takes it from there.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        index: str,
        ledger: str,
        writer: str,
        client: httpx.Client | None = None,
        max_staleness: float = DEFAULT_MAX_STALENESS_SECONDS,
        lag_seconds: float = DEFAULT_LAG_SECONDS,
        clock=time.monotonic,
        wall=_utcnow,
        page_size: int = _PAGE_SIZE,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.index = index
        self.ledger = ledger
        self.writer = writer
        self._client = client
        self._max_staleness = max_staleness
        self._lag_ms = int(lag_seconds * 1000)
        self._clock = clock
        self._wall = wall
        self._page_size = page_size
        self._records: list[dict] = []
        # (written_at as epoch millis, uid) per record, same order. Taken
        # from each hit's own `sort` values, so the local ordering is the
        # cluster's ordering rather than a re-parse of the timestamp.
        self._keys: list[tuple[int, str]] = []
        self._generation = 0
        self._fetched_at: float | None = None
        # Set by an append: the view is stale, but the CURSOR is not.
        # Distinct from `_fetched_at is None`, which means "this ledger
        # has never been read" and forces a full read.
        self._dirty = False
        self._seq = 0

    # --- HistoryLog ---------------------------------------------------------

    @property
    def generation(self) -> int:
        return self._generation

    def records(self) -> list[dict]:
        if (
            self._dirty
            or self._fetched_at is None
            or self._clock() - self._fetched_at >= self._max_staleness
        ):
            self.refresh()
        return self._records

    def append(self, rec: dict) -> bool:
        """Index one record and make it visible before returning.

        `refresh=wait_for` costs up to the index's refresh interval (a
        second by default) per append, and buys the contract the local
        file gives for free: append-then-read sees the record. Without it
        dedup's "has this alert already been really investigated?" check
        can answer NO about a record written moments earlier and suppress
        an alert whose verdict is on disk — the quiet direction, bought
        for a second of wall clock on a path that just spent seconds in a
        model call.

        The document id is generated here, which is what makes the write
        `replayable`: a retry of a create that already landed comes back
        409 rather than duplicating the record.
        """
        return self._put(rec, self._next_uid(), _utcnow())

    def _next_uid(self) -> str:
        """A unique id that SORTS in append order for this writer.

        Ordering is (written_at, uid), and written_at is only accurate to
        the millisecond — so two appends inside one millisecond are
        ordered by uid alone, and a random uid orders them by coin flip.
        The store's whole "the latest record for this alert wins"
        semantics rest on that comparison: two rulings synced for one
        alert in the same millisecond would resolve arbitrarily, and the
        one that won could be the one the analyst replaced.

        Fixed-width hex millis, then a per-process counter, then
        randomness for cross-writer uniqueness. Lexicographic order is
        therefore (millisecond, sequence) for our own records, which is
        append order, and stays unique against every other writer.
        """
        self._seq = (self._seq + 1) % 0xFFFFFF
        return (
            f"{_to_millis(_utcnow()):012x}"
            f"{self._seq:06x}{uuid.uuid4().hex[:12]}"
        )

    def import_record(self, rec: dict, uid: str, written_at: datetime) -> bool:
        """Append with a CALLER-CHOSEN id and write time. Migration only.

        Deliberately does NOT wait for each document to become
        searchable. `append` does, because the very next read may be a
        safety check on the record just written; an import has no such
        reader, and paying an index refresh per document turns a 50k
        record history into hours. `migrate_to_shared` refreshes once at
        the end instead.

        The id makes the import idempotent: a deterministic id derived from
        the record means a re-run collides with what it already wrote and
        reports it rather than duplicating the desk's memory. The write
        time matters just as much and is easier to get wrong — every
        migrated record stamped at the import instant would order by id,
        which is to say arbitrarily, and "the latest ruling per alert
        wins" would start resolving to a coin flip. The caller passes the
        record's own timestamp, made monotone.
        """
        return self._put(rec, uid, written_at, refresh="false")

    def refresh_index(self) -> None:
        """Make everything written so far searchable, once."""
        self._request("POST", f"/{self.index}/_refresh", replayable=True)

    def newest_written_at(self) -> datetime | None:
        """When the newest record this log holds was written, by its
        writer's clock. `--memory-status` compares it against the local
        clock: ordering here is by wall-clock timestamps from writers
        nobody sequences, so a desk whose clocks are further apart than
        `lag_seconds` has instances that cannot see each other's writes,
        and this is the only number that makes that visible.
        """
        if not self._keys:
            return None
        return _from_millis(self._keys[-1][0])

    def known_uids(self) -> set[str]:
        """Every document id already in this ledger.

        Only the dry run needs this: without it, `--dry-run` reports every
        record as new even when the real run would skip it as already
        present, which is the opposite of what an operator checking on a
        half-finished import wants to read.
        """
        body: dict = {
            "size": self._page_size,
            "track_total_hits": False,
            "_source": ["uid"],
            "sort": [{"written_at": "asc"}, {"uid": "asc"}],
            "query": {"bool": {"filter": [{"term": {"ledger": self.ledger}}]}},
        }
        uids: set[str] = set()
        for _ in range(_MAX_PAGES):
            hits = self._search(body)
            uids.update(h["_id"] for h in hits)
            if len(hits) < self._page_size:
                return uids
            body["search_after"] = hits[-1]["sort"]
        raise RuntimeError(
            f"shared memory: {self.index} would not finish listing "
            f"ledger '{self.ledger}'"
        )

    def _put(
        self, rec: dict, uid: str, written_at: datetime,
        refresh: str = "wait_for",
    ) -> bool:
        # Round to the resolution the index actually stores, so the key
        # kept here is exactly the key the cluster will sort on. Deriving
        # the stored string from the same integer removes any chance of
        # the local view and the tail disagreeing by one millisecond.
        millis = _to_millis(written_at)
        doc = {
            "uid": uid,
            "ledger": self.ledger,
            "writer": self.writer,
            "written_at": _from_millis(millis).isoformat(),
            "record": rec,
        }
        try:
            self._request(
                "PUT",
                f"/{self.index}/_create/{uid}",
                params={"refresh": refresh},
                json=doc,
                replayable=True,
            )
        except httpx.HTTPStatusError as e:
            # Already there: either our own retry landing twice, or a
            # re-run of an import that chose the same deterministic id.
            if e.response.status_code == 409:
                return False
            raise RuntimeError(
                f"shared memory: could not append to {self.index} "
                f"(HTTP {e.response.status_code}): {e.response.text[:300]}"
            ) from e
        except httpx.HTTPError as e:
            raise RuntimeError(
                f"shared memory: {self.index} unreachable on append: {e}"
            ) from e
        # Read-your-writes WITHOUT splicing the record in locally: the
        # `wait_for` above already makes it searchable, so invalidating
        # is enough and the view stays in the cluster's order rather than
        # this instance's.
        #
        # Splicing looked free and was not. Our record went on the end
        # with our timestamp, so any document another writer had produced
        # in between sorted BEFORE it — and the next re-read was then a
        # reorder rather than an append, which bumps the generation and
        # costs the query index a full O(history) rebuild. On a desk with
        # two active writers that is most reads. Letting the cluster
        # order everything makes the same re-read a plain append.
        #
        # `_dirty` and not `_fetched_at = None`: the view is stale, the
        # CURSOR is not. Clearing the cursor would make the next read
        # page the WHOLE ledger instead of the lag window — trading a
        # local rebuild for a full re-materialize over the network, on
        # every append (measured: 6 searches over 5001 documents instead
        # of 1). Our own record is stamped now, comfortably inside the
        # window, so `wait_for` still gives read-your-writes.
        self._dirty = True
        return True

    # --- tailing ------------------------------------------------------------

    def refresh(self) -> None:
        """Re-read the tail now, regardless of the staleness window."""
        floor_ms = self._floor()
        split = (
            0 if floor_ms is None
            else bisect_left(self._keys, (floor_ms, ""))
        )
        # Identity of the records inside the re-read window must survive
        # the re-read: callers memoize by row and treat records as the
        # same objects across calls.
        window = {
            uid: rec
            for (_, uid), rec in zip(self._keys[split:], self._records[split:])
        }
        keys, records = self._page_through(floor_ms, window)

        existing = self._keys[split:]
        if len(keys) >= len(existing) and keys[: len(existing)] == existing:
            # The prefix is still what it was: a pure append.
            self._records = self._records + records[len(existing):]
            self._keys = self._keys + keys[len(existing):]
        else:
            # A late arrival, a deletion, or a rewrite inside the window.
            # Splicing would put records out of order, so rebuild the
            # window and let every derived structure rebuild with it.
            # Records OLDER than the window are trusted to be settled —
            # the log is append-only by contract, and a deletion behind
            # the lag window is not something a tail can see.
            self._generation += 1
            self._records = self._records[:split] + records
            self._keys = self._keys[:split] + keys
        self._fetched_at = self._clock()
        self._dirty = False

    def _floor(self) -> int | None:
        """Where the re-read starts: a lag window behind the tail — but
        never ahead of the wall clock.

        Without the wall-clock cap the floor is monotone in whatever the
        index CONTAINS, and one document stamped in the future pushes it
        past every honest write that follows. The re-read then returns
        only that document, which is exactly what the pure-append check
        expects to see, so there is no generation bump, no error, and no
        end: the ledger is frozen for the life of the process while this
        instance's own writes keep arriving through the local splice and
        make it look healthy. A hostile write can do that on purpose; a
        container with a two-minute-fast clock does it to ITSELF on its
        first append, and then stops seeing the rest of the desk.

        Capping at now only ever widens the window, and a window that is
        too wide costs a re-read, which is the direction to be wrong in.

        The cap is not a fix for OUR OWN clock being wrong: an instance
        whose clock is fast stamps its appends fast and reads its own
        fast clock here, so both sides of the `min` move together. What
        protects that case is the lag being wider than the skew — see
        DEFAULT_LAG_SECONDS — and `--memory-status` reporting the skew it
        can measure.
        """
        if self._fetched_at is None or not self._keys:
            # Never actually read this ledger, so there is no prefix to
            # keep and nothing to anchor a window on — read all of it.
            # The `_fetched_at` half is the one that is easy to miss: an
            # append lands in `_keys` through the local splice, so a log
            # that is WRITTEN to before it is READ from would otherwise
            # anchor its first ever read on its own new record and fetch
            # only the lag window around it, discarding every older
            # record in the shared ledger — permanently, and with a
            # perfectly healthy-looking view of the recent tail.
            return None
        tail_ms = self._keys[-1][0]
        return min(tail_ms, _to_millis(self._wall())) - self._lag_ms

    def _page_through(
        self, floor_ms: int | None, window: dict[str, dict]
    ) -> tuple[list[tuple[int, str]], list[dict]]:
        filters: list[dict] = [{"term": {"ledger": self.ledger}}]
        if floor_ms is not None:
            # NOT clamped to zero. The local bisect below splits on this
            # same value, so a floor the query silently raised would make
            # the re-read return fewer rows than the window it is meant
            # to replace — which this method's caller reads as "the
            # prefix changed" and answers by REPLACING the window with
            # the short answer. A pre-epoch record (an import whose
            # source rows carried no timestamp) would empty the desk's
            # memory on the next read. epoch_millis takes negatives.
            filters.append({
                "range": {
                    "written_at": {
                        "gte": floor_ms, "format": "epoch_millis",
                    }
                }
            })
        body: dict = {
            "size": self._page_size,
            "track_total_hits": False,
            "sort": [{"written_at": "asc"}, {"uid": "asc"}],
            "query": {"bool": {"filter": filters}},
        }
        keys: list[tuple[int, str]] = []
        records: list[dict] = []
        for _ in range(_MAX_PAGES):
            hits = self._search(body)
            for hit in hits:
                key, rec = _materialize(hit, self.index)
                keys.append(key)
                # Same uid, same dict object as before.
                records.append(window.get(key[1], rec))
            if len(hits) < self._page_size:
                return keys, records
            body["search_after"] = hits[-1]["sort"]
        raise RuntimeError(
            f"shared memory: {self.index} returned more than "
            f"{_MAX_PAGES * self._page_size} documents for ledger "
            f"'{self.ledger}' without exhausting; refusing to page further"
        )

    def _search(self, body: dict) -> list[dict]:
        """One page of the tail, or a raised error.

        Elasticsearch answers a search whose shards partly failed, or
        which timed out, with HTTP 200 and the hits it MANAGED to
        collect. Reading only `hits` therefore turns a degraded cluster
        into a shorter ledger: the caller sees a re-read that does not
        match the window it holds, rebuilds from the short answer, and
        the desk runs with memory it does not know is missing. That is
        the quiet direction arriving as a green status code, so a partial
        answer is an error here — the same choice as an outage, for the
        same reason.
        """
        resp = self._request(
            "POST", f"/{self.index}/_search", json=body, replayable=True
        )
        payload = resp.json()
        shards = payload.get("_shards", {})
        failed = shards.get("failed") or 0
        if payload.get("timed_out") or failed:
            raise RuntimeError(
                f"shared memory: {self.index} answered a partial search "
                f"(timed_out={bool(payload.get('timed_out'))}, "
                f"failed_shards={failed} of {shards.get('total', '?')}). "
                f"Refusing to treat a short answer as the ledger."
            )
        return payload.get("hits", {}).get("hits", [])

    def _request(
        self, method: str, path: str, *, replayable: bool = False, **kwargs
    ) -> httpx.Response:
        try:
            return httpio.request_sync(
                method,
                f"{self.base_url}{path}",
                client=self._client,
                headers={
                    "Authorization": f"ApiKey {self.api_key}",
                    "Content-Type": "application/json",
                },
                replayable=replayable,
                **kwargs,
            )
        except httpx.HTTPStatusError:
            raise
        except httpx.HTTPError as e:
            raise RuntimeError(
                f"shared memory: {self.base_url} unreachable "
                f"({method} {path}): {e}"
            ) from e

    # --- provisioning -------------------------------------------------------

    def ensure_index(self) -> None:
        """Create the memory index if it is absent, and refuse to use one
        whose mapping would eventually start dropping writes.

        An index auto-created by a stray write maps `record` dynamically,
        which works right up until the field-count limit and then rejects
        every append — a desk that stops remembering without saying so.
        Checking is one request at startup.
        """
        try:
            mapping = self._request(
                "GET", f"/{self.index}/_mapping", replayable=True
            ).json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code != 404:
                raise RuntimeError(
                    f"shared memory: cannot read the mapping of "
                    f"{self.index} (HTTP {e.response.status_code}): "
                    f"{e.response.text[:300]}"
                ) from e
            self._create_index()
            return
        props = (
            mapping.get(self.index, {})
            .get("mappings", {})
            .get("properties", {})
        )
        record = props.get("record")
        if not isinstance(record, dict) or record.get("enabled") is not False:
            raise RuntimeError(
                f"shared memory: index '{self.index}' exists but does not "
                f"map `record` as a stored-not-indexed object. It was "
                f"probably auto-created by a write before the index was "
                f"provisioned; a dynamically mapped `record` hits the "
                f"field-count limit and then rejects appends silently. "
                f"Reindex it into a fresh index created by "
                f"`soc-copilot --memory-status`, or delete it if it holds "
                f"nothing you need."
            )

    def _create_index(self) -> None:
        try:
            self._request("PUT", f"/{self.index}", json=_MAPPING)
        except httpx.HTTPStatusError as e:
            # Another instance created it between our GET and our PUT.
            if "resource_already_exists" not in e.response.text:
                raise RuntimeError(
                    f"shared memory: could not create index {self.index} "
                    f"(HTTP {e.response.status_code}): "
                    f"{e.response.text[:300]}"
                ) from e
            # Losing the race is fine; assuming the winner created the
            # mapping WE would have is not. A stray write racing us
            # auto-creates a dynamically mapped index, which is exactly
            # the one this check exists to refuse.
            self.ensure_index()


def _materialize(hit: dict, index: str) -> tuple[tuple[int, str], dict]:
    """One search hit as ((written_at millis, uid), record).

    A document that does not carry a record object is a PARSE failure and
    is raised, not skipped — the same choice the JSONL log makes for an
    unparseable line, and for the same reason: a silently truncated
    history reads as "never seen, never overturned", which is the one
    answer memory must never invent. `dynamic: strict` keeps most
    malformed documents out of the index in the first place, but `record`
    itself is unvalidated by construction (that is what stored-not-indexed
    means), so this check is the only thing standing there.
    """
    sort = hit.get("sort")
    doc_id = hit.get("_id")
    if (
        not isinstance(sort, list)
        or len(sort) != 2
        or not isinstance(sort[0], int)
        or not isinstance(sort[1], str)
    ):
        raise RuntimeError(
            f"shared memory: document {doc_id!r} in {index} sorted as "
            f"{sort!r}; expected [written_at_millis, uid]"
        )
    record = hit.get("_source", {}).get("record")
    if not isinstance(record, dict):
        raise RuntimeError(
            f"shared memory: document {doc_id!r} in {index} carries "
            f"record={type(record).__name__}, not an object"
        )
    return (sort[0], sort[1]), record


# --- backends ---------------------------------------------------------------


class HistoryBackend(Protocol):
    """Where each of the store's ledgers lives."""

    shared: bool

    def log(self, ledger: str) -> HistoryLog: ...

    def describe(self) -> str: ...


class JsonlBackend:
    """Every ledger in a JSONL file. The zero-dependency default.

    A private memory: one process, one directory, filesystem permissions
    as the whole access-control story. Also strictly single-writer — two
    processes appending to one file interleave partial lines, and while
    the incremental reader is careful never to parse a half-written line,
    nothing makes two writers' lines whole. That is the honest reason
    sharing needed a different backend rather than a shared mount.
    """

    shared = False

    def __init__(self, path: str | Path) -> None:
        investigations = Path(path)
        self.paths: dict[str, Path] = {INVESTIGATIONS: investigations}
        for ledger in LEDGERS:
            if ledger != INVESTIGATIONS:
                self.paths[ledger] = investigations.with_name(
                    f"{ledger}.jsonl"
                )
        self._logs = {n: JsonlLog(p) for n, p in self.paths.items()}

    def log(self, ledger: str) -> HistoryLog:
        return self._logs[ledger]

    def describe(self) -> str:
        return f"local JSONL at {self.paths[INVESTIGATIONS].parent}"


class ElasticBackend:
    """The shared ledgers in one Elasticsearch index; the rest still local.

    WHAT IS SHARED IS A SAFETY DECISION. Two of the five ledgers are
    shared and three are not, and the line is not about size:

    - `investigations` (shared) is EVIDENCE. More of it is strictly
      better for every reader that consumes it in the loud direction:
      prior sightings, campaign correlation, the analyst-overturn block.
    - `dispositions` (shared) is GROUND TRUTH. An analyst ruling is the
      most valuable thing on the desk and the thing a second analyst most
      needs to see; a ruling that only one instance can read is a safety
      gate that fires for one person.
    - `created_alerts` (local) is a TRUST ledger — the set of alert ids
      whose synced rulings this copilot will believe. It exists precisely
      because a self-asserted label is not provenance, and putting it
      somewhere a second writer can extend would hand back the property
      the ruling-provenance work bought.
    - `closures` (local) records what THIS instance did autonomously —
      and it is read in the QUIET direction, which settles it. The
      morning digest marks an entry `auto_closed` with its reason, and
      the briefing is told not to present those as waiting on a human;
      a closure record is therefore a way to make an alert look already
      handled. Local, it can only ever say that about alerts this
      instance really closed. The cost is a metric, not a risk: the
      scorecard's automation rate counts the whole desk's
      investigations against this instance's closures, so it UNDERSTATES
      automation in shared mode — the safe direction for that number,
      and stated in the README rather than quietly corrected.
    - `watch_progress` (local) is one loop's cursor through its own
      cycle. Sharing it would let one instance resume — and re-push, and
      re-acknowledge — an alert another instance is working right now.

    Writes are not routed by this class: each ledger simply gets the log
    it should have, and the store above appends to whichever it is given.
    """

    shared = True

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        index: str,
        writer: str,
        local_path: str | Path,
        client: httpx.Client | None = None,
        max_staleness: float = DEFAULT_MAX_STALENESS_SECONDS,
        lag_seconds: float = DEFAULT_LAG_SECONDS,
        clock=time.monotonic,
    ) -> None:
        self.base_url = base_url
        self.index = index
        self.writer = writer
        local = JsonlBackend(local_path)
        # Only the local ledgers have files, so `paths` is exactly the set
        # a file-shaped operation (retention, `store.path`) may touch —
        # and asking for the investigations file in shared mode raises
        # instead of silently rotating a file nobody writes any more.
        self.paths = {
            n: p for n, p in local.paths.items() if n not in SHARED_LEDGERS
        }
        self._logs: dict[str, HistoryLog] = {}
        for ledger in LEDGERS:
            if ledger in SHARED_LEDGERS:
                self._logs[ledger] = ElasticLog(
                    base_url=base_url,
                    api_key=api_key,
                    index=index,
                    ledger=ledger,
                    writer=writer,
                    client=client,
                    max_staleness=max_staleness,
                    lag_seconds=lag_seconds,
                    clock=clock,
                )
            else:
                self._logs[ledger] = local.log(ledger)

    def log(self, ledger: str) -> HistoryLog:
        return self._logs[ledger]

    @property
    def lag_seconds(self) -> float:
        log = self._logs[INVESTIGATIONS]
        assert isinstance(log, ElasticLog)
        return log._lag_ms / 1000.0

    def ensure_index(self) -> None:
        # Every shared ledger shares one index, so provisioning it once is
        # enough; the check is cheap and the first log is as good as any.
        log = self._logs[INVESTIGATIONS]
        assert isinstance(log, ElasticLog)
        log.ensure_index()

    def describe(self) -> str:
        return (
            f"shared memory: {'/'.join(sorted(SHARED_LEDGERS))} in "
            f"{self.index} on {self.base_url} as writer '{self.writer}'; "
            f"{'/'.join(n for n in LEDGERS if n not in SHARED_LEDGERS)} "
            f"local at {self.paths[CLOSURES].parent}"
        )


def instance_id(cfg) -> str:
    """This instance's writer identity.

    Defaults to the hostname, which is stable across restarts — the point
    of the identity is "records this desk wrote", and a pid would make
    every restart a different writer and every record before it foreign.
    """
    return getattr(cfg, "INSTANCE_ID", None) or socket.gethostname()


def open_backend(
    cfg,
    *,
    client: httpx.Client | None = None,
    allow_cold: bool = False,
    **kwargs,
) -> HistoryBackend:
    """The backend the configuration asks for.

    `allow_cold=True` skips the empty-shared-memory refusal below; the
    migration command passes it, because filling an empty shared index is
    the one thing that is supposed to start from empty.
    """
    backend = getattr(cfg, "HISTORY_BACKEND", "jsonl")
    if backend == "jsonl":
        _refuse_silent_revert(Path(cfg.HISTORY_PATH))
        return JsonlBackend(cfg.HISTORY_PATH)
    if backend != "elastic":
        raise RuntimeError(
            f"HISTORY_BACKEND must be 'jsonl' or 'elastic', got {backend!r}"
        )
    cfg.require("ELASTIC_URL", "ELASTIC_API_KEY")
    shared = ElasticBackend(
        base_url=cfg.ELASTIC_URL,
        api_key=cfg.ELASTIC_API_KEY,
        index=cfg.ELASTIC_MEMORY_INDEX,
        writer=instance_id(cfg),
        local_path=cfg.HISTORY_PATH,
        client=client,
        **kwargs,
    )
    shared.ensure_index()
    _mark_shared(Path(cfg.HISTORY_PATH), cfg.ELASTIC_MEMORY_INDEX)
    if not allow_cold:
        _refuse_silent_cold_start(
            shared, Path(cfg.HISTORY_PATH), instance_id(cfg)
        )
    return shared


def _marker_path(local_path: Path) -> Path:
    return Path(local_path).with_name(SHARED_MARKER)


def _mark_shared(local_path: Path, index: str) -> None:
    """Record that this desk ran on shared memory. Best effort: a desk
    that cannot write here still works, it just loses the guard below."""
    marker = _marker_path(local_path)
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(f"{index}\n")
    except OSError:
        pass


def _refuse_silent_revert(local_path: Path) -> None:
    """Refuse to fall back to local files on a desk that was sharing.

    The mirror image of the cold-start refusal, and the same loss in the
    same direction. `HISTORY_BACKEND` DEFAULTS to jsonl, so losing one
    line of a unit file — or starting the process from a shell that never
    read it — silently swaps a desk's whole memory for whatever stale
    local files happen to be sitting there: every prior sighting and
    every analyst ruling written since the migration, gone, with a
    perfectly healthy-looking history underneath. Reverting on purpose is
    one `rm` away, and saying so is the point.
    """
    marker = _marker_path(local_path)
    if not marker.exists():
        return
    try:
        index = marker.read_text().strip()
    except OSError:
        index = "the shared index"
    raise RuntimeError(
        f"this desk last ran on shared memory ({index}), and "
        f"HISTORY_BACKEND is now 'jsonl'. Falling back to {local_path} "
        f"would silently swap the desk's memory for whatever these local "
        f"files still hold — every prior sighting and analyst ruling "
        f"written since the migration would be invisible to the safety "
        f"gates. Set HISTORY_BACKEND=elastic (with ELASTIC_URL and "
        f"ELASTIC_API_KEY), or delete {marker} to go back to local "
        f"memory on purpose."
    )


def _refuse_silent_cold_start(
    backend: ElasticBackend, local_path: Path, writer: str
) -> None:
    """Refuse to start when THIS instance has a local ledger that shared
    memory has never seen.

    Starting anyway is a silent amnesia: prior sightings gone, analyst
    rulings that block an autonomous closure gone, dedup anchors gone —
    the safety net turned off by a configuration change, in the quiet
    direction, with nothing in the log to say so.

    The test is "shared memory holds nothing this instance wrote", not
    "shared memory is empty". Emptiness only protects the FIRST desk to
    join: the second analyst to flip the switch finds a shared index full
    of someone else's records, sails past an emptiness check, and
    abandons their own rulings — which is the same loss, arriving later
    and quieter.

    EVERY shared ledger is checked separately. A desk whose
    investigations migrated but whose rulings did not looks completely
    healthy — full history, sensible reports — while the one gate that
    lets a human overrule autonomous closure quietly matches nothing.
    """
    local = JsonlBackend(local_path)
    for ledger in sorted(SHARED_LEDGERS):
        path = local.paths[ledger]
        try:
            populated = path.stat().st_size > 0
        except OSError:
            continue
        if not populated:
            continue
        if any(
            rec.get("writer") == writer
            for rec in backend.log(ledger).records()
        ):
            continue
        raise RuntimeError(
            f"shared memory ({backend.index}) holds no '{ledger}' records "
            f"written by '{writer}', but {path} does. Starting like this "
            f"would silently discard what the safety gates read — so say "
            f"which you mean: run `soc-copilot --migrate-memory` to import "
            f"this instance's history into shared memory, or move {path} "
            f"aside to join the shared desk without it."
        )


# --- migration --------------------------------------------------------------


def migrate_to_shared(
    local: JsonlBackend,
    shared: ElasticBackend,
    *,
    writer: str,
    dry_run: bool = False,
) -> dict[str, tuple[int, int, int]]:
    """Copy the shared ledgers out of a local history into shared memory.

    Returns {ledger: (imported, already_there, writer_stamped)}.

    Idempotent by construction: each document's id is a hash of the
    ledger, the record, and WHICH occurrence of that record this is, so a
    second run collides with the first and reports what was already there
    instead of doubling the desk's memory. That property is why this is
    safe to re-run after a partial failure, which matters because there is
    no transaction here — an import that dies halfway has really written
    half.

    The occurrence counter is the part that is easy to leave out and
    wrong to. A content hash alone silently collapses two byte-identical
    lines into one document, so an import would quietly change how many
    records the desk has and then report the copy it dropped as "already
    present". Numbering repeats keeps the import faithful while staying
    stable under the two things that actually happen to these files:
    appending (positions of existing records do not move) and rotation
    (records leave from the front, and the survivors' ids either already
    exist or were never written).

    Order is preserved exactly, because the store's semantics depend on
    it: "the latest ruling per alert wins" is decided by write time in
    shared memory, so a migration that stamped every record at the import
    instant would resolve two rulings on one alert by document id. Each
    record is written at its OWN timestamp, made monotone against the
    record before it — the same cumulative-maximum trick the query index
    uses on `investigated_at`, and for the same reason: a clock that
    stepped back must not let a record hide before its predecessor. The
    step is a MILLISECOND rather than the smallest thing Python can
    represent, because a millisecond is the finest distinction the index
    keeps; a microsecond step would collapse on write and hand the order
    back to the document ids, which for an import are content hashes.

    The local-only ledgers are deliberately not copied. What this desk
    autonomously closed, what it created in TheHive, and where its watch
    loop is are not facts about the world that a second instance should
    inherit; see ElasticBackend for the line.
    """
    out: dict[str, tuple[int, int, int]] = {}
    for ledger in sorted(SHARED_LEDGERS):
        target = shared.log(ledger)
        assert isinstance(target, ElasticLog)
        imported = already = stamped_count = 0
        previous = _EPOCH_DT
        seen: dict[str, int] = {}
        present = target.known_uids() if dry_run else set()
        for rec in local.log(ledger).records():
            # The id is derived from the record AS IT IS IN THE FILE, so
            # a re-run under a different INSTANCE_ID collides with the
            # first import instead of duplicating every legacy record
            # under a new identity.
            fingerprint = _content_hash(ledger, rec)
            stamped = dict(rec)
            if not stamped.get("writer"):
                # Records written before writers existed. Importing them
                # is the operator asserting they are this desk's own —
                # which is what re-enables dedup and resume over them, so
                # the command says out loud how many it stamped.
                stamped["writer"] = writer
                stamped_count += 1
            when = _record_time(stamped, ledger)
            when = max(when, previous + _MILLISECOND)
            previous = when
            occurrence = seen.get(fingerprint, 0)
            seen[fingerprint] = occurrence + 1
            uid = _import_uid(fingerprint, occurrence)
            if dry_run:
                # Reported against what is REALLY there: a dry run that
                # calls every record new is the opposite of what an
                # operator checking on a half-finished import wants.
                if uid in present:
                    already += 1
                else:
                    imported += 1
                continue
            if target.import_record(stamped, uid, when):
                imported += 1
            else:
                already += 1
        if not dry_run and imported:
            # One refresh for the whole ledger, since the per-document
            # writes deliberately skipped theirs.
            target.refresh_index()
        out[ledger] = (imported, already, stamped_count)
    return out


# The floor an undated record sinks to. The Unix epoch rather than
# datetime.min: both are "older than any real record" and both preserve
# order once the monotone pass lifts them, but only one of them stays
# inside the range of timestamps the rest of this file reasons about — a
# year-1 stamp is a large NEGATIVE epoch-millis, and the tail's range
# floor is compared against exactly those millis.
_EPOCH_DT = _EPOCH_UTC
# The field each ledger stamps at write time.
_TIME_FIELD = {INVESTIGATIONS: "investigated_at", DISPOSITIONS: "recorded_at"}


def _record_time(rec: dict, ledger: str) -> datetime:
    """A record's own write time, or the epoch when it has none.

    The epoch is not a guess at the truth — it is a floor. The monotone
    pass above lifts it to just after its predecessor, so an undated
    record keeps its position in the file rather than acquiring a
    plausible-looking date it never had.
    """
    raw = rec.get(_TIME_FIELD[ledger])
    if not isinstance(raw, str):
        return _EPOCH_DT
    try:
        when = datetime.fromisoformat(raw)
    except ValueError:
        return _EPOCH_DT
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def _content_hash(ledger: str, rec: dict) -> str:
    payload = json.dumps(
        {"ledger": ledger, "record": rec}, sort_keys=True, default=str
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _import_uid(fingerprint: str, occurrence: int) -> str:
    """A document id that depends only on what is being imported, and on
    which copy of it this is."""
    return hashlib.sha256(
        f"{fingerprint}:{occurrence}".encode()
    ).hexdigest()[:32]

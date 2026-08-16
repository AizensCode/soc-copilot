"""Alert history — the copilot's cross-alert memory.

Every completed investigation is persisted, indexed by the indicators it
involved. When a new alert arrives, the store surfaces past investigations that
touched the same IOCs — the context a human analyst keeps in their head ("this
IP was flagged true_positive last week").

Backed by a JSONL file (one investigation record per line): appends are cheap,
no new dependency, and it matches the project's existing file-based persistence.
The interface is deliberately backend-agnostic — a SQLite implementation could
replace it without touching callers.
"""
import bisect
import ipaddress
import json
import re
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import (
    Alert,
    Correlation,
    Investigation,
    PriorSighting,
    RelatedAlert,
)

# Default temporal window for campaign correlation. Overridable via config.
DEFAULT_WINDOW_HOURS = 72
# How many related prior alerts make this a "campaign" (current + this many).
CAMPAIGN_MIN_RELATED = 2

_TCODE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

# How many trailing bytes of the already-parsed prefix to re-verify before
# splicing an append onto it. Enough to catch a rewritten file, O(1) to read.
_PREFIX_CHECK_BYTES = 64


def alert_host(alert: Alert) -> str | None:
    """The alert's host as a plain string, whichever shape it arrived in.

    Native fixtures carry raw_log["host"] as a string; ECS-normalized
    alerts carry the ECS object ({"name": ...}). Memory must compare
    hosts across both shapes or an ECS alert and a native alert about
    the same machine would never correlate.
    """
    host = alert.raw_log.get("host") if isinstance(alert.raw_log, dict) else None
    if isinstance(host, dict):
        host = host.get("name")
    return host if isinstance(host, str) and host else None


def alert_iocs(alert: Alert) -> list[str]:
    """Flatten an alert's indicators into a de-duplicated list of IOC strings."""
    seen: list[str] = []
    for values in alert.indicators.values():
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, str) and value not in seen:
                seen.append(value)
    return seen


def _ipv4s(values: list[str]) -> list[str]:
    """Keep only the entries that parse as IPv4 addresses."""
    out: list[str] = []
    for v in values:
        try:
            if isinstance(ipaddress.ip_address(v), ipaddress.IPv4Address):
                out.append(v)
        except ValueError:
            continue
    return out


def _same_24(a: str, b: str) -> bool:
    """True if two IPv4 addresses share a /24 but are not identical."""
    if a == b:
        return False
    net = ipaddress.ip_network(f"{a}/24", strict=False)
    return ipaddress.ip_address(b) in net


def _parent_tcodes(techniques: list[str]) -> set[str]:
    """Parent-family T-codes from a list of technique strings (T1566.002 -> T1566)."""
    codes: set[str] = set()
    for t in techniques:
        for code in _TCODE_RE.findall(t):
            codes.add(code.split(".")[0])
    return codes


class _CachedJsonl:
    """Parsed-record cache for one append-only JSONL file.

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

    Three contracts callers rely on:
    - Records are the SAME dict objects across calls. Callers treat them
      as read-only (every store reader builds new structures; the one
      annotator, latest_record, copies first). Mutating one in place
      would poison every later read until the file next changes.
    - A re-parse or an append REBINDS the list, never mutates it, so an
      iterator handed out earlier keeps walking its own snapshot.
    - A half-written final line is never parsed: only bytes up to the
      last newline are consumed, so a reader that catches a writer
      mid-append sees the record on the next read, never a JSON error.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
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
        self.generation = 0

    def records(self) -> list[dict]:
        try:
            st = self.path.stat()
        except OSError:  # missing file: an empty store, not an error
            if self._state is not None or self._records:
                self.generation += 1     # a real wipe, not a repeat look
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
                self.generation += 1
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
            self.generation += 1
        # Rebind rather than extend, so an iterator handed out before this
        # append keeps walking the snapshot it started on.
        self._records = base + fresh if fresh else base
        self._offset = offset + consumed
        self._tail = (
            (b"" if reset else self._tail) + chunk[:consumed]
        )[-_PREFIX_CHECK_BYTES:]
        self._state = state
        return self._records


def _net24(value: object) -> str | None:
    """The /24 network key for anything ip_address() reads as IPv4, or
    None. The input domain is deliberately as WIDE as the readers'
    predicates: ipaddress.ip_address accepts ints (a hand-imported
    record can carry a JSON-number IOC), and the original _same_24 scan
    matched those — so the network is built from the PARSED address,
    which renders dotted-quad whatever the input shape. Building it
    from the raw value crashed correlate on exactly the records the
    full scan handled (review catch, reproduced end to end)."""
    try:
        ip = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None
    if not isinstance(ip, ipaddress.IPv4Address):
        return None
    return str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)


_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


class _RecordIndex:
    """Query indexes over one _CachedJsonl's records.

    The incremental cache removed the PARSE cost; these remove the SCAN
    cost. Every hot reader used to walk all of history per alert —
    prior_sightings and correlate looking for shared infrastructure,
    dedup's anchor scan looking for a recent same-fingerprint record —
    which is O(history) by construction and was the dominant per-alert
    term once parsing went incremental (61+17+15ms of the ~95ms at 50k
    records).

    The design rule that keeps this SAFE: indexes only PRESELECT
    candidate rows; every caller re-applies its original per-record
    predicates to each candidate. An index bug can therefore only make a
    query slower (too many candidates) or incomplete (a missing posting)
    — never accept a record the old scan would have rejected — and the
    equivalence tests in tests/test_history_index.py hold indexed and
    brute-force results equal on randomized stores.

    Four posting maps (row = position in the records list, file order):
    - ioc_rows:   IOC string -> rows whose record lists that IOC
    - host_rows:  host       -> rows on that host
    - net24_rows: IPv4 /24   -> rows with an IPv4 IOC in that network
      (correlate's related_ip signal needs neighbors, not equality)
    - id_rows:    alert_id   -> rows for that alert (latest_record,
      dedup's already-investigated and analyst-overturn checks)

    And one time array for dedup's window: investigated_at is stamped at
    write time, so it is monotone in file order — modulo clock steps,
    which is why the bisect runs over the CUMULATIVE MAX of the parsed
    times (a sorted sequence by construction) rather than the raw
    values: a row can never hide before the window's start position,
    because cummax[j] < cutoff implies that row's own time is below the
    cutoff too. Unparseable or missing times index as the previous max
    (they cannot advance the clock); naive times are assumed UTC.

    Maintenance mirrors the cache: same generation -> the already-indexed
    prefix is untouched, index only the new tail; a generation bump
    (file replaced, truncated, gone) -> rebuild from scratch.
    """

    def __init__(self, cache: _CachedJsonl) -> None:
        self._cache = cache
        self._generation = cache.generation - 1   # force first build
        self._count = 0
        self.rows: list[dict] = []
        self.ioc_rows: dict[str, list[int]] = {}
        self.host_rows: dict[str, list[int]] = {}
        self.net24_rows: dict[str, list[int]] = {}
        self.id_rows: dict[str, list[int]] = {}
        self.inv_cummax: list[datetime] = []
        # The alert timestamp, parsed once per record instead of once per
        # (record, query) — at 50k records the per-candidate fromisoformat
        # was most of correlate's remaining cost. None where the field is
        # missing or unparseable; readers FALL BACK to the original
        # expression there, so those records fail exactly as the full
        # scan failed (loudly), never silently skip.
        self.ts: list[datetime | None] = []
        # Scratch space for derived per-row values owned by CALLERS (e.g.
        # dedup memoizes record fingerprints under "fingerprint"). Cleared
        # whenever the index rebuilds; within a generation rows only ever
        # append, so a value memoized by row number can never go stale.
        self.memo: dict[str, dict] = {}

    def sync(self) -> list[dict]:
        """Bring the index up to date; return the records it indexes."""
        records = self._cache.records()
        if self._cache.generation != self._generation:
            self._generation = self._cache.generation
            self._count = 0
            self.ioc_rows, self.host_rows = {}, {}
            self.net24_rows, self.id_rows = {}, {}
            self.inv_cummax = []
            self.ts = []
            self.memo = {}
        for row in range(self._count, len(records)):
            self._add(row, records[row])
            # Committed per row, not per batch: if a future _add ever
            # raises mid-batch, a retry must not re-post the rows that
            # already succeeded (duplicated postings, misaligned arrays —
            # review catch).
            self._count = row + 1
        self.rows = records
        return records

    def _add(self, row: int, rec: object) -> None:
        """Index one record. Total over anything json.loads can produce:
        every field access is isinstance-guarded, so a malformed line
        degrades to an unindexed (never-preselected) row instead of
        crashing EVERY indexed reader at build time — the full scans
        crashed only the queries that touched the bad record, and the
        index must not widen that blast radius (review catch). The two
        parallel arrays are appended exactly once per row, on every
        path, so they can never fall out of alignment with rows."""
        ts_parsed: datetime | None = None
        prev = self.inv_cummax[-1] if self.inv_cummax else _EPOCH
        when = prev
        if isinstance(rec, dict):
            iocs = rec.get("iocs")
            # A string value degrades to its characters — the same shape
            # set(rec.get("iocs", [])) gave the full scans. Anything
            # non-iterable is skipped (the scans crashed there; a record
            # that can't be indexed can still be reached via its other
            # postings, where the reader's own access fails as before).
            if isinstance(iocs, (list, str)):
                for ioc in iocs:
                    if isinstance(ioc, str):
                        self.ioc_rows.setdefault(ioc, []).append(row)
                    # net24 postings take the READERS' domain, not the
                    # string domain: _ipv4s and the /24 pair check accept
                    # ints, so a numeric IOC must still be preselected
                    # (review catch: it silently vanished from correlate).
                    net = _net24(ioc)
                    if net is not None:
                        self.net24_rows.setdefault(net, []).append(row)
            host = rec.get("host")
            if isinstance(host, str) and host:
                self.host_rows.setdefault(host, []).append(row)
            alert_id = rec.get("alert_id")
            # Any JSON scalar: the joins this index serves were plain
            # dict lookups (rulings.get(rec["alert_id"])), which match
            # non-string ids too — a string-only index silently dropped
            # an analyst overturn keyed by a numeric id (review catch).
            if alert_id is not None and not isinstance(alert_id, (list, dict)):
                self.id_rows.setdefault(alert_id, []).append(row)
            ts = rec.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts_parsed = datetime.fromisoformat(ts)
                except ValueError:
                    ts_parsed = None
            raw = rec.get("investigated_at")
            if isinstance(raw, str):
                try:
                    parsed = datetime.fromisoformat(raw)
                except ValueError:
                    parsed = None
                if parsed is not None:
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    when = max(prev, parsed)
        self.ts.append(ts_parsed)
        self.inv_cummax.append(when)

    def rows_since(self, cutoff: datetime) -> int:
        """First row that could carry investigated_at >= cutoff. Every
        earlier row is provably below the cutoff (see class docstring);
        rows from here on still get the caller's exact time filter."""
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)
        return bisect.bisect_left(self.inv_cummax, cutoff)

    def candidate_rows(
        self,
        iocs: set[str] | None = None,
        host: str | None = None,
        ips: list[str] | None = None,
    ) -> list[int]:
        """Sorted union of rows sharing any given signal — file order, so
        callers that keep 'first record per alert_id' semantics see the
        same record the full scan saw."""
        rows: set[int] = set()
        for ioc in iocs or ():
            rows.update(self.ioc_rows.get(ioc, ()))
        if host:
            rows.update(self.host_rows.get(host, ()))
        for ip in ips or ():
            net = _net24(ip)
            if net is not None:
                rows.update(self.net24_rows.get(net, ()))
        return sorted(rows)


class AlertHistoryStore:
    """Persist investigations and look them up by shared indicator.

    Beside the investigations file lives a dispositions file
    (dispositions.jsonl): analyst rulings synced back from case
    management. The copilot's own verdicts are opinions; a human ruling
    on one of them is ground truth, and prior sightings carry both so
    the model can never cite an overturned opinion as unchallenged.

    Reads go through per-file parsed-record caches (_CachedJsonl) that
    parse only what was appended since the last look, so a long-running
    watch never re-parses its whole history. Writes are unchanged: plain
    appends, which is exactly the property the incremental read depends
    on.

    The incremental cache removed the PARSE cost; the query index
    (_RecordIndex) removed the SCAN cost that then dominated. Measured
    at 50k records (~90MB synthetic, timings the medians of repeated
    calls on this dev machine): prior_sightings 19ms -> 0.08ms (2ms when
    the probe carries an IOC present in ~1k records), dedup's
    find_anchor 16ms -> 0.2ms (window bisect + memoized fingerprints),
    correlate 51-69ms -> 9-11ms. Correlate's residual is honest and
    data-dependent: it is O(candidate rows) — rows sharing an IOC, a
    /24, or a host — and the benchmark deliberately packs 2000 IPs into
    eight /24s, so thousands of rows qualify; a sparser environment
    pays proportionally less, a denser one more. Building the index
    costs ~330-350ms once per process at that size (on top of ~650-750ms
    cold parse; the build is now timed by the same bench script as every
    other number here — the first draft said ~150ms from memory, the one
    figure with no provenance, and it was ~2x off: review catch), then
    stays warm via the same append-only incremental discipline as the
    cache.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.dispositions_path = self.path.with_name("dispositions.jsonl")
        self.closures_path = self.path.with_name("closures.jsonl")
        self.created_alerts_path = self.path.with_name("created_alerts.jsonl")
        self._records_cache = _CachedJsonl(self.path)
        self._dispositions_cache = _CachedJsonl(self.dispositions_path)
        self._closures_cache = _CachedJsonl(self.closures_path)
        self._created_alerts_cache = _CachedJsonl(self.created_alerts_path)
        self._record_index = _RecordIndex(self._records_cache)

    def _iter_records(self) -> Iterator[dict]:
        yield from self._records_cache.records()

    def _index(self) -> _RecordIndex:
        """The synced query index over the investigations file. Internal:
        used by this class's own readers and by dedup's scans (which
        already live inside the store's privacy boundary)."""
        self._record_index.sync()
        return self._record_index

    def record_disposition(
        self,
        alert_id: str,
        human_verdict: str,
        source: str,
        summary: str | None = None,
    ) -> None:
        """Append an analyst ruling for a previously investigated alert.

        Append-only like the investigations file; the latest record per
        alert_id wins, so a re-opened and re-ruled case simply appends.
        """
        rec = {
            "alert_id": alert_id,
            "human_verdict": human_verdict,
            "source": source,
            "summary": summary,
            # When the ruling was SYNCED (not when the analyst clicked in
            # TheHive) — enough for "what came back since yesterday".
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        self.dispositions_path.parent.mkdir(parents=True, exist_ok=True)
        with self.dispositions_path.open("a") as f:
            f.write(json.dumps(rec) + "\n")

    def dispositions(self) -> dict[str, dict]:
        """Latest analyst ruling per alert_id.

        The mapping is built fresh per call (callers may .pop() it);
        the record dicts inside are the cache's — read-only by contract.
        """
        out: dict[str, dict] = {}
        for rec in self._dispositions_cache.records():
            out[rec["alert_id"]] = rec
        return out

    def record_created_alert(self, alert_id: str, thehive_id: str) -> None:
        """Record that THIS copilot created a TheHive alert for `alert_id`
        (sourceRef) as TheHive object `thehive_id`.

        This is the provenance ledger that gates the feedback loop. A synced
        analyst ruling is only trusted for an alert_id present here — because
        the alternative, trusting any TheHive alert that merely carries
        type='soc-copilot', is trusting a self-asserted label: anyone able to
        POST an alert into the feed could otherwise forge a ruling for any
        alert_id and poison the copilot's accuracy record and its
        precedent-aware closure. Written at create-alert time (main's
        _maybe_open_case), same append-only sidecar pattern as closures."""
        rec = {
            "alert_id": alert_id,
            "thehive_id": thehive_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.created_alerts_path.parent.mkdir(parents=True, exist_ok=True)
        with self.created_alerts_path.open("a") as f:
            f.write(json.dumps(rec) + "\n")

    def created_alerts(self) -> dict[str, str]:
        """alert_id (sourceRef) -> the latest TheHive object id we created
        for it. The trusted set for the feedback loop."""
        out: dict[str, str] = {}
        for rec in self._created_alerts_cache.records():
            out[rec["alert_id"]] = rec.get("thehive_id", "")
        return out

    def record_closure(self, alert_id: str, reason: str | None) -> None:
        """Append an AUTONOMOUS closure event (watch mode's --auto-close
        actually firing). Until this existed the decision was pushed to
        Elastic and then forgotten locally, so the desk's automation rate
        — the whole point of autonomous closure — could not be computed
        from the store. Sidecar file, same append-only pattern as
        dispositions: what the copilot DID is a different kind of fact
        from what it CONCLUDED, and neither overwrites the other."""
        rec = {
            "alert_id": alert_id,
            "reason": reason,
            "closed_at": datetime.now(timezone.utc).isoformat(),
        }
        self.closures_path.parent.mkdir(parents=True, exist_ok=True)
        with self.closures_path.open("a") as f:
            f.write(json.dumps(rec) + "\n")

    def closures(self) -> dict[str, dict]:
        """Latest autonomous-closure event per alert_id."""
        out: dict[str, dict] = {}
        for rec in self._closures_cache.records():
            out[rec["alert_id"]] = rec
        return out

    def record(self, alert: Alert, investigation: Investigation) -> None:
        """Append a record for a completed investigation.

        The summary fields (verdict, iocs, techniques...) are what memory
        lookups read on every alert; the full alert and investigation dumps
        exist so the copilot can later answer questions about its own
        reasoning (--ask) instead of remembering only its conclusion.
        Records written before these fields existed simply lack them.
        """
        rec = {
            "alert_id": alert.alert_id,
            # The alert's own time vs when the copilot worked it: memory
            # correlates on the former, the daily digest windows on the
            # latter. Records written before investigated_at existed
            # simply lack it (and fall outside any digest window).
            "timestamp": alert.timestamp.isoformat(),
            "investigated_at": datetime.now(timezone.utc).isoformat(),
            "title": alert.title,
            "verdict": investigation.verdict,
            "confidence": investigation.confidence,
            "host": alert_host(alert),
            "iocs": alert_iocs(alert),
            "attack_techniques": investigation.attack_techniques,
            # Flattened beside the summary fields (not only inside the
            # investigation dump) so cost/latency reporting never has to
            # parse a full record per row.
            "cost_usd": tel.cost_usd if (tel := investigation.telemetry) else None,
            "duration_seconds": tel.duration_seconds if tel else None,
            # Flattened so dedup's anchor scan and the digest can skip
            # suppressed records without parsing the investigation dump.
            "duplicate_of": investigation.duplicate_of,
            "alert": alert.model_dump(mode="json"),
            "investigation": investigation.model_dump(mode="json"),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(json.dumps(rec) + "\n")

    def latest_record(self, alert_id: str) -> dict | None:
        """The most recent investigation record for an alert, with the
        analyst's ruling (if any) joined in under "ruling"."""
        index = self._index()
        rows = index.id_rows.get(alert_id)
        found = index.rows[rows[-1]] if rows else None  # last line wins
        if found is None:
            return None
        ruling = self.dispositions().get(alert_id)
        if ruling:
            found = {**found, "ruling": ruling}
        return found

    def prior_sightings(self, alert: Alert) -> list[PriorSighting]:
        """Past investigations (excluding this alert_id) that share an IOC.

        Most recent first. Each prior alert appears once, with all of its
        overlapping indicators collected into matched_iocs.
        """
        current = set(alert_iocs(alert))
        if not current:
            return []

        rulings = self.dispositions()
        sightings: list[PriorSighting] = []
        seen_alert_ids: set[str] = set()
        index = self._index()
        # The index preselects rows sharing at least one IOC — in file
        # order, so the record chosen per alert_id is the one the full
        # scan chose; the exact match below re-derives matched_iocs.
        for row in index.candidate_rows(iocs=current):
            rec = index.rows[row]
            if rec["alert_id"] == alert.alert_id:
                continue  # don't match an alert against itself
            if rec["alert_id"] in seen_alert_ids:
                continue
            matched = sorted(current & set(rec.get("iocs", [])))
            if not matched:
                continue
            seen_alert_ids.add(rec["alert_id"])
            ruling = rulings.get(rec["alert_id"], {})
            sightings.append(
                PriorSighting(
                    alert_id=rec["alert_id"],
                    timestamp=rec["timestamp"],
                    verdict=rec["verdict"],
                    confidence=rec["confidence"],
                    title=rec["title"],
                    matched_iocs=matched,
                    human_verdict=ruling.get("human_verdict"),
                    human_summary=ruling.get("summary"),
                )
            )

        sightings.sort(key=lambda s: s.timestamp, reverse=True)
        return sightings

    def correlate(
        self,
        alert: Alert,
        techniques: list[str] | None = None,
        window_hours: int = DEFAULT_WINDOW_HOURS,
    ) -> Correlation:
        """Assess whether this alert clusters with recent prior alerts.

        Two alerts are "related" when they fall within window_hours of each
        other AND share at least one infrastructure/target signal (an exact
        IOC, a /24-adjacent IP, or the same host). A shared technique family is
        recorded as a corroborating signal but is never the sole link — that
        keeps generic TTPs (e.g. every phishing alert uses T1566) from
        producing spurious campaigns. is_campaign is True once enough related
        priors accumulate.

        `techniques` is optional so this can run BEFORE investigation (on
        alert-level signals alone, to inform the escalation decision) and again
        AFTER (with the final technique mapping, to record technique
        corroboration). Because relatedness rests on infrastructure/target
        signals, is_campaign is stable whether or not techniques are supplied.
        """
        current_iocs = set(alert_iocs(alert))
        current_ips = _ipv4s(list(current_iocs))
        current_nets = [(a, _net24(a)) for a in current_ips]
        current_host = alert_host(alert)
        current_techs = _parent_tcodes(techniques or [])
        window = timedelta(hours=window_hours)

        related: list[RelatedAlert] = []
        seen_alert_ids: set[str] = set()
        index = self._index()
        # Relatedness REQUIRES an infrastructure/target signal (exact IOC,
        # /24-adjacent IP, or same host) — a shared technique only ever
        # corroborates — so the union of those three posting lists is a
        # complete candidate set. Every filter below is the full scan's,
        # re-applied; the time window stays a per-record check because the
        # alert's own timestamp (the window's center) is not something the
        # file is ordered by.
        for row in index.candidate_rows(
            iocs=current_iocs, host=current_host, ips=current_ips
        ):
            rec = index.rows[row]
            if rec["alert_id"] == alert.alert_id:
                continue
            if rec["alert_id"] in seen_alert_ids:
                continue
            rec_time = index.ts[row]
            if rec_time is None:  # missing/bad field: fail as the scan did
                rec_time = datetime.fromisoformat(rec["timestamp"])
            if abs(alert.timestamp - rec_time) > window:
                continue

            rec_iocs = set(rec.get("iocs", []))
            signals: list[str] = []

            for shared in sorted(current_iocs & rec_iocs):
                signals.append(f"shared_ioc:{shared}")

            rec_ips = _ipv4s(list(rec_iocs))
            # Same /24, different address — computed by comparing each
            # side's precomputed network key instead of building an
            # ip_network object per PAIR (the pairwise construction was
            # the dominant per-candidate cost at scale). _net24 is the
            # same arithmetic _same_24 performed; the pair loop and its
            # signal order are unchanged.
            rec_nets = [(b, _net24(b)) for b in rec_ips]
            for a, a_net in current_nets:
                for b, b_net in rec_nets:
                    if a_net == b_net and a != b:
                        signals.append(f"related_ip:{b}/24")

            rec_host = rec.get("host")
            if current_host and rec_host and current_host == rec_host:
                signals.append(f"shared_host:{current_host}")

            # Infrastructure/target overlap is required to be "related".
            if not signals:
                continue

            # Shared technique family corroborates an already-related pair.
            shared_techs = current_techs & _parent_tcodes(
                rec.get("attack_techniques", [])
            )
            for code in sorted(shared_techs):
                signals.append(f"shared_technique:{code}")

            seen_alert_ids.add(rec["alert_id"])
            related.append(
                RelatedAlert(
                    alert_id=rec["alert_id"],
                    timestamp=rec_time,
                    verdict=rec["verdict"],
                    signals=signals,
                )
            )

        related.sort(key=lambda r: r.timestamp, reverse=True)
        is_campaign = len(related) >= CAMPAIGN_MIN_RELATED

        if is_campaign:
            summary = (
                f"Possible coordinated campaign: {len(related) + 1} related "
                f"alerts within {window_hours}h "
                f"(this alert + {len(related)} prior)."
            )
        elif related:
            summary = (
                f"{len(related)} related prior alert(s) within {window_hours}h "
                f"— related activity, below campaign threshold."
            )
        else:
            summary = f"No related prior alerts within {window_hours}h."

        return Correlation(
            is_campaign=is_campaign,
            window_hours=window_hours,
            related_alerts=related,
            summary=summary,
        )

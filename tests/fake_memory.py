"""A fake Elasticsearch, faithful to exactly what shared memory uses.

Small enough to read, and deliberately strict where the real cluster is
strict: `dynamic: strict` rejects unknown top-level fields, `_create`
answers 409 on a repeat, `_search` honors the request's own `sort` and
`search_after` (the ordering contract the whole tail rests on) and
rejects a filter shape it does not recognize, and — with
`require_refresh` — a document written without `refresh=wait_for` is not
searchable until something refreshes, which is what makes `wait_for`
load-bearing rather than decorative. Anything the module does not use is
a 400 rather than a shrug, so a test cannot pass against a request the
real cluster would have refused.
"""
import json
import re
from datetime import datetime, timezone

import httpx

_CREATE = re.compile(r"^/([^/]+)/_create/([^/]+)$")
_SEARCH = re.compile(r"^/([^/]+)/_search$")
_MAPPING = re.compile(r"^/([^/]+)/_mapping$")
_INDEX = re.compile(r"^/([^/]+)$")
_REFRESH = re.compile(r"^/([^/]+)/_refresh$")


def _millis(iso: str) -> int:
    when = datetime.fromisoformat(iso)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return int(when.timestamp() * 1000)


class FakeMemoryIndex:
    """One cluster's worth of state, plus a request log for assertions."""

    def __init__(self) -> None:
        self.indices: dict[str, dict] = {}       # name -> mapping body
        self.docs: dict[str, dict[str, dict]] = {}   # index -> uid -> _source
        self.requests: list[tuple[str, str, dict]] = []
        self.fail_next: Exception | None = None
        self.fail_always: Exception | None = None
        # A degraded cluster answers a search with HTTP 200 and the hits
        # it managed to collect; set these to reproduce that.
        self.failed_shards = 0
        self.timed_out = False
        self.searches = 0
        self.refreshes = 0
        # When true, a document written without refresh=wait_for is NOT
        # searchable until something refreshes the index — which is what
        # a real cluster does, and what makes `wait_for` load-bearing
        # rather than decorative.
        self.require_refresh = False
        self.unrefreshed: dict[str, dict[str, dict]] = {}

    # --- test helpers -------------------------------------------------------

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handle))

    def create_index(self, name: str, mapping: dict | None = None) -> None:
        self.indices[name] = mapping or {
            "mappings": {
                "dynamic": "strict",
                "properties": {
                    "uid": {"type": "keyword"},
                    "ledger": {"type": "keyword"},
                    "writer": {"type": "keyword"},
                    "written_at": {"type": "date"},
                    "record": {"type": "object", "enabled": False},
                },
            }
        }
        self.docs.setdefault(name, {})

    def put(
        self, index: str, ledger: str, record: dict, *,
        written_at: str, writer: str = "other-host", uid: str | None = None,
    ) -> str:
        """Write a document the way another instance would have."""
        uid = uid or f"u{len(self.docs.get(index, {})):06d}"
        self.docs.setdefault(index, {})[uid] = {
            "uid": uid, "ledger": ledger, "writer": writer,
            "written_at": written_at, "record": record,
        }
        return uid

    # --- transport ----------------------------------------------------------

    def handle(self, request: httpx.Request) -> httpx.Response:
        if self.fail_always is not None:
            raise self.fail_always
        if self.fail_next is not None:
            exc, self.fail_next = self.fail_next, None
            raise exc
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        self.requests.append((request.method, str(request.url), body))

        if (m := _MAPPING.match(path)) and request.method == "GET":
            name = m.group(1)
            if name not in self.indices:
                return httpx.Response(404, json={"error": "index_not_found"})
            return httpx.Response(200, json={name: self.indices[name]})

        if (m := _INDEX.match(path)) and request.method == "PUT":
            name = m.group(1)
            if name in self.indices:
                return httpx.Response(400, json={
                    "error": {"type": "resource_already_exists_exception"}
                })
            self.create_index(name, body)
            return httpx.Response(200, json={"acknowledged": True})

        if (m := _CREATE.match(path)) and request.method == "PUT":
            return self._create(m.group(1), m.group(2), body, request)

        if (m := _REFRESH.match(path)) and request.method == "POST":
            # Everything here is visible the instant it is written, so a
            # refresh is a no-op — but it must EXIST, because a document
            # imported without one is invisible in a real cluster until
            # something asks for it.
            self.refreshes += 1
            name = m.group(1)
            if name not in self.indices:
                return httpx.Response(404, json={"error": "index_not_found"})
            self.docs.setdefault(name, {}).update(
                self.unrefreshed.pop(name, {})
            )
            return httpx.Response(200, json={"_shards": {"failed": 0}})

        if (m := _SEARCH.match(path)) and request.method == "POST":
            return self._search(m.group(1), body)

        return httpx.Response(400, json={"error": f"unsupported {path}"})

    def visible(self, index: str) -> dict[str, dict]:
        """The documents a search would actually see."""
        return self.docs.get(index, {})

    def _create(
        self, index: str, uid: str, body: dict, request: httpx.Request
    ) -> httpx.Response:
        if index not in self.indices:
            return httpx.Response(404, json={"error": "index_not_found"})
        allowed = set(
            self.indices[index]["mappings"].get("properties", {})
        )
        strict = (
            self.indices[index]["mappings"].get("dynamic") == "strict"
        )
        if strict and not set(body) <= allowed:
            # What a strict mapping really does with an unmapped field.
            return httpx.Response(400, json={"error": {
                "type": "strict_dynamic_mapping_exception",
                "reason": f"unmapped fields {sorted(set(body) - allowed)}",
            }})
        pending = self.unrefreshed.setdefault(index, {})
        if uid in self.docs.setdefault(index, {}) or uid in pending:
            return httpx.Response(409, json={"error": {
                "type": "version_conflict_engine_exception"
            }})
        waited = request.url.params.get("refresh") == "wait_for"
        if self.require_refresh and not waited:
            pending[uid] = body          # written, but not yet searchable
        else:
            self.docs[index][uid] = body
        return httpx.Response(201, json={"_id": uid, "result": "created"})

    def _search(self, index: str, body: dict) -> httpx.Response:
        self.searches += 1
        if index not in self.indices:
            return httpx.Response(404, json={"error": "index_not_found"})
        # The ORDER is the contract the whole tail rests on: the cursor is
        # (written_at, uid) and every splice decision compares against it.
        # A fake that sorted its own way regardless of the request would
        # keep passing if the real sort changed underneath.
        if body.get("sort") != [{"written_at": "asc"}, {"uid": "asc"}]:
            return httpx.Response(400, json={"error": {
                "type": "search_phase_execution_exception",
                "reason": f"unsupported sort {body.get('sort')!r}",
            }})
        ledger = floor = None
        for f in body.get("query", {}).get("bool", {}).get("filter", []):
            if "term" in f and set(f["term"]) == {"ledger"}:
                ledger = f["term"]["ledger"]
            elif "range" in f and set(f["range"]) == {"written_at"}:
                spec = f["range"]["written_at"]
                if spec.get("format") != "epoch_millis":
                    # A range against a date field without a format is
                    # parsed as a date string, not as millis.
                    return httpx.Response(400, json={"error": {
                        "type": "parse_exception",
                        "reason": f"cannot parse {spec.get('gte')!r} as a date",
                    }})
                floor = spec["gte"]
            else:
                # Whatever this is, the real cluster would either reject it
                # or answer a different question. Both are failures here.
                return httpx.Response(400, json={"error": {
                    "type": "query_shaping_exception",
                    "reason": f"unsupported filter {f!r}",
                }})
        rows = []
        for uid, src in self.visible(index).items():
            if ledger is not None and src.get("ledger") != ledger:
                continue
            when = _millis(src["written_at"])
            if floor is not None and when < floor:
                continue
            rows.append(((when, uid), src))
        rows.sort(key=lambda r: r[0])
        after = body.get("search_after")
        if after is not None:
            cursor = (after[0], after[1])
            rows = [r for r in rows if r[0] > cursor]
        size = body.get("size", 10)
        hits = [
            {"_id": key[1], "sort": [key[0], key[1]], "_source": src}
            for key, src in rows[:size]
        ]
        if self.failed_shards:
            hits = hits[:-1]     # a short answer, exactly as ES gives it
        return httpx.Response(200, json={
            "timed_out": self.timed_out,
            "_shards": {
                "total": 1 + self.failed_shards,
                "successful": 1,
                "failed": self.failed_shards,
            },
            "hits": {"hits": hits},
        })

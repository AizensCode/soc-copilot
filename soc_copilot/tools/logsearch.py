"""Internal log search — the copilot's own SIEM pivot.

The single most common pivot an investigation produces is one it could
not answer: "was there a SUCCESSFUL authentication from this IP?", "did
this host actually connect to that destination?". Reputation feeds
answer "is this indicator known-bad"; only the environment's own
telemetry answers "did the thing happen here". This tool gives the
agentic loop that answer, turning an inconclusive into a confident
verdict in either direction.

Security is the whole design, because this tool reads the SIEM under the
direction of a model that is consuming attacker-influenced indicator
values:

- NOT a query interface. The model never writes a query string. It picks
  FIELD/VALUE filters from a fixed allowlist (ALLOWED_FIELDS), enforced
  both by the schema `enum` and re-validated here. Each filter becomes an
  exact Elasticsearch `term`, so an attacker-controlled value like
  ``* OR host:*`` is matched as a literal string, never interpreted — the
  classic query-injection surface does not exist.
- Read-only, bounded, time-boxed. Only `_search` (never `_update`), a
  hard result-size cap, a server-side `@timestamp` range via ES date
  math, and a query timeout. An alert with hundreds of IOCs cannot turn
  this into an unbounded scan.
- Degrades gracefully. When Elastic (or the events index) is not
  configured, the tool returns a clear not-configured result rather than
  raising — the agent then knows the pivot is unavailable and defers to a
  human, exactly as the rest of the copilot runs fine without Elastic.

The returned sample events carry attacker-influenced log text (usernames,
command lines); the copilot's tool-output injection scan already covers
every tool's `data`, so that content is scanned like any other.
"""
import ipaddress

import httpx

from ..config import settings
from .base import Tool, ToolResult

# ip-typed ECS fields where Elasticsearch's `term` special-cases CIDR
# notation as a SUBNET RANGE. A model-supplied (attacker-influenced) value
# like "0.0.0.0/0" would silently broaden "from this IP" to "from anywhere"
# and steer the confirm/refute verdict — so these must be single literal
# addresses, validated below.
_IP_FIELDS = {"source.ip", "destination.ip"}

# The ONLY fields the model may filter on — ECS names, all keyword/ip
# typed so an exact `term` is the right match. Anything else is rejected.
# Extend deliberately: every field here is a field the model can probe.
ALLOWED_FIELDS = [
    "source.ip",
    "destination.ip",
    "user.name",
    "host.name",
    "event.action",
    "event.category",
    "event.outcome",
    "event.type",
    "process.name",
    "network.protocol",
    "dns.question.name",
    "file.hash.sha256",
    "url.original",
]

MAX_FILTERS = 5
MAX_SAMPLE = 5
MIN_WINDOW_HOURS = 1
MAX_WINDOW_HOURS = 168  # one week
DEFAULT_WINDOW_HOURS = 24
QUERY_TIMEOUT = "5s"


class SearchLogsTool(Tool):
    name = "search_internal_logs"
    description = (
        "Search the organization's OWN internal event telemetry (the SIEM's "
        "raw logs — authentications, process events, network connections), "
        "not external reputation, to establish whether something actually "
        "happened in this environment. This is how you turn an attempt into "
        "a confirmed outcome: 'was there a SUCCESSFUL authentication from "
        "this source IP?' (filter source.ip=<ip> AND event.outcome=success "
        "AND event.category=authentication), 'did this host connect out to "
        "that destination?', 'what did this user account do?'.\n\n"
        "You do NOT write a query. You supply one or more field/value "
        "filters, chosen from a fixed set of fields; they are AND-ed and "
        "matched exactly, over a bounded recent time window. The tool "
        "returns the number of matching events, a breakdown by event.action "
        "and event.outcome, and a small sample. Use it to CONFIRM or REFUTE "
        "your hypothesis with ground truth before you commit to a verdict — "
        "it is the difference between 'brute force attempted' and 'brute "
        "force succeeded'. A zero-match result is itself evidence (e.g. no "
        "successful login means the attempt likely failed)."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "filters": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_FILTERS,
                "description": (
                    "Field/value conditions, AND-ed together and matched "
                    "exactly (e.g. source.ip=1.2.3.4 AND event.outcome=success)."
                ),
                "items": {
                    "type": "object",
                    "properties": {
                        "field": {"type": "string", "enum": ALLOWED_FIELDS},
                        "value": {
                            "type": "string",
                            "description": "Exact value to match for this field.",
                        },
                    },
                    "required": ["field", "value"],
                },
            },
            "time_window_hours": {
                "type": "integer",
                "minimum": MIN_WINDOW_HOURS,
                "maximum": MAX_WINDOW_HOURS,
                "description": (
                    f"How far back to search, in hours "
                    f"(default {DEFAULT_WINDOW_HOURS}, max {MAX_WINDOW_HOURS})."
                ),
            },
        },
        "required": ["filters"],
    }

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        index: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._url = (url or settings.ELASTIC_URL or "").rstrip("/")
        self._api_key = api_key or settings.ELASTIC_API_KEY
        self._index = index or settings.ELASTIC_EVENTS_INDEX
        self._client = client

    def _fail(self, error: str) -> ToolResult:
        return ToolResult(tool_name=self.name, success=False, data={}, error=error)

    def _build_query(self, filters: list[dict], window_hours: int) -> dict:
        """Assemble the bounded, read-only search body. Every model-supplied
        value goes into a `term` (never string-interpolated), so the value
        is data, not query syntax."""
        term_filters = [
            {"term": {f["field"]: f["value"]}} for f in filters
        ]
        return {
            "size": MAX_SAMPLE,
            "timeout": QUERY_TIMEOUT,
            # Cap the count instead of exact-counting the whole match set:
            # an exact total over a broad term (e.g. every success in the
            # window) is the unbounded cost this tool is supposed to avoid.
            # A capped count returns value=10000, relation="gte", surfaced
            # as a lower bound so the model isn't misled.
            "track_total_hits": 10000,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": f"now-{window_hours}h"}}},
                        *term_filters,
                    ]
                }
            },
            "aggs": {
                "by_action": {"terms": {"field": "event.action", "size": 10}},
                "by_outcome": {"terms": {"field": "event.outcome", "size": 10}},
            },
        }

    def _validate(
        self, filters: object, time_window_hours: object
    ) -> tuple[list[dict], int] | ToolResult:
        """Re-validate the model's arguments server-side (defense in depth,
        not trusting the schema alone). Returns cleaned (filters, window)
        or a failed ToolResult naming the problem so the model can retry."""
        if not isinstance(filters, list) or not filters:
            return self._fail("filters must be a non-empty list.")
        if len(filters) > MAX_FILTERS:
            return self._fail(f"at most {MAX_FILTERS} filters allowed.")
        clean: list[dict] = []
        for f in filters:
            if not isinstance(f, dict) or "field" not in f or "value" not in f:
                return self._fail("each filter needs a 'field' and a 'value'.")
            field = f["field"]
            if field not in ALLOWED_FIELDS:
                return self._fail(
                    f"field {field!r} is not searchable. Allowed fields: "
                    f"{', '.join(ALLOWED_FIELDS)}."
                )
            value = f["value"]
            if not isinstance(value, str):
                return self._fail(
                    f"filter value for {field!r} must be a string, got "
                    f"{type(value).__name__}."
                )
            if field in _IP_FIELDS:
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    return self._fail(
                        f"{field} value {value!r} must be a single literal IP "
                        f"address — CIDR ranges and hostnames are rejected, so "
                        f"the match cannot silently broaden from one host to a "
                        f"whole subnet."
                    )
            clean.append({"field": field, "value": value})

        window = (
            DEFAULT_WINDOW_HOURS
            if time_window_hours is None
            else time_window_hours
        )
        if not isinstance(window, int) or isinstance(window, bool):
            return self._fail("time_window_hours must be an integer.")
        if not (MIN_WINDOW_HOURS <= window <= MAX_WINDOW_HOURS):
            return self._fail(
                f"time_window_hours must be between {MIN_WINDOW_HOURS} and "
                f"{MAX_WINDOW_HOURS}."
            )
        return clean, window

    async def execute(
        self, filters=None, time_window_hours=None
    ) -> ToolResult:
        if not self._url or not self._api_key:
            return self._fail(
                "internal log search is not configured (set ELASTIC_URL, "
                "ELASTIC_API_KEY, and ELASTIC_EVENTS_INDEX). No internal "
                "telemetry is available; a human must run this pivot."
            )

        validated = self._validate(filters, time_window_hours)
        if isinstance(validated, ToolResult):
            return validated
        clean_filters, window = validated
        body = self._build_query(clean_filters, window)

        async def do(client: httpx.AsyncClient) -> dict:
            resp = await client.post(
                f"{self._url}/{self._index}/_search",
                json=body,
                headers={"Authorization": f"ApiKey {self._api_key}"},
            )
            resp.raise_for_status()
            return resp.json()

        try:
            if self._client is not None:
                raw = await do(self._client)
            else:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    raw = await do(client)
        except httpx.HTTPStatusError as e:
            return self._fail(
                f"HTTP {e.response.status_code} from Elastic: "
                f"{e.response.text[:200]}"
            )
        except Exception as e:
            # Any transport-level error is non-fatal: the pivot simply
            # wasn't answerable, and the agent moves on.
            return self._fail(f"log search failed: {e}")

        # Parse defensively: a 200 with an unexpected shape (a top-level
        # array, null hits/aggs, buckets missing keys — e.g. ELASTIC_URL
        # pointed at a non-ES service) must still return a clean _fail, not
        # raise, to honor the graceful-degradation contract.
        try:
            return self._shape_result(raw, clean_filters, window)
        except Exception as e:
            return self._fail(
                f"unexpected Elasticsearch response shape: {type(e).__name__}: "
                f"{e}"
            )

    def _shape_result(
        self, raw: object, clean_filters: list[dict], window: int
    ) -> ToolResult:
        if not isinstance(raw, dict):
            return self._fail("Elasticsearch response was not a JSON object.")
        hits = raw.get("hits") or {}
        hits = hits if isinstance(hits, dict) else {}
        aggs = raw.get("aggregations") or {}
        aggs = aggs if isinstance(aggs, dict) else {}

        total = hits.get("total")
        if isinstance(total, dict):
            total_value = total.get("value", 0)
            # relation == "gte" means the count was capped (track_total_hits).
            total_is_lower_bound = total.get("relation") == "gte"
        else:
            total_value = total or 0
            total_is_lower_bound = False

        def _buckets(name: str) -> dict:
            agg = aggs.get(name)
            buckets = agg.get("buckets", []) if isinstance(agg, dict) else []
            return {
                b["key"]: b.get("doc_count", 0)
                for b in buckets
                if isinstance(b, dict) and "key" in b
            }

        sample = hits.get("hits", [])
        sample = sample if isinstance(sample, list) else []

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "index": self._index,
                "filters": clean_filters,
                "time_window_hours": window,
                "total_matches": total_value,
                "total_is_lower_bound": total_is_lower_bound,
                "by_action": _buckets("by_action"),
                "by_outcome": _buckets("by_outcome"),
                "sample_events": [
                    h.get("_source", {})
                    for h in sample
                    if isinstance(h, dict)
                ],
            },
        )

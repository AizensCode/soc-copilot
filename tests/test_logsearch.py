"""Unit tests for the internal log-search tool (API-free, network-free).

This tool reads the SIEM under the direction of a model consuming
attacker-influenced indicators, so its security properties are the point
of the tests: the model's values become exact `term`s (never query
syntax), only allowlisted fields are searchable, results are bounded and
read-only, and a missing configuration degrades gracefully instead of
crashing.

    uv run pytest tests/test_logsearch.py -v
"""
import httpx

from soc_copilot.tools.logsearch import (
    ALLOWED_FIELDS,
    MAX_FILTERS,
    MAX_WINDOW_HOURS,
    SearchLogsTool,
)


def _tool(handler=None) -> SearchLogsTool:
    """A configured tool with an injected transport (or no transport when
    only argument validation is under test)."""
    client = (
        httpx.AsyncClient(transport=httpx.MockTransport(handler))
        if handler else None
    )
    return SearchLogsTool(
        url="https://es.test:9200", api_key="k", index="events", client=client,
    )


def _ok_response(hits=None, total=0, aggs=None):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "hits": {"total": {"value": total}, "hits": hits or []},
            "aggregations": aggs or {},
        })
    return handler


# --- security: the query builder ---------------------------------------------


async def test_values_become_exact_terms_never_query_syntax():
    """The injection-safety property: a hostile value is matched as a
    literal term, so query DSL embedded in it is inert."""
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        captured["body"] = json.loads(request.content)
        captured["path"] = request.url.path
        return _ok_response()(request)

    # Use user.name: a text-ish field where arbitrary strings are allowed
    # (ip fields have their own CIDR guard, tested separately). The point
    # is that query DSL embedded in the value stays inert.
    hostile = "root OR host.name:* OR *"
    result = await _tool(handler).execute(
        filters=[
            {"field": "user.name", "value": hostile},
            {"field": "event.outcome", "value": "success"},
        ],
        time_window_hours=6,
    )
    assert result.success is True
    filters = captured["body"]["query"]["bool"]["filter"]
    # A range guard plus one term per filter — and the hostile string sits
    # INSIDE a term value, not as a query_string or interpolated clause.
    assert {"term": {"user.name": hostile}} in filters
    assert {"term": {"event.outcome": "success"}} in filters
    assert any("range" in f for f in filters)
    assert not any("query_string" in str(f) for f in filters)
    # Read-only: it hits _search, and the size is bounded.
    assert captured["path"].endswith("/events/_search")
    assert captured["body"]["size"] <= MAX_FILTERS + 5
    assert captured["body"]["query"]["bool"]["filter"][0]["range"][
        "@timestamp"]["gte"] == "now-6h"


async def test_disallowed_field_is_rejected_before_any_request():
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return _ok_response()(request)

    result = await _tool(handler).execute(
        filters=[{"field": "password", "value": "x"}]
    )
    assert result.success is False
    assert "not searchable" in result.error
    assert called["n"] == 0  # never reached the network


async def test_allowlist_covers_the_canonical_auth_pivot():
    """The tool's reason for existing: 'successful auth from this IP'."""
    for field in ("source.ip", "event.outcome", "event.category", "user.name"):
        assert field in ALLOWED_FIELDS


async def test_too_many_filters_rejected():
    result = await _tool(_ok_response()).execute(
        filters=[{"field": "source.ip", "value": str(i)}
                 for i in range(MAX_FILTERS + 1)]
    )
    assert result.success is False
    assert "at most" in result.error


async def test_out_of_range_window_rejected():
    result = await _tool(_ok_response()).execute(
        filters=[{"field": "source.ip", "value": "1.1.1.1"}],
        time_window_hours=MAX_WINDOW_HOURS + 1,
    )
    assert result.success is False
    assert "between" in result.error


async def test_empty_filters_rejected():
    result = await _tool(_ok_response()).execute(filters=[])
    assert result.success is False


async def test_cidr_on_ip_field_is_rejected():
    """The integrity fix: ES `term` on an ip-typed field reads CIDR as a
    SUBNET RANGE, so a hostile `0.0.0.0/0` would broaden 'from this IP' to
    'from anywhere' and steer the verdict. Only a single literal IP is
    allowed on ip fields."""
    called = {"n": 0}

    def handler(request):
        called["n"] += 1
        return _ok_response()(request)

    for bad in ("0.0.0.0/0", "10.0.0.0/8", "not-an-ip", "::/0"):
        result = await _tool(handler).execute(
            filters=[{"field": "source.ip", "value": bad}]
        )
        assert result.success is False, f"{bad} should be rejected"
        assert "literal IP" in result.error
    assert called["n"] == 0  # rejected before any request

    # A single literal IP (v4 or v6) is still accepted.
    ok = await _tool(_ok_response()).execute(
        filters=[{"field": "source.ip", "value": "185.220.101.47"}]
    )
    assert ok.success is True


async def test_non_ip_fields_still_accept_arbitrary_strings():
    """The CIDR guard applies only to ip fields; a username with a slash
    or odd characters is a legitimate exact value elsewhere."""
    ok = await _tool(_ok_response()).execute(
        filters=[{"field": "user.name", "value": "DOMAIN\\svc/oddity"}]
    )
    assert ok.success is True


async def test_non_string_value_is_rejected_not_coerced():
    """A non-string value ('None'/'True' after str()) is nonsense, not a
    real term. Reject it so the model can retry with a proper string."""
    for bad in (None, True, 5, ["a"]):
        result = await _tool(_ok_response()).execute(
            filters=[{"field": "user.name", "value": bad}]
        )
        assert result.success is False
        assert "must be a string" in result.error


async def test_count_is_capped_and_marked_a_lower_bound():
    """track_total_hits is capped (not an exact whole-set count); when ES
    reports the cap, the result flags the total as a lower bound so the
    model isn't misled into reading 10000 as exact."""
    captured = {}

    def handler(request):
        import json
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "hits": {"total": {"value": 10000, "relation": "gte"}, "hits": []},
            "aggregations": {},
        })

    result = await _tool(handler).execute(
        filters=[{"field": "event.outcome", "value": "success"}]
    )
    assert captured["body"]["track_total_hits"] == 10000
    assert result.data["total_matches"] == 10000
    assert result.data["total_is_lower_bound"] is True


async def test_malformed_200_response_degrades_gracefully():
    """A 200 with an unexpected shape (non-ES service behind the URL, null
    hits/aggs, buckets missing keys) must _fail cleanly, never raise —
    the graceful-degradation contract the module promises."""
    bodies = [
        [],                                  # top-level array
        "ok",                                # scalar
        {"hits": None},                      # null hits
        {"aggregations": {"by_action": None}},   # null sub-agg
        {"hits": {"total": {"value": 1}, "hits": [{"_source": {}}]},
         "aggregations": {"by_outcome": {"buckets": [{"doc_count": 2}]}}},  # bucket missing key
    ]
    for body in bodies:
        def handler(request, body=body):
            return httpx.Response(200, json=body)
        result = await _tool(handler).execute(
            filters=[{"field": "source.ip", "value": "1.1.1.1"}]
        )
        # Either a clean structured result or a clean _fail — never a raise.
        assert isinstance(result.success, bool)
        if not result.success:
            assert "Elasticsearch response" in result.error


# --- result shaping ----------------------------------------------------------


async def test_result_summarizes_matches_and_breakdowns():
    handler = _ok_response(
        total=3,
        hits=[{"_source": {"user": {"name": "root"}, "event": {"outcome": "success"}}}],
        aggs={
            "by_outcome": {"buckets": [{"key": "success", "doc_count": 3}]},
            "by_action": {"buckets": [{"key": "ssh_login", "doc_count": 3}]},
        },
    )
    result = await _tool(handler).execute(
        filters=[
            {"field": "source.ip", "value": "185.220.101.47"},
            {"field": "event.outcome", "value": "success"},
        ],
    )
    assert result.success is True
    d = result.data
    assert d["total_matches"] == 3
    assert d["by_outcome"] == {"success": 3}
    assert d["by_action"] == {"ssh_login": 3}
    assert d["sample_events"][0]["user"]["name"] == "root"
    assert d["time_window_hours"] == 24  # default applied


async def test_zero_matches_is_a_clean_negative_result():
    """A zero-match answer is evidence (the login did not succeed), not an
    error — the model must be able to act on it."""
    result = await _tool(_ok_response(total=0)).execute(
        filters=[
            {"field": "source.ip", "value": "185.220.101.47"},
            {"field": "event.outcome", "value": "success"},
        ],
    )
    assert result.success is True
    assert result.data["total_matches"] == 0


# --- graceful degradation ----------------------------------------------------


async def test_unconfigured_tool_degrades_gracefully():
    """No Elastic configured: a clear not-configured result, not a crash,
    so the agent defers the pivot to a human. Blank the resolved
    credentials directly so the guard is exercised regardless of whether
    the developer's .env happens to set ELASTIC_URL."""
    tool = SearchLogsTool(index="events")
    tool._url = ""
    tool._api_key = None
    result = await tool.execute(
        filters=[{"field": "source.ip", "value": "1.1.1.1"}]
    )
    assert result.success is False
    assert "not configured" in result.error


async def test_http_error_is_non_fatal():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    result = await _tool(handler).execute(
        filters=[{"field": "source.ip", "value": "1.1.1.1"}]
    )
    assert result.success is False
    assert "403" in result.error

"""Unit tests for the eval harness's own SIEM double (API-free).

A test double that the harness pins expectations on is load-bearing: if
this fake answers differently from the tool's real backend, the eval
measures a fiction and nobody finds out. So it gets the same treatment as
production code — the matching semantics are tested directly, and the
strictness that makes it fail loudly (rather than answer wrongly) on a
query shape it doesn't model is tested too.

    uv run pytest tests/test_fake_siem.py -v
"""
from soc_copilot.tools.logsearch import SearchLogsTool

from .fake_siem import (
    ADMIN_IP,
    ATTACKER_IP,
    FAILED_ATTEMPTS,
    TARGET_HOST,
    FakeEventsIndex,
    compromised_index,
    contained_index,
)


def _tool(index: FakeEventsIndex) -> SearchLogsTool:
    return SearchLogsTool(
        url="https://fake-siem.test:9200",
        api_key="k",
        index="events",
        client=index.client(),
    )


# --- the worlds differ in exactly one way ------------------------------------


async def test_the_two_worlds_agree_on_the_failures():
    """Both worlds saw the same brute force — the alert is real in both."""
    for index in (compromised_index(), contained_index()):
        result = await _tool(index).execute(
            filters=[
                {"field": "source.ip", "value": ATTACKER_IP},
                {"field": "event.outcome", "value": "failure"},
            ],
            time_window_hours=24,
        )
        assert result.success is True
        assert result.data["total_matches"] == FAILED_ATTEMPTS


async def test_only_the_compromised_world_has_a_success_from_the_attacker():
    """The one discriminator: the join of attacker IP AND success."""
    pivot = [
        {"field": "source.ip", "value": ATTACKER_IP},
        {"field": "event.outcome", "value": "success"},
    ]
    hit = await _tool(compromised_index()).execute(filters=pivot)
    assert hit.data["total_matches"] == 1
    assert hit.data["sample_events"][0]["user"]["name"] == "root"

    miss = await _tool(contained_index()).execute(filters=pivot)
    assert miss.success is True  # a zero-match answer is evidence, not an error
    assert miss.data["total_matches"] == 0


async def test_both_worlds_have_ordinary_successful_logins():
    """Without ambient successes the contained world would be right for the
    wrong reason — any success query returning zero. Both worlds must show
    successful logins; only the source IP separates them."""
    for index in (compromised_index(), contained_index()):
        result = await _tool(index).execute(
            filters=[
                {"field": "host.name", "value": TARGET_HOST},
                {"field": "event.outcome", "value": "success"},
            ],
            time_window_hours=1,
        )
        assert result.data["total_matches"] >= 1
        sources = {e.get("source", {}).get("ip") for e in result.data["sample_events"]}
        assert ADMIN_IP in sources


async def test_only_the_compromised_world_has_the_follow_on_process():
    for index, expected in ((compromised_index(), 1), (contained_index(), 0)):
        result = await _tool(index).execute(
            filters=[{"field": "process.name", "value": "wget"}]
        )
        assert result.data["total_matches"] == expected


# --- matching semantics ------------------------------------------------------


def _event(ts: str, **fields) -> dict:
    return {"@timestamp": ts, **fields}


async def test_filters_are_and_ed_not_or_ed():
    index = FakeEventsIndex([
        _event("2026-04-19T03:00:00Z", source={"ip": "1.1.1.1"},
               event={"outcome": "success"}),
        _event("2026-04-19T03:00:00Z", source={"ip": "2.2.2.2"},
               event={"outcome": "failure"}),
    ])
    result = await _tool(index).execute(
        filters=[
            {"field": "source.ip", "value": "1.1.1.1"},
            {"field": "event.outcome", "value": "failure"},
        ]
    )
    assert result.data["total_matches"] == 0


async def test_time_window_excludes_older_events():
    """The tool's bound is a real bound here — an event outside the window
    must not answer the question."""
    index = FakeEventsIndex([
        _event("2026-04-19T02:30:00Z", source={"ip": "1.1.1.1"}),  # 50m before NOW
        _event("2026-04-18T03:00:00Z", source={"ip": "1.1.1.1"}),  # a day before
    ])
    inside = await _tool(index).execute(
        filters=[{"field": "source.ip", "value": "1.1.1.1"}], time_window_hours=1
    )
    assert inside.data["total_matches"] == 1
    wider = await _tool(index).execute(
        filters=[{"field": "source.ip", "value": "1.1.1.1"}], time_window_hours=48
    )
    assert wider.data["total_matches"] == 2


async def test_aggregations_count_and_rank_matching_events():
    result = await _tool(compromised_index()).execute(
        filters=[{"field": "host.name", "value": TARGET_HOST}],
        time_window_hours=24,
    )
    by_outcome = result.data["by_outcome"]
    assert by_outcome["failure"] == FAILED_ATTEMPTS
    assert by_outcome["success"] >= 1
    assert result.data["by_action"]["ssh_login"] >= FAILED_ATTEMPTS


async def test_counts_are_exact_below_the_cap_and_the_sample_is_bounded():
    """848 events is under the tool's track_total_hits cap, so the count is
    exact and not flagged as a lower bound — while the returned sample stays
    small regardless of how many matched."""
    result = await _tool(compromised_index()).execute(
        filters=[{"field": "source.ip", "value": ATTACKER_IP}],
        time_window_hours=24,
    )
    assert result.data["total_matches"] == FAILED_ATTEMPTS + 1
    assert result.data["total_is_lower_bound"] is False
    assert len(result.data["sample_events"]) <= 5


# --- strictness: fail loudly, never answer wrongly ---------------------------


async def test_unmodeled_query_clause_is_rejected_not_guessed():
    """If the tool's query builder grows a clause this fake doesn't model,
    the eval must break loudly. A double that quietly ignores what it
    doesn't understand turns a green harness into a lie."""
    index = FakeEventsIndex([])
    tool = _tool(index)
    original = tool._build_query

    def with_wildcard(filters, window):
        body = original(filters, window)
        body["query"]["bool"]["filter"].append({"wildcard": {"user.name": "adm*"}})
        return body

    tool._build_query = with_wildcard
    result = await tool.execute(filters=[{"field": "user.name", "value": "x"}])
    assert result.success is False
    assert "400" in result.error and "wildcard" in result.error


async def test_writes_are_refused_like_a_least_privilege_key():
    index = FakeEventsIndex([])
    async with index.client() as client:
        resp = await client.post("https://fake-siem.test:9200/events/_update/1", json={})
    assert resp.status_code == 403


# --- introspection the eval asserts on ---------------------------------------


async def test_index_records_the_queries_it_was_asked():
    index = compromised_index()
    await _tool(index).execute(
        filters=[
            {"field": "source.ip", "value": ATTACKER_IP},
            {"field": "event.outcome", "value": "success"},
        ]
    )
    assert index.filters_used() == [
        [("source.ip", ATTACKER_IP), ("event.outcome", "success")]
    ]


async def test_duplicate_field_terms_are_preserved_not_collapsed():
    """A self-contradictory query (outcome=failure AND outcome=success)
    matches nothing — and the query log must show BOTH pairs, so an eval
    assertion can see the contradiction instead of a dict collapsing it
    into the last value and 'finding' a pivot that was never asked."""
    index = compromised_index()
    result = await _tool(index).execute(
        filters=[
            {"field": "source.ip", "value": ATTACKER_IP},
            {"field": "event.outcome", "value": "failure"},
            {"field": "event.outcome", "value": "success"},
        ]
    )
    assert result.data["total_matches"] == 0  # AND semantics, faithfully
    (pairs,) = index.filters_used()
    assert pairs.count(("event.outcome", "failure")) == 1
    assert pairs.count(("event.outcome", "success")) == 1


async def test_long_form_term_values_are_rejected_not_mismatched():
    """ES's long form — {"term": {f: {"value": v}}} — is legal and means
    the same thing, which is exactly why it must 400 here: comparing the
    dict with == would answer the canonical pivot with a silent zero."""
    index = FakeEventsIndex([])
    tool = _tool(index)
    original = tool._build_query

    def long_form(filters, window):
        body = original(filters, window)
        body["query"]["bool"]["filter"][1] = {
            "term": {"source.ip": {"value": ATTACKER_IP}}
        }
        return body

    tool._build_query = long_form
    result = await tool.execute(filters=[{"field": "source.ip", "value": ATTACKER_IP}])
    assert result.success is False
    assert "400" in result.error and "short-form" in result.error


async def test_unbounded_or_missing_count_cap_is_rejected():
    """track_total_hits must be a bounded int: True is the uncapped exact
    count the tool exists to avoid, and an absent key would force the fake
    to guess count/relation semantics. Both refuse instead of guessing."""
    index = FakeEventsIndex([])
    base = {
        "size": 1,
        "query": {"bool": {"filter": [{"term": {"user.name": "x"}}]}},
    }
    async with index.client() as client:
        for body in (base, {**base, "track_total_hits": True},
                     {**base, "track_total_hits": "banana"}):
            resp = await client.post(
                "https://fake-siem.test:9200/events/_search", json=body
            )
            assert resp.status_code == 400
            assert "track_total_hits" in resp.text

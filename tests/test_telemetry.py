"""Unit tests for per-investigation telemetry (no API, no network).

Covers the pricing table's semantics, accumulation across retries and
tool calls in both modes (against a fake Anthropic client), persistence
into the history record and the Elastic doc, and the digest's spend
rollup — including the honest-absence cases, which are the point: an
unpriced model must not silently report $0.00 as if it were measured.

    uv run pytest tests/test_telemetry.py -v
"""
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx

from soc_copilot.digest import build_digest_data
from soc_copilot.history import AlertHistoryStore
from soc_copilot.models import Alert, Investigation, Telemetry
from soc_copilot.pricing import estimate_cost, is_priced

_T = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _alert(alert_id: str = "A1") -> Alert:
    return Alert(
        alert_id=alert_id, timestamp=_T, source="edr", severity="high",
        title="t", raw_log={}, indicators={},
    )


def _inv(alert_id: str = "A1", telemetry: Telemetry | None = None) -> Investigation:
    return Investigation(
        alert_id=alert_id, verdict="false_positive", confidence="high",
        hypothesis="h", escalation_recommended=False, telemetry=telemetry,
    )


# --- pricing ----------------------------------------------------------------


def test_known_model_prices_per_million_tokens():
    # 1M in + 1M out on Sonnet 5 list price = $3 + $15
    assert estimate_cost("claude-sonnet-5", 1_000_000, 1_000_000) == 18.0
    assert is_priced("claude-sonnet-5")


def test_dated_model_ids_resolve_by_prefix():
    """Model IDs carry date suffixes that share a price."""
    assert estimate_cost("claude-sonnet-5-20260514", 1_000_000, 0) == 3.0
    assert is_priced("claude-sonnet-5-20260514")


def test_unknown_model_is_unpriced_not_free():
    """A wrong price is worse than a missing one — it silently pollutes
    the averages a tiering decision would be made from."""
    assert is_priced("some-future-model") is False
    assert estimate_cost("some-future-model", 1_000_000, 1_000_000) == 0.0


# --- accumulation across both modes -----------------------------------------


class _FakeMessages:
    """Returns a scripted sequence of responses, each with a usage block."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    async def create(self, **kwargs):
        self.calls += 1
        return self._responses.pop(0)


def _response(text: str, tokens: tuple[int, int], tool_use=None):
    content = [SimpleNamespace(type="text", text=text)]
    if tool_use:
        content = [
            SimpleNamespace(
                type="tool_use", id="tu1", name=tool_use, input={"ip": "9.9.9.9"}
            )
        ]
    return SimpleNamespace(
        content=content,
        stop_reason="tool_use" if tool_use else "end_turn",
        usage=SimpleNamespace(input_tokens=tokens[0], output_tokens=tokens[1]),
    )


def _final_json(alert_id="A1") -> str:
    return json.dumps({
        "alert_id": alert_id, "verdict": "false_positive", "confidence": "high",
        "hypothesis": "h", "attack_techniques": [], "suggested_pivots": [],
        "escalation_recommended": False, "escalation_draft": None,
        "reasoning_transcript": "r",
    })


def _copilot(tmp_path, responses):
    from soc_copilot.copilot import SOCCopilot

    copilot = SOCCopilot(
        history_store=AlertHistoryStore(tmp_path / "investigations.jsonl")
    )
    copilot.client = SimpleNamespace(messages=_FakeMessages(responses))
    return copilot


async def test_phase_one_records_tokens_cost_and_duration(tmp_path):
    copilot = _copilot(tmp_path, [_response(_final_json(), (1000, 500))])
    inv = await copilot.investigate(_alert())

    tel = inv.telemetry
    assert tel.input_tokens == 1000 and tel.output_tokens == 500
    assert tel.api_calls == 1 and tel.retries == 0
    assert tel.duration_seconds >= 0
    assert tel.cost_usd == round(
        estimate_cost(tel.model, 1000, 500), 6
    )


async def test_phase_one_counts_a_resample_as_a_retry_and_bills_both(tmp_path):
    """A retried investigation really did cost twice — the telemetry must
    say so, or cost-per-alert averages understate reality."""
    copilot = _copilot(
        tmp_path,
        [
            _response("not json at all", (1000, 200)),
            _response(_final_json(), (1000, 500)),
        ],
    )
    inv = await copilot.investigate(_alert())

    tel = inv.telemetry
    assert tel.api_calls == 2 and tel.retries == 1
    assert tel.input_tokens == 2000 and tel.output_tokens == 700


async def test_agentic_counts_tool_calls_and_every_round_trip(tmp_path, monkeypatch):
    import soc_copilot.copilot as copilot_mod
    from soc_copilot.tools.base import ToolResult

    async def fake_dispatch(name, tool_input):
        return ToolResult(tool_name=name, success=True, data={"score": 0})

    monkeypatch.setattr(copilot_mod, "dispatch", fake_dispatch)

    copilot = _copilot(
        tmp_path,
        [
            _response("", (1000, 100), tool_use="check_ip_reputation"),
            _response(_final_json(), (1500, 400)),
        ],
    )
    inv = await copilot.investigate_agentic(_alert())

    tel = inv.telemetry
    assert tel.api_calls == 2
    assert tel.tool_calls == 1
    assert tel.input_tokens == 2500 and tel.output_tokens == 500


# --- persistence ------------------------------------------------------------


def test_history_record_flattens_cost_beside_the_summary(tmp_path):
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    tel = Telemetry(model="claude-sonnet-5", input_tokens=1000,
                    output_tokens=500, api_calls=1, cost_usd=0.0105,
                    duration_seconds=12.5)
    store.record(_alert(), _inv(telemetry=tel))

    rec = store.latest_record("A1")
    assert rec["cost_usd"] == 0.0105
    assert rec["duration_seconds"] == 12.5
    assert rec["investigation"]["telemetry"]["input_tokens"] == 1000


def test_history_record_without_telemetry_stores_none_not_zero(tmp_path):
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    store.record(_alert(), _inv())
    rec = store.latest_record("A1")
    assert rec["cost_usd"] is None and rec["duration_seconds"] is None


async def test_elastic_doc_carries_flattened_telemetry():
    from soc_copilot.elastic import ElasticAlertSource

    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(201, json={"_id": "doc1"})

    source = ElasticAlertSource(
        url="https://es.test:9200", api_key="k",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    tel = Telemetry(model="claude-sonnet-5", input_tokens=1000,
                    output_tokens=500, api_calls=1, tool_calls=2,
                    cost_usd=0.0105, duration_seconds=12.5)
    await source.push_investigation(_alert(), _inv(telemetry=tel))

    assert captured["cost_usd"] == 0.0105
    assert captured["tool_calls"] == 2
    assert captured["model"] == "claude-sonnet-5"


async def test_elastic_doc_omits_telemetry_fields_when_absent():
    from soc_copilot.elastic import ElasticAlertSource

    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(201, json={"_id": "doc1"})

    source = ElasticAlertSource(
        url="https://es.test:9200", api_key="k",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    await source.push_investigation(_alert(), _inv())
    assert "cost_usd" not in captured  # absent, never a misleading 0.0


# --- digest rollup ----------------------------------------------------------


def _record_with_cost(store, alert_id, cost, duration=10.0):
    tel = Telemetry(model="claude-sonnet-5", cost_usd=cost,
                    duration_seconds=duration, api_calls=1)
    store.record(_alert(alert_id), _inv(alert_id, telemetry=tel))


def test_digest_spend_sums_the_same_set_it_reports(tmp_path):
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    _record_with_cost(store, "A1", 0.02, duration=10.0)
    _record_with_cost(store, "A2", 0.04, duration=20.0)

    data = build_digest_data(store, since_hours=24)
    assert data["counts"]["total"] == 2
    assert data["spend"]["total_cost_usd"] == 0.06
    assert data["spend"]["mean_cost_usd"] == 0.03
    assert data["spend"]["mean_duration_seconds"] == 15.0
    assert data["spend"]["unmeasured_investigations"] == 0


def test_digest_counts_unmeasured_investigations_separately(tmp_path):
    """Records without telemetry must not be averaged in as $0.00."""
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    _record_with_cost(store, "A1", 0.02)
    store.record(_alert("A2"), _inv("A2"))  # no telemetry

    spend = build_digest_data(store, since_hours=24)["spend"]
    assert spend["measured_investigations"] == 1
    assert spend["unmeasured_investigations"] == 1
    assert spend["total_cost_usd"] == 0.02
    assert spend["mean_cost_usd"] == 0.02   # not 0.01


def test_digest_spend_is_none_when_nothing_is_measured(tmp_path):
    store = AlertHistoryStore(tmp_path / "investigations.jsonl")
    store.record(_alert(), _inv())
    spend = build_digest_data(store, since_hours=24)["spend"]
    assert spend["mean_cost_usd"] is None
    assert spend["total_cost_usd"] == 0

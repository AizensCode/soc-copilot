"""Unit tests for the Elastic SIEM integration (API-free, network-free).

normalize_hit is a pure function tested against recorded-style ECS docs; the
HTTP layer is tested with httpx.MockTransport. No Elastic cluster and no
Anthropic API are involved.

    uv run pytest tests/test_elastic.py -v
"""
import json

import httpx
import pytest

from src.elastic import ElasticAlertSource, normalize_hit
from src.models import Investigation

# A detection alert hit the way Elastic returns it: nested _source objects.
NESTED_HIT = {
    "_id": "abc123",
    "_index": ".alerts-security.alerts-default",
    "_source": {
        "@timestamp": "2026-04-19T18:22:31.000Z",
        "kibana": {
            "alert": {
                "uuid": "d9c1e5a0-1111-2222-3333-444455556666",
                "severity": "high",
                "risk_score": 73,
                "reason": "process event on hr-ws-22 by s.martel",
                "workflow_status": "open",
                "rule": {
                    "name": "Windows Command Shell spawned by Office app",
                    "description": "Detects Office spawning cmd/powershell.",
                },
            }
        },
        "event": {"category": ["process"], "type": ["start"]},
        "host": {"name": "hr-ws-22.corp.internal", "os": {"family": "windows"}},
        "user": {"name": "s.martel"},
        "source": {"ip": "10.20.4.31"},
        "destination": {"ip": "45.137.21.88", "domain": "cdn-updates.example"},
        "process": {
            "name": "powershell.exe",
            "hash": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        },
        "file": {"hash": {"md5": "d41d8cd98f00b204e9800998ecf8427e"}},
    },
}

# The same alert as a flat, dotted-key document (export/pipeline style).
DOTTED_HIT = {
    "_id": "flat456",
    "_source": {
        "@timestamp": "2026-04-19T18:22:31.000Z",
        "kibana.alert.uuid": "flat-uuid-1",
        "kibana.alert.severity": "critical",
        "kibana.alert.rule.name": "Flat-doc rule",
        "host.name": "srv-9",
        "source.ip": "192.0.2.7",
        "user.name": "root",
    },
}


# --- normalization -----------------------------------------------------------


def test_normalize_nested_hit_core_fields():
    alert = normalize_hit(NESTED_HIT)
    assert alert.alert_id == "d9c1e5a0-1111-2222-3333-444455556666"
    assert alert.source == "elastic"
    assert alert.severity == "high"
    assert alert.title == "Windows Command Shell spawned by Office app"
    assert alert.timestamp.year == 2026


def test_normalize_extracts_iocs():
    alert = normalize_hit(NESTED_HIT)
    assert alert.indicators["ips"] == ["10.20.4.31", "45.137.21.88"]
    assert alert.indicators["users"] == ["s.martel"]
    assert alert.indicators["domains"] == ["cdn-updates.example"]
    # both process sha256 and file md5, deduped, order preserved
    assert len(alert.indicators["hashes"]) == 2


def test_normalize_projects_raw_log():
    alert = normalize_hit(NESTED_HIT)
    assert alert.raw_log["host"]["name"] == "hr-ws-22.corp.internal"
    assert alert.raw_log["detection"]["rule_name"].startswith("Windows Command")
    assert alert.raw_log["detection"]["risk_score"] == 73
    # Kibana execution metadata is not passed through wholesale
    assert "kibana" not in alert.raw_log


def test_normalize_dotted_keys():
    alert = normalize_hit(DOTTED_HIT)
    assert alert.alert_id == "flat-uuid-1"
    assert alert.severity == "critical"
    assert alert.title == "Flat-doc rule"
    assert alert.indicators["ips"] == ["192.0.2.7"]
    assert alert.indicators["users"] == ["root"]


def test_normalize_defaults_when_fields_missing():
    hit = {"_id": "bare1", "_source": {"@timestamp": "2026-01-01T00:00:00Z"}}
    alert = normalize_hit(hit)
    assert alert.alert_id == "bare1"          # falls back to _id
    assert alert.severity == "medium"          # unknown -> medium
    assert alert.title == "Elastic detection alert"
    assert alert.indicators == {}


def test_normalize_rejects_bogus_severity():
    hit = {
        "_id": "x",
        "_source": {
            "@timestamp": "2026-01-01T00:00:00Z",
            "kibana": {"alert": {"severity": "catastrophic"}},
        },
    }
    assert normalize_hit(hit).severity == "medium"


# --- HTTP layer (MockTransport) ---------------------------------------------


def _source_with(handler) -> ElasticAlertSource:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return ElasticAlertSource(
        url="https://elastic.test:9200", api_key="key123", client=client
    )


async def test_fetch_alerts_queries_open_and_normalizes():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"hits": {"hits": [NESTED_HIT]}})

    source = _source_with(handler)
    alerts = await source.fetch_alerts(limit=5)

    assert captured["url"].endswith("/.alerts-security.alerts-default/_search")
    assert captured["auth"] == "ApiKey key123"
    assert captured["body"]["size"] == 5
    filt = captured["body"]["query"]["bool"]["filter"][0]
    assert filt == {"term": {"kibana.alert.workflow_status": "open"}}
    assert len(alerts) == 1
    assert alerts[0].severity == "high"


async def test_push_investigation_indexes_summary_doc():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["doc"] = json.loads(request.content)
        return httpx.Response(201, json={"_id": "res-1"})

    source = _source_with(handler)
    alert = normalize_hit(NESTED_HIT)
    inv = Investigation(
        alert_id=alert.alert_id, verdict="true_positive", confidence="high",
        hypothesis="h", attack_techniques=["T1059.001"],
        escalation_recommended=True,
    )
    doc_id = await source.push_investigation(alert, inv)

    assert doc_id == "res-1"
    assert captured["url"].endswith("/soc-copilot-investigations/_doc")
    doc = captured["doc"]
    assert doc["alert_id"] == alert.alert_id
    assert doc["verdict"] == "true_positive"
    assert doc["escalation_recommended"] is True
    assert doc["is_campaign"] is False
    assert doc["investigation"]["attack_techniques"] == ["T1059.001"]


async def test_http_error_surfaces_clearly():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="security_exception: forbidden")

    source = _source_with(handler)
    with pytest.raises(RuntimeError, match="HTTP 403"):
        await source.fetch_alerts()


def test_unconfigured_source_raises_helpfully(monkeypatch):
    # Settings is a frozen dataclass; swap the module's reference with a stub.
    from types import SimpleNamespace

    from src import elastic as elastic_mod

    stub = SimpleNamespace(
        ELASTIC_URL=None,
        ELASTIC_API_KEY=None,
        ELASTIC_ALERTS_INDEX="x",
        ELASTIC_RESULTS_INDEX="y",
    )
    monkeypatch.setattr(elastic_mod, "settings", stub)
    with pytest.raises(RuntimeError, match="ELASTIC_URL"):
        ElasticAlertSource()

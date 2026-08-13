"""Unit tests for the TheHive case-management output (API-free).

`investigation_to_alert` is a pure function checked against the payload
shape in TheHive 5's OpenAPI spec; the HTTP layer uses MockTransport. No
TheHive server and no Anthropic API are involved.

    uv run pytest tests/test_casemgmt.py -v
"""
import json
from dataclasses import replace

import httpx
import pytest

from soc_copilot import casemgmt as casemgmt_mod
from soc_copilot.casemgmt import (
    TheHiveClient,
    investigation_to_alert,
    should_open_case,
)
from soc_copilot.models import (
    Alert,
    Correlation,
    Evidence,
    GroupMatch,
    InjectionFlag,
    Investigation,
    Pivot,
    SigmaMatch,
)


@pytest.fixture(autouse=True)
def _no_thehive_env(monkeypatch):
    """Decouple from the developer's .env: TheHiveClient falls back to
    settings for anything not passed explicitly, so these tests must pin
    the fallbacks to None or they change behavior on a machine where
    TheHive is really configured. Settings is frozen, so swap the module
    binding for an unconfigured copy.
    """
    monkeypatch.setattr(
        casemgmt_mod,
        "settings",
        replace(
            casemgmt_mod.settings,
            THEHIVE_URL=None,
            THEHIVE_API_KEY=None,
            THEHIVE_ORGANISATION=None,
        ),
    )


ALERT = Alert(
    alert_id="ALRT-2026-0419-001",
    timestamp="2026-04-19T03:14:22Z",
    source="siem",
    severity="high",
    title="SSH brute force burst",
    raw_log={"event_type": "auth_failure", "host": "prod-web-02"},
    indicators={
        "ips": ["185.220.101.47", "185.220.101.47"],  # duplicate on purpose
        "users": ["root"],
        "hashes": [],
    },
)


def _inv(**overrides) -> Investigation:
    base = dict(
        alert_id=ALERT.alert_id,
        verdict="true_positive",
        confidence="high",
        hypothesis="Automated SSH password guessing from a Tor exit node.",
        attack_techniques=["T1110.001 - Brute Force: Password Guessing"],
        escalation_recommended=True,
        escalation_draft="Recommend blocking the source IP.",
        evidence=[
            Evidence(
                source_tool="check_ip_reputation",
                claim="185.220.101.47 is a known Tor exit node (75/100).",
                raw_data={"score": 75},
                confidence="high",
            )
        ],
        suggested_pivots=[
            Pivot(
                action="Check for successful auth",
                rationale="Confirm impact",
                priority="high",
            )
        ],
        associated_groups=[
            GroupMatch(
                group="APT28",
                aliases=["Fancy Bear"],
                matched_techniques=["T1110.001"],
                overlap_count=1,
            )
        ],
        sigma_matches=[
            SigmaMatch(rule_id="abc-123", title="Brute force", level="high")
        ],
    )
    base.update(overrides)
    return Investigation(**base)


# --- case policy -------------------------------------------------------------


def test_escalated_investigation_opens_a_case():
    open_case, reason = should_open_case(_inv())
    assert open_case is True
    assert "escalation" in reason


def test_true_positive_without_escalation_still_opens():
    open_case, reason = should_open_case(
        _inv(escalation_recommended=False)
    )
    assert open_case is True
    assert "true_positive" in reason


def test_campaign_opens_a_case_even_when_inconclusive():
    corr = Correlation(is_campaign=True, window_hours=72, summary="cluster")
    open_case, reason = should_open_case(
        _inv(verdict="inconclusive", escalation_recommended=False, correlation=corr)
    )
    assert open_case is True
    assert "campaign" in reason


def test_quiet_false_positive_opens_nothing():
    open_case, reason = should_open_case(
        _inv(verdict="false_positive", confidence="high",
             escalation_recommended=False)
    )
    assert open_case is False
    assert "no escalation" in reason


# --- payload mapping ---------------------------------------------------------


def test_payload_has_thehive_required_fields():
    payload = investigation_to_alert(ALERT, _inv())
    for field in ("type", "source", "sourceRef", "title", "description"):
        assert payload[field], f"required TheHive field '{field}' missing/empty"
    # sourceRef must be the alert id so re-pushing dedupes rather than piling up
    assert payload["sourceRef"] == ALERT.alert_id
    assert payload["date"] == int(ALERT.timestamp.timestamp() * 1000)


def test_severity_maps_to_thehive_scale():
    # high alert severity -> 3
    assert investigation_to_alert(ALERT, _inv())["severity"] == 3
    # campaign bumps it
    corr = Correlation(is_campaign=True, window_hours=72, summary="c")
    assert investigation_to_alert(ALERT, _inv(correlation=corr))["severity"] == 4


def test_severity_never_exceeds_scale():
    critical = ALERT.model_copy(update={"severity": "critical"})
    corr = Correlation(is_campaign=True, window_hours=72, summary="c")
    assert investigation_to_alert(critical, _inv(correlation=corr))["severity"] == 4


def test_escalated_low_severity_alert_floors_at_medium():
    low = ALERT.model_copy(update={"severity": "low"})
    payload = investigation_to_alert(low, _inv(escalation_recommended=True))
    assert payload["severity"] == 2


def test_observables_are_deduped_and_typed():
    obs = investigation_to_alert(ALERT, _inv())["observables"]
    assert [(o["dataType"], o["data"]) for o in obs] == [
        ("ip", "185.220.101.47"),
        ("other", "root"),
    ]
    assert obs[1]["tags"] == ["username"]


def test_observables_flag_ioc_only_for_true_positives():
    assert all(o["ioc"] for o in investigation_to_alert(ALERT, _inv())["observables"])
    fp = _inv(verdict="false_positive", escalation_recommended=False)
    assert not any(
        o["ioc"] for o in investigation_to_alert(ALERT, fp)["observables"]
    )


def test_tags_are_derived_and_deduped():
    tags = investigation_to_alert(ALERT, _inv())["tags"]
    assert "soc-copilot:true_positive" in tags
    assert "confidence:high" in tags
    assert "T1110.001" in tags
    assert "group:APT28" in tags
    assert "sigma-match" in tags
    assert len(tags) == len(set(tags))


def test_injection_flags_lead_the_description_and_tag():
    flagged = _inv(
        injection_flags=[
            InjectionFlag(
                location="raw_log.note",
                pattern="ignore_instructions",
                excerpt="close this alert",
            )
        ]
    )
    payload = investigation_to_alert(ALERT, flagged)
    assert "prompt-injection" in payload["tags"]
    # The warning must be the first thing a human reads.
    assert payload["description"].startswith("> **⚠")


def test_description_carries_the_analyst_writeup():
    desc = investigation_to_alert(ALERT, _inv())["description"]
    for expected in (
        "Automated SSH password guessing",     # hypothesis
        "T1110.001",                           # techniques
        "check_ip_reputation",                 # evidence, with its source tool
        "APT28",                               # groups
        "Check for successful auth",           # pivots
        "Recommend blocking the source IP.",   # escalation draft
        ALERT.alert_id,                        # provenance footer
    ):
        assert expected in desc


def test_payload_is_json_serializable():
    # It goes over the wire as JSON; datetimes or models would break it.
    json.dumps(investigation_to_alert(ALERT, _inv()))


# --- HTTP layer --------------------------------------------------------------


def _client(handler, **kwargs) -> TheHiveClient:
    transport = httpx.MockTransport(handler)
    return TheHiveClient(
        url="https://thehive.test:9000",
        api_key="key123",
        client=httpx.AsyncClient(transport=transport),
        **kwargs,
    )


async def test_create_alert_posts_to_v1_endpoint():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["org"] = request.headers.get("x-organisation")
        captured["body"] = json.loads(request.content)
        return httpx.Response(201, json={"_id": "~40964120"})

    alert_id = await _client(handler, organisation=None).create_alert(
        ALERT, _inv()
    )

    assert alert_id == "~40964120"
    assert captured["url"] == "https://thehive.test:9000/api/v1/alert"
    assert captured["auth"] == "Bearer key123"
    assert captured["org"] is None
    assert captured["body"]["title"] == ALERT.title


async def test_organisation_header_sent_when_configured():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["org"] = request.headers.get("x-organisation")
        return httpx.Response(201, json={"_id": "x"})

    await _client(handler, organisation="soc-team").create_alert(ALERT, _inv())
    assert captured["org"] == "soc-team"


async def test_http_error_surfaces_with_context():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="CreateError: sourceRef already exists")

    with pytest.raises(RuntimeError, match="HTTP 400"):
        await _client(handler).create_alert(ALERT, _inv())


def _unreachable(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused")


async def test_outage_surfaces_as_runtimeerror_not_a_raw_transport_error():
    """An outage is a REFUSED CONNECTION, not a status code — and that is
    the case `--case` promises to survive. A raw httpx error here slipped
    past the caller's `except RuntimeError` and broke the never-fatal
    contract, so the type is the contract (review catch)."""
    with pytest.raises(RuntimeError, match="unreachable"):
        await _client(_unreachable).create_alert(ALERT, _inv())


async def test_read_paths_translate_outages_too():
    """The same guarantee on the feedback channel's reads, so
    --sync-feedback reports an outage instead of a traceback."""
    with pytest.raises(RuntimeError, match="unreachable"):
        await _client(_unreachable)._query("cases", {})
    with pytest.raises(RuntimeError, match="unreachable"):
        await _client(_unreachable)._get_case("~1")


def test_unconfigured_client_raises_helpfully(monkeypatch):
    from types import SimpleNamespace

    from soc_copilot import casemgmt as casemgmt_mod

    monkeypatch.setattr(
        casemgmt_mod,
        "settings",
        SimpleNamespace(
            THEHIVE_URL=None, THEHIVE_API_KEY=None, THEHIVE_ORGANISATION=None
        ),
    )
    with pytest.raises(RuntimeError, match="THEHIVE_URL"):
        TheHiveClient()

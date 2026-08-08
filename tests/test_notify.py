"""Unit tests for the escalation webhook (no API, no network).

Three layers, like casemgmt: the page-or-not policy, the pure payload
builder, and the thin HTTP wrapper via MockTransport. The policy is the
load-bearing part — a notification channel that fires on routine
acknowledgements becomes the noise it exists to cut.

    uv run pytest tests/test_notify.py -v
"""
from datetime import datetime, timezone

import httpx
import pytest

from src.models import Alert, Correlation, Investigation
from src.notify import WebhookClient, build_notification, should_notify

_T = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _alert(**overrides) -> Alert:
    base = dict(
        alert_id="ALRT-1", timestamp=_T, source="edr", severity="high",
        title="Beaconing to external host", raw_log={},
        indicators={"ips": ["45.148.10.216"]},
    )
    base.update(overrides)
    return Alert(**base)


def _inv(**overrides) -> Investigation:
    base = dict(
        alert_id="ALRT-1", verdict="true_positive", confidence="high",
        hypothesis="h", escalation_recommended=True,
    )
    base.update(overrides)
    return Investigation(**base)


def _campaign(is_campaign: bool = True) -> Correlation:
    return Correlation(
        is_campaign=is_campaign, window_hours=72, related_alerts=[],
        summary="s",
    )


# --- policy ------------------------------------------------------------------


def test_escalation_pages():
    page, reason = should_notify(_inv(escalation_recommended=True))
    assert page is True
    assert "escalation" in reason


def test_campaign_pages_even_without_escalation():
    inv = _inv(escalation_recommended=False, correlation=_campaign())
    page, reason = should_notify(inv)
    assert page is True
    assert "campaign" in reason


def test_true_positive_without_escalation_does_not_page():
    """Narrower than should_open_case on purpose: a true positive the
    copilot did not escalate is case-worthy, not page-worthy."""
    inv = _inv(verdict="true_positive", escalation_recommended=False)
    page, reason = should_notify(inv)
    assert page is False
    assert "no\n" not in reason  # reason is a single line
    assert "escalation or campaign" in reason


def test_routine_false_positive_stays_silent():
    inv = _inv(verdict="false_positive", escalation_recommended=False)
    page, _ = should_notify(inv)
    assert page is False


# --- payload -----------------------------------------------------------------


def test_payload_carries_text_and_structured_fields():
    inv = _inv(
        attack_techniques=["T1071.001"],
        escalation_draft="Beaconing observed; recommend containment.",
    )
    payload = build_notification(_alert(), inv, case_link="https://th/alert/1")

    # Human-readable text renders in a Slack-style channel.
    assert payload["text"].startswith("🚨 SOC copilot: ALRT-1 needs a human")
    assert "escalation recommended" in payload["text"]
    assert "Beaconing observed" in payload["text"]
    assert "https://th/alert/1" in payload["text"]
    # Structured fields carry the same facts for a programmatic consumer.
    assert payload["alert_id"] == "ALRT-1"
    assert payload["verdict"] == "true_positive"
    assert payload["is_campaign"] is False
    assert payload["attack_techniques"] == ["T1071.001"]
    assert payload["case_link"] == "https://th/alert/1"


def test_payload_names_both_reasons_for_an_escalated_campaign():
    inv = _inv(escalation_recommended=True, correlation=_campaign())
    payload = build_notification(_alert(), inv)
    assert "escalation recommended" in payload["text"]
    assert "campaign-correlated" in payload["text"]
    assert payload["is_campaign"] is True
    assert payload["case_link"] is None


# --- HTTP wrapper ------------------------------------------------------------


async def test_post_sends_json_and_raises_construction_without_url():
    sent = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent["url"] = str(request.url)
        sent["json"] = request.read().decode()
        return httpx.Response(200, text="ok")

    client = WebhookClient(
        url="https://hook.test/x",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    await client.post({"text": "hi", "alert_id": "A1"})
    assert sent["url"] == "https://hook.test/x"
    assert "A1" in sent["json"]

    with pytest.raises(RuntimeError, match="Webhook is not configured"):
        WebhookClient(url="")


async def test_http_error_becomes_runtime_error_for_never_fatal_callers():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="upstream boom")

    client = WebhookClient(
        url="https://hook.test/x",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(RuntimeError, match="HTTP 500"):
        await client.post({"text": "hi"})

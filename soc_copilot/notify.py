"""Push notifications — wake a human when the copilot finds something
that cannot wait for shift start.

In --watch mode an escalation or a campaign lands in Elastic and (with
--case) in TheHive, and then simply waits to be noticed; there is no
push channel, so --watch --auto-close is really only safe to run while
the desk is staffed. This adds the channel: a webhook POST fired ONLY
for escalations and campaigns — never for a routine acknowledgement, or
the notification becomes the very noise it exists to cut. That is the
same restraint soc_copilot/casemgmt.py applies to case creation, and
deliberately NARROWER: a true positive the copilot did not escalate is
worth a case, but not worth a page.

Design mirrors soc_copilot/casemgmt.py and soc_copilot/elastic.py: `build_notification`
is a pure function tested against fixtures with no network, and the HTTP
layer is a thin httpx wrapper testable via MockTransport. The webhook is
optional — the copilot runs fine without WEBHOOK_URL — and posting is
never fatal: a webhook outage must not lose an investigation that
already succeeded.

Payload shape: a top-level `text` (renders in Slack / Mattermost /
generic incoming webhooks out of the box) plus the structured fields
beside it, for a consumer that wants the data rather than the prose.
"""
import httpx

from . import httpio
from .config import settings
from .models import Alert, Investigation


def should_notify(investigation: Investigation) -> tuple[bool, str]:
    """Decide whether an investigation is worth paging a human about.

    Escalations and campaigns page; nothing else does. Deliberately
    narrower than should_open_case (which also fires on any true
    positive) — a true positive the copilot did not escalate belongs in
    the queue, not in someone's pager at 03:00.
    """
    if investigation.escalation_recommended:
        return True, "investigation recommends escalation"
    if investigation.correlation and investigation.correlation.is_campaign:
        return True, "alert correlates into a campaign"
    return False, (
        f"{investigation.verdict}/{investigation.confidence} with no "
        f"escalation or campaign signal"
    )


def build_notification(
    alert: Alert,
    investigation: Investigation,
    case_link: str | None = None,
) -> dict:
    """Assemble the webhook payload from an investigation. Pure function.

    `text` is the human-readable summary (what a Slack channel shows);
    the structured fields carry the same facts for a programmatic
    consumer. Nothing here is model-authored beyond the escalation draft
    the investigation already produced.
    """
    campaign = bool(
        investigation.correlation and investigation.correlation.is_campaign
    )
    reasons = []
    if investigation.escalation_recommended:
        reasons.append("escalation recommended")
    if campaign:
        reasons.append("campaign-correlated")

    lines = [
        f"🚨 SOC copilot: {alert.alert_id} needs a human "
        f"({', '.join(reasons)})",
        alert.title,
        f"verdict: {investigation.verdict} "
        f"({investigation.confidence} confidence)",
    ]
    if investigation.attack_techniques:
        lines.append(f"techniques: {', '.join(investigation.attack_techniques)}")
    if investigation.escalation_draft:
        lines.append("")
        lines.append(investigation.escalation_draft)
    if case_link:
        lines.append("")
        lines.append(f"case: {case_link}")

    return {
        "text": "\n".join(lines),
        "alert_id": alert.alert_id,
        "title": alert.title,
        "severity": alert.severity,
        "verdict": investigation.verdict,
        "confidence": investigation.confidence,
        "escalation_recommended": investigation.escalation_recommended,
        "is_campaign": campaign,
        "attack_techniques": investigation.attack_techniques,
        "escalation_draft": investigation.escalation_draft,
        "case_link": case_link,
    }


class WebhookClient:
    """POST notifications to a configured webhook URL.

    Mirrors TheHiveClient: URL comes from settings unless injected, an
    httpx client can be injected for tests, and a missing URL raises at
    construction so a misconfigured --notify fails loudly at startup
    rather than silently dropping pages.
    """

    def __init__(
        self,
        url: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.url = url or settings.WEBHOOK_URL or ""
        if not self.url:
            raise RuntimeError(
                "Webhook is not configured. Set WEBHOOK_URL in your .env "
                "to use --notify."
            )
        self._client = client

    async def post(self, payload: dict) -> None:
        """POST the payload; raises RuntimeError on HTTP failure. The
        caller treats notification as never-fatal and catches.

        Marked replayable although a page is not idempotent: this
        channel only ever fires for escalations and campaigns, so the
        failure cost is asymmetric — a duplicate page is an apology, a
        lost 03:00 page is the reason the channel exists.
        """
        try:
            await httpio.request(
                "POST",
                self.url,
                client=self._client,
                timeout=10.0,
                replayable=True,
                json=payload,
            )
        except httpx.HTTPStatusError as e:
            raise RuntimeError(
                f"Webhook returned HTTP {e.response.status_code}: "
                f"{e.response.text[:200]}"
            ) from e
        except httpx.HTTPError as e:
            raise RuntimeError(f"Webhook POST failed: {e}") from e

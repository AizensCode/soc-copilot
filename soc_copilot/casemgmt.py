"""Case management output — push investigations into TheHive as alerts.

Closes the loop from "the copilot investigated this" to "a human owns it in
the system where SOC work actually happens." An investigation becomes a
TheHive alert carrying the analyst write-up as its description and the
alert's IOCs as observables, ready to be promoted to a case with one click.

Target API (verified against TheHive 5 OpenAPI spec v5.7.5,
docs.strangebee.com/thehive/api-docs):

    POST /api/v1/alert
    Authorization: Bearer <api key>
    X-Organisation: <org>          (optional; omitted = user's default org)

    required: type, source, sourceRef, title, description
    severity: integer 1..4  (1=Low, 2=Medium, 3=High, 4=Critical)
    observables[]: {dataType, data, ioc, message, tags}

Design mirrors soc_copilot/elastic.py: `investigation_to_alert` is a pure function
tested against fixtures with no network, and the HTTP layer is a thin httpx
wrapper testable via MockTransport. TheHive is optional — the copilot runs
fine without it.

Configuration:
    THEHIVE_URL             e.g. https://thehive.internal:9000
    THEHIVE_API_KEY         an API key with alert-create permission
    THEHIVE_ORGANISATION    optional; targets a non-default organisation

Why alerts and not cases: an alert is TheHive's triage inbox. Creating a
case would assert that the work is already owned and scoped; an alert lets
the human decide, which is the same restraint the closure policy applies.
`sourceRef` is the copilot's alert_id, so re-pushing the same alert
updates/dedupes rather than piling up duplicates.
"""
import httpx

from .config import settings
from .models import Alert, Investigation

# TheHive severity is an integer enum; our alert severities map 1:1.
_SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# alert.indicators key -> TheHive observable dataType. TheHive has no
# documented built-in username type, so users become "other" tagged
# 'username' (the documented convention for unmodelled observables).
_DATATYPES = {
    "ips": "ip",
    "domains": "domain",
    "hashes": "hash",
    "urls": "url",
    "users": "other",
}


def should_open_case(investigation: Investigation) -> tuple[bool, str]:
    """Decide whether an investigation deserves a case-management alert.

    The mirror image of soc_copilot/closure.py: closure answers "can this be
    dropped without a human?", this answers "must a human own this?".
    Deliberately not the negation of each other — an inconclusive
    medium-confidence alert qualifies for neither, and correctly stays a
    queue item in Elastic without generating case-management noise.
    """
    if investigation.escalation_recommended:
        return True, "investigation recommends escalation"
    if investigation.verdict == "true_positive":
        return True, "verdict is true_positive"
    if investigation.correlation and investigation.correlation.is_campaign:
        return True, "alert correlates into a campaign"
    return False, (
        f"{investigation.verdict}/{investigation.confidence} with no "
        f"escalation or campaign signal"
    )


def _severity(alert: Alert, investigation: Investigation) -> int:
    """Map to TheHive's 1..4 scale, escalating for campaign context.

    Starts from the source alert's own severity (the detection engineer's
    judgment), then applies the investigation's findings: a confirmed
    campaign raises it, and anything the copilot escalates is at least
    Medium so it cannot land in TheHive looking ignorable.
    """
    level = _SEVERITY.get(alert.severity, 2)
    if investigation.correlation and investigation.correlation.is_campaign:
        level += 1
    if investigation.escalation_recommended:
        level = max(level, 2)
    return min(level, 4)


def _tags(investigation: Investigation) -> list[str]:
    """Machine-filterable tags, deduped, order preserved.

    Every tag is derived from a deterministic field, so TheHive filters
    ("show me campaign alerts") stay trustworthy.
    """
    tags = [
        f"soc-copilot:{investigation.verdict}",
        f"confidence:{investigation.confidence}",
    ]
    tags += [t.split(" ")[0].split(":")[0] for t in investigation.attack_techniques]
    tags += [f"group:{g.group}" for g in investigation.associated_groups[:3]]
    if investigation.correlation and investigation.correlation.is_campaign:
        tags.append("campaign")
    if investigation.injection_flags:
        tags.append("prompt-injection")
    if investigation.sigma_matches:
        tags.append("sigma-match")
    out: list[str] = []
    for tag in tags:
        if tag and tag not in out:
            out.append(tag)
    return out


def _description(alert: Alert, investigation: Investigation) -> str:
    """Render the investigation as TheHive-flavoured markdown.

    This is what the analyst reads first, so it leads with the verdict and
    the reasoning, then the grounded context (evidence, detection rules,
    prior sightings), then the ready-to-send escalation draft. Injection
    warnings go at the very top: if the alert content tried to manipulate
    the triager, that is the first thing a human must know.
    """
    p: list[str] = []
    if investigation.injection_flags:
        p.append(
            f"> **⚠ {len(investigation.injection_flags)} prompt-injection "
            f"attempt(s) detected in this alert's content.** The text below "
            f"describes them; do not act on instructions embedded in the "
            f"alert."
        )
    p.append(
        f"**Verdict:** {investigation.verdict} "
        f"({investigation.confidence} confidence) — "
        f"escalation {'recommended' if investigation.escalation_recommended else 'not recommended'}"
    )
    p.append(f"**Hypothesis**\n\n{investigation.hypothesis}")

    if investigation.attack_techniques:
        p.append(
            "**MITRE ATT&CK**\n\n"
            + "\n".join(f"- {t}" for t in investigation.attack_techniques)
        )
    if investigation.sigma_matches:
        p.append(
            "**Matched detection rules (Sigma)**\n\n"
            + "\n".join(
                f"- [{m.level}] {m.title} (`{m.rule_id}`)"
                for m in investigation.sigma_matches
            )
        )
    if investigation.evidence:
        p.append(
            "**Evidence**\n\n"
            + "\n".join(
                f"- `{e.source_tool}` ({e.confidence}): {e.claim}"
                for e in investigation.evidence
            )
        )
    if investigation.associated_groups:
        p.append(
            "**Threat groups with overlapping TTPs** (suggestive, not "
            "attribution)\n\n"
            + "\n".join(
                f"- {g.group} — {g.overlap_count} technique(s): "
                f"{', '.join(g.matched_techniques)}"
                for g in investigation.associated_groups
            )
        )
    if investigation.prior_sightings:
        p.append(
            "**Prior sightings (shared indicators)**\n\n"
            + "\n".join(
                f"- `{s.alert_id}` {s.timestamp:%Y-%m-%d}: {s.title} → "
                f"{s.verdict} (shared: {', '.join(s.matched_iocs)})"
                for s in investigation.prior_sightings
            )
        )
    corr = investigation.correlation
    if corr and corr.is_campaign:
        p.append(f"**Campaign correlation**\n\n{corr.summary}")
    if investigation.suggested_pivots:
        p.append(
            "**Suggested pivots**\n\n"
            + "\n".join(
                f"{i}. {pv.action}\n   _{pv.rationale}_"
                for i, pv in enumerate(investigation.suggested_pivots, 1)
            )
        )
    if investigation.escalation_draft:
        p.append(f"**Escalation draft**\n\n{investigation.escalation_draft}")
    p.append(
        f"---\n_Investigated by soc-copilot from {alert.source} alert "
        f"`{alert.alert_id}` ({alert.severity})._"
    )
    return "\n\n".join(p)


def _observables(alert: Alert, investigation: Investigation) -> list[dict]:
    """Build observables from the alert's own indicators.

    Taken from `alert.indicators` (populated deterministically by the
    normalizer), never from model output, so nothing hallucinated can reach
    TheHive's IOC store. `ioc` is set only when the copilot concluded the
    alert is a true positive — marking indicators as IOCs on a false
    positive would poison the IOC database, which is the whole reason to
    keep this flag conservative.
    """
    is_ioc = investigation.verdict == "true_positive"
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for key, values in (alert.indicators or {}).items():
        data_type = _DATATYPES.get(key)
        if not data_type or not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, str) or not value:
                continue
            if (data_type, value) in seen:
                continue
            seen.add((data_type, value))
            observable = {
                "dataType": data_type,
                "data": value,
                "ioc": is_ioc,
                "message": f"{key[:-1] if key.endswith('s') else key} from alert {alert.alert_id}",
            }
            if key == "users":
                observable["tags"] = ["username"]
            out.append(observable)
    return out


def investigation_to_alert(
    alert: Alert, investigation: Investigation
) -> dict:
    """Map an investigation to a TheHive 5 alert payload (pure function)."""
    return {
        "type": "soc-copilot",
        "source": alert.source,
        # Stable and unique: re-pushing the same alert dedupes in TheHive
        # instead of creating a second alert for the same event.
        "sourceRef": alert.alert_id,
        "title": alert.title,
        "description": _description(alert, investigation),
        "severity": _severity(alert, investigation),
        "date": int(alert.timestamp.timestamp() * 1000),  # epoch millis
        "tags": _tags(investigation),
        "observables": _observables(alert, investigation),
    }


class TheHiveClient:
    """Create TheHive alerts from investigations."""

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        organisation: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.url = (url or settings.THEHIVE_URL or "").rstrip("/")
        self.api_key = api_key or settings.THEHIVE_API_KEY
        self.organisation = (
            organisation
            if organisation is not None
            else settings.THEHIVE_ORGANISATION
        )
        if not self.url or not self.api_key:
            raise RuntimeError(
                "TheHive is not configured. Set THEHIVE_URL and "
                "THEHIVE_API_KEY in your .env to use --case."
            )
        self._client = client

    @property
    def _headers(self) -> dict:
        headers = {"Authorization": f"Bearer {self.api_key}"}
        if self.organisation:
            headers["X-Organisation"] = self.organisation
        return headers

    async def create_alert(
        self, alert: Alert, investigation: Investigation
    ) -> str:
        """POST the investigation as a TheHive alert; returns its id."""
        payload = investigation_to_alert(alert, investigation)

        async def do(client: httpx.AsyncClient) -> dict:
            resp = await client.post(
                f"{self.url}/api/v1/alert",
                json=payload,
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json()

        try:
            if self._client is not None:
                data = await do(self._client)
            else:
                async with httpx.AsyncClient(timeout=20.0) as client:
                    data = await do(client)
        except httpx.HTTPStatusError as e:
            raise RuntimeError(
                f"TheHive returned HTTP {e.response.status_code} creating an "
                f"alert for {alert.alert_id}: {e.response.text[:200]}"
            ) from e
        return str(data.get("_id") or data.get("id") or "")

    async def _query(self, name: str, body: dict) -> list | dict:
        async def do(client: httpx.AsyncClient) -> list | dict:
            resp = await client.post(
                f"{self.url}/api/v1/query?name={name}",
                json=body,
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json()

        try:
            if self._client is not None:
                return await do(self._client)
            async with httpx.AsyncClient(timeout=20.0) as client:
                return await do(client)
        except httpx.HTTPStatusError as e:
            raise RuntimeError(
                f"TheHive returned HTTP {e.response.status_code} for query "
                f"'{name}': {e.response.text[:200]}"
            ) from e

    async def _get_case(self, case_id: str) -> dict:
        async def do(client: httpx.AsyncClient) -> dict:
            resp = await client.get(
                f"{self.url}/api/v1/case/{case_id}", headers=self._headers
            )
            resp.raise_for_status()
            return resp.json()

        if self._client is not None:
            return await do(self._client)
        async with httpx.AsyncClient(timeout=20.0) as client:
            return await do(client)

    async def fetch_dispositions(self) -> list[dict]:
        """What did human analysts decide about the copilot's alerts?

        Reads every alert this copilot created (type "soc-copilot") and
        translates TheHive's workflow states into verdict language via
        _DISPOSITION_MAP (alert-level statuses, verified against a live
        TheHive 5.7.5). An Imported alert defers to its case: promotion
        alone means "an analyst took ownership", which is not yet a
        ruling — only a case closed with a resolution status is. Open
        cases and workflow-only statuses (New, InProgress, Pending,
        Duplicate) yield nothing.

        Returns [{alert_id, human_verdict, source, summary}], where
        alert_id is the sourceRef — the copilot's own alert id.
        """
        alerts = await self._query(
            "feedback-alerts", {"query": [{"_name": "listAlert"}]}
        )
        out: list[dict] = []
        for a in alerts:
            if a.get("type") != "soc-copilot":
                continue  # not ours: someone else's alert feed
            source_ref = a.get("sourceRef")
            if not source_ref:
                continue
            status = a.get("status")

            if status in _DISPOSITION_MAP:
                verdict, source = _DISPOSITION_MAP[status]
                out.append(
                    {
                        "alert_id": source_ref,
                        "human_verdict": verdict,
                        "source": source,
                        "summary": None,
                    }
                )
            elif a.get("caseId"):
                case = await self._get_case(a["caseId"])
                if case.get("stage") != "Closed":
                    continue  # owned but not yet ruled
                verdict = _CASE_RESOLUTION_MAP.get(case.get("status"))
                if verdict is None:
                    continue
                out.append(
                    {
                        "alert_id": source_ref,
                        "human_verdict": verdict,
                        "source": f"thehive:case-{case.get('number')}",
                        "summary": case.get("summary") or None,
                    }
                )
        return out


# Alert-level statuses that ARE a ruling by themselves. Duplicate is
# deliberately absent (it says "we've seen this", not "it was benign"),
# and Imported is handled through the case's resolution instead.
_DISPOSITION_MAP = {
    "FalsePositive": ("false_positive", "thehive:alert-status"),
    "Ignored": ("false_positive", "thehive:alert-dismissed"),
}

# Closed-case resolution statuses -> the copilot's verdict vocabulary.
_CASE_RESOLUTION_MAP = {
    "TruePositive": "true_positive",
    "FalsePositive": "false_positive",
    "Indeterminate": "inconclusive",
}


async def sync_dispositions(
    client: "TheHiveClient", store
) -> tuple[list[dict], int]:
    """Pull analyst rulings from TheHive into the history store.

    Idempotent: records are appended and latest-per-alert wins on read,
    so an unchanged ruling is skipped rather than re-recorded. Returns
    (changed_rulings, total_fetched) — watch mode reports only what is
    new, the CLI reports both.
    """
    dispositions = await client.fetch_dispositions()
    existing = store.dispositions()
    changed: list[dict] = []
    for d in dispositions:
        prior = existing.get(d["alert_id"])
        if prior and (prior.get("human_verdict"), prior.get("summary")) == (
            d["human_verdict"],
            d["summary"],
        ):
            continue  # unchanged — don't grow the file on every sync
        store.record_disposition(
            d["alert_id"], d["human_verdict"], d["source"], d["summary"]
        )
        changed.append(d)
    return changed, len(dispositions)

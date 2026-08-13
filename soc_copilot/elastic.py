"""Elastic SIEM integration — pull detection alerts, push investigations back.

Bridges the copilot to a live alert source: fetch open detection alerts from
Elastic's alert indices (`.alerts-security.alerts-*`), normalize each ECS
document into the copilot's `Alert` model, and after investigation index the
result into a dedicated results index where dashboards or case workflows can
pick it up.

The normalization (`normalize_hit`) is the tested core — it's a pure function
from an Elastic hit to an `Alert`, exercised against recorded fixture docs with
no network. The HTTP layer is a thin httpx wrapper, testable via MockTransport.

Configuration (all optional — the copilot runs fine without Elastic):
    ELASTIC_URL            e.g. https://elastic.internal:9200
    ELASTIC_API_KEY        an API key with read on the alert indices and
                           write on the results index
    ELASTIC_ALERTS_INDEX   default .alerts-security.alerts-default
    ELASTIC_RESULTS_INDEX  default soc-copilot-investigations
"""
from datetime import datetime, timezone

import httpx

from . import httpio
from .config import settings
from .models import Alert, Investigation

# ECS fields that carry the alert's actual observables — projected into
# raw_log so the model sees signal, not Kibana rule-execution metadata.
# "labels" and "tags" are ECS's designated custom-metadata carriers:
# enrichment pipelines put structured context there (recurrence counts,
# schedule matches), and dropping them starved the model of exactly the
# evidence that separates known-benign from unknown.
_RAW_KEYS = [
    "event", "host", "user", "source", "destination", "network",
    "process", "file", "url", "dns", "message", "labels", "tags",
]

_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _get(doc: dict, path: str):
    """Fetch a dotted path from a doc that may be nested or flat-dotted.

    Elastic returns `_source` as nested objects ({"host": {"name": ...}}),
    but exports and some pipelines flatten to dotted keys
    ({"host.name": ...}). Support both.
    """
    cur = doc
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            cur = None
            break
    if cur is not None:
        return cur
    return doc.get(path) if isinstance(doc, dict) else None


def _collect(doc: dict, paths: list[str]) -> list[str]:
    """Gather string values (or lists of them) from several paths, deduped."""
    out: list[str] = []
    for path in paths:
        value = _get(doc, path)
        values = value if isinstance(value, list) else [value]
        for v in values:
            if isinstance(v, str) and v and v not in out:
                out.append(v)
    return out


def normalize_hit(hit: dict) -> Alert:
    """Convert one Elastic search hit (a detection alert doc) to an Alert."""
    src = hit.get("_source", {})

    severity = _get(src, "kibana.alert.severity")
    if severity not in _VALID_SEVERITIES:
        severity = "medium"

    raw_log = {k: src[k] for k in _RAW_KEYS if k in src}
    detection = {
        k: v
        for k, v in {
            "reason": _get(src, "kibana.alert.reason"),
            "risk_score": _get(src, "kibana.alert.risk_score"),
            "rule_name": _get(src, "kibana.alert.rule.name"),
            "rule_description": _get(src, "kibana.alert.rule.description"),
        }.items()
        if v is not None
    }
    if detection:
        raw_log["detection"] = detection
    if not raw_log:
        # Flat-dotted doc: keep everything except Kibana's own metadata.
        raw_log = {
            k: v for k, v in src.items() if not k.startswith("kibana")
        } or dict(src)

    indicators = {
        key: values
        for key, values in {
            "ips": _collect(src, ["source.ip", "destination.ip"]),
            "users": _collect(src, ["user.name"]),
            "domains": _collect(
                src, ["url.domain", "destination.domain", "dns.question.name"]
            ),
            "hashes": _collect(
                src,
                [
                    "file.hash.sha256", "file.hash.sha1", "file.hash.md5",
                    "process.hash.sha256",
                ],
            ),
        }.items()
        if values
    }

    return Alert(
        alert_id=_get(src, "kibana.alert.uuid") or hit.get("_id") or "elastic-unknown",
        timestamp=_get(src, "@timestamp"),
        source="elastic",
        severity=severity,
        title=_get(src, "kibana.alert.rule.name")
        or _get(src, "kibana.alert.reason")
        or "Elastic detection alert",
        raw_log=raw_log,
        indicators=indicators,
    )


class ElasticAlertSource:
    """Fetch detection alerts from Elastic and push investigations back."""

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        client: httpx.AsyncClient | None = None,
        alerts_index: str | None = None,
        results_index: str | None = None,
    ) -> None:
        self.url = (url or settings.ELASTIC_URL or "").rstrip("/")
        self.api_key = api_key or settings.ELASTIC_API_KEY
        if not self.url or not self.api_key:
            raise RuntimeError(
                "Elastic is not configured. Set ELASTIC_URL and "
                "ELASTIC_API_KEY in your .env to use --from-elastic."
            )
        self.alerts_index = alerts_index or settings.ELASTIC_ALERTS_INDEX
        self.results_index = results_index or settings.ELASTIC_RESULTS_INDEX
        self._client = client

    @property
    def _headers(self) -> dict:
        return {"Authorization": f"ApiKey {self.api_key}"}

    async def _post(self, path: str, body: dict, replayable: bool = False) -> dict:
        """POST under the shared outbound policy (soc_copilot/httpio.py).

        `replayable` is a per-call-site fact: searches and fixed-value
        updates can be applied twice, indexing a fresh results _doc
        cannot (a replay would duplicate the row a dashboard counts).
        """
        try:
            resp = await httpio.request(
                "POST",
                f"{self.url}{path}",
                client=self._client,
                timeout=20.0,
                replayable=replayable,
                json=body,
                headers=self._headers,
            )
            return resp.json()
        except httpx.HTTPStatusError as e:
            raise RuntimeError(
                f"Elastic returned HTTP {e.response.status_code} for {path}: "
                f"{e.response.text[:200]}"
            ) from e

    async def fetch_alert_hits(
        self, limit: int = 3, status: str = "open"
    ) -> list[tuple[str, Alert]]:
        """Pull the most recent detection alerts as (doc_id, Alert) pairs.

        The Elasticsearch _id rides along because it is what update APIs
        address documents by — kibana.alert.uuid inside _source is not
        guaranteed to match it.
        """
        body = {
            "size": limit,
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"kibana.alert.workflow_status": status}}
                    ]
                }
            },
        }
        data = await self._post(
            f"/{self.alerts_index}/_search", body, replayable=True
        )
        hits = data.get("hits", {}).get("hits", [])
        return [(h.get("_id", ""), normalize_hit(h)) for h in hits]

    async def fetch_alerts(
        self, limit: int = 3, status: str = "open"
    ) -> list[Alert]:
        """Pull the most recent open detection alerts, normalized."""
        return [a for _, a in await self.fetch_alert_hits(limit, status)]

    async def set_alert_status(self, doc_id: str, status: str) -> None:
        """Set an alert's workflow status ('acknowledged', 'closed', ...).

        Partial-update merge on the nested ECS shape (the form Kibana alert
        docs and this project's dev seeds use). refresh=true so the next
        poll cycle doesn't re-fetch the same alert. On a production Elastic
        Security cluster, prefer Kibana's detection-engine signals-status
        API, which keeps the alert's audit trail; direct index updates are
        the dev-stack shortcut.
        """
        # replayable: a fixed-value merge — applying it twice sets the
        # same status twice.
        await self._post(
            f"/{self.alerts_index}/_update/{doc_id}?refresh=true",
            {"doc": {"kibana": {"alert": {"workflow_status": status}}}},
            replayable=True,
        )

    async def acknowledge_alert(self, doc_id: str) -> None:
        """Mark an alert as acknowledged so it leaves the 'open' queue."""
        await self.set_alert_status(doc_id, "acknowledged")

    async def annotate_disposition(
        self,
        alert_id: str,
        human_verdict: str,
        human_summary: str | None = None,
    ) -> int:
        """Stamp an analyst ruling onto that alert's investigation docs.

        Investigations are point-in-time snapshots; the ruling arrives
        later, from case management. Writing it back to the results
        index is what lets the dashboard show the copilot's verdict and
        the human's side by side — including the disagreements, which
        are the rows worth reading.

        Deliberately search + per-doc _update rather than
        _update_by_query: byquery needs broader index privileges than a
        least-privilege SIEM key usually carries (observed as a 403 on
        the dev stack), and per-doc updates also let human_agrees be
        computed against EACH doc's own verdict — a re-investigated
        alert shows which of the copilot's attempts the human ended up
        agreeing with. Returns how many docs were updated.
        """
        data = await self._post(
            f"/{self.results_index}/_search",
            {
                "size": 100,
                "query": {"term": {"alert_id.keyword": alert_id}},
                "_source": ["verdict"],
            },
            replayable=True,
        )
        hits = data.get("hits", {}).get("hits", [])
        for hit in hits:
            # replayable: stamps the same computed values either time.
            await self._post(
                f"/{self.results_index}/_update/{hit['_id']}?refresh=true",
                {
                    "doc": {
                        "human_verdict": human_verdict,
                        "human_summary": human_summary,
                        "human_agrees": hit["_source"].get("verdict")
                        == human_verdict,
                    }
                },
                replayable=True,
            )
        return len(hits)

    async def push_investigation(
        self,
        alert: Alert,
        investigation: Investigation,
        auto_closed: bool = False,
        closure_reason: str | None = None,
    ) -> str:
        """Index the investigation into the results index; returns the doc id.

        Summary fields are flattened at the top for easy dashboarding; the
        complete investigation rides along nested. When watch mode closes an
        alert autonomously, the closure decision and its policy reason are
        recorded here — the audit trail for the one action the copilot takes
        without a human.
        """
        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert.alert_id,
            "alert_title": alert.title,
            "verdict": investigation.verdict,
            "confidence": investigation.confidence,
            "escalation_recommended": investigation.escalation_recommended,
            "attack_techniques": investigation.attack_techniques,
            "is_campaign": bool(
                investigation.correlation
                and investigation.correlation.is_campaign
            ),
            "injection_flags": len(investigation.injection_flags),
            "auto_closed": auto_closed,
            "closure_reason": closure_reason,
            # Flattened so a dashboard can EXCLUDE suppressed duplicates
            # from cost aggregations: their true $0.00 would otherwise pull
            # the mean cost-per-investigation toward zero in Kibana exactly
            # as it would have in the digest (which filters on this field).
            "duplicate_of": investigation.duplicate_of,
            "is_duplicate": investigation.duplicate_of is not None,
            "investigation": investigation.model_dump(mode="json"),
        }
        # Flattened for dashboarding: cost and latency are things a SOC
        # lead charts over time, not fields they drill into a nested doc
        # for. Absent (not zero) when telemetry wasn't recorded.
        if investigation.telemetry:
            tel = investigation.telemetry
            doc.update(
                {
                    "cost_usd": tel.cost_usd,
                    "duration_seconds": tel.duration_seconds,
                    "input_tokens": tel.input_tokens,
                    "output_tokens": tel.output_tokens,
                    "api_calls": tel.api_calls,
                    "tool_calls": tel.tool_calls,
                    "model": tel.model,
                }
            )
        # NOT replayable: /_doc auto-generates an id, so a replay after an
        # ambiguous failure would index a duplicate results row (which the
        # dashboard counts). Connect failures still retry inside httpio.
        data = await self._post(f"/{self.results_index}/_doc", doc)
        return data.get("_id", "")

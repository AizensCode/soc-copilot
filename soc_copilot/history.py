"""Alert history — the copilot's cross-alert memory.

Every completed investigation is persisted, indexed by the indicators it
involved. When a new alert arrives, the store surfaces past investigations that
touched the same IOCs — the context a human analyst keeps in their head ("this
IP was flagged true_positive last week").

Backed by a JSONL file (one investigation record per line): appends are cheap,
no new dependency, and it matches the project's existing file-based persistence.
The interface is deliberately backend-agnostic — a SQLite implementation could
replace it without touching callers.
"""
import ipaddress
import json
import re
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import (
    Alert,
    Correlation,
    Investigation,
    PriorSighting,
    RelatedAlert,
)

# Default temporal window for campaign correlation. Overridable via config.
DEFAULT_WINDOW_HOURS = 72
# How many related prior alerts make this a "campaign" (current + this many).
CAMPAIGN_MIN_RELATED = 2

_TCODE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def alert_host(alert: Alert) -> str | None:
    """The alert's host as a plain string, whichever shape it arrived in.

    Native fixtures carry raw_log["host"] as a string; ECS-normalized
    alerts carry the ECS object ({"name": ...}). Memory must compare
    hosts across both shapes or an ECS alert and a native alert about
    the same machine would never correlate.
    """
    host = alert.raw_log.get("host") if isinstance(alert.raw_log, dict) else None
    if isinstance(host, dict):
        host = host.get("name")
    return host if isinstance(host, str) and host else None


def alert_iocs(alert: Alert) -> list[str]:
    """Flatten an alert's indicators into a de-duplicated list of IOC strings."""
    seen: list[str] = []
    for values in alert.indicators.values():
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, str) and value not in seen:
                seen.append(value)
    return seen


def _ipv4s(values: list[str]) -> list[str]:
    """Keep only the entries that parse as IPv4 addresses."""
    out: list[str] = []
    for v in values:
        try:
            if isinstance(ipaddress.ip_address(v), ipaddress.IPv4Address):
                out.append(v)
        except ValueError:
            continue
    return out


def _same_24(a: str, b: str) -> bool:
    """True if two IPv4 addresses share a /24 but are not identical."""
    if a == b:
        return False
    net = ipaddress.ip_network(f"{a}/24", strict=False)
    return ipaddress.ip_address(b) in net


def _parent_tcodes(techniques: list[str]) -> set[str]:
    """Parent-family T-codes from a list of technique strings (T1566.002 -> T1566)."""
    codes: set[str] = set()
    for t in techniques:
        for code in _TCODE_RE.findall(t):
            codes.add(code.split(".")[0])
    return codes


class AlertHistoryStore:
    """Persist investigations and look them up by shared indicator.

    Beside the investigations file lives a dispositions file
    (dispositions.jsonl): analyst rulings synced back from case
    management. The copilot's own verdicts are opinions; a human ruling
    on one of them is ground truth, and prior sightings carry both so
    the model can never cite an overturned opinion as unchallenged.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.dispositions_path = self.path.with_name("dispositions.jsonl")
        self.closures_path = self.path.with_name("closures.jsonl")

    def _iter_records(self) -> Iterator[dict]:
        if not self.path.exists():
            return
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if line:
                yield json.loads(line)

    def record_disposition(
        self,
        alert_id: str,
        human_verdict: str,
        source: str,
        summary: str | None = None,
    ) -> None:
        """Append an analyst ruling for a previously investigated alert.

        Append-only like the investigations file; the latest record per
        alert_id wins, so a re-opened and re-ruled case simply appends.
        """
        rec = {
            "alert_id": alert_id,
            "human_verdict": human_verdict,
            "source": source,
            "summary": summary,
            # When the ruling was SYNCED (not when the analyst clicked in
            # TheHive) — enough for "what came back since yesterday".
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        self.dispositions_path.parent.mkdir(parents=True, exist_ok=True)
        with self.dispositions_path.open("a") as f:
            f.write(json.dumps(rec) + "\n")

    def dispositions(self) -> dict[str, dict]:
        """Latest analyst ruling per alert_id."""
        out: dict[str, dict] = {}
        if not self.dispositions_path.exists():
            return out
        for line in self.dispositions_path.read_text().splitlines():
            line = line.strip()
            if line:
                rec = json.loads(line)
                out[rec["alert_id"]] = rec
        return out

    def record_closure(self, alert_id: str, reason: str | None) -> None:
        """Append an AUTONOMOUS closure event (watch mode's --auto-close
        actually firing). Until this existed the decision was pushed to
        Elastic and then forgotten locally, so the desk's automation rate
        — the whole point of autonomous closure — could not be computed
        from the store. Sidecar file, same append-only pattern as
        dispositions: what the copilot DID is a different kind of fact
        from what it CONCLUDED, and neither overwrites the other."""
        rec = {
            "alert_id": alert_id,
            "reason": reason,
            "closed_at": datetime.now(timezone.utc).isoformat(),
        }
        self.closures_path.parent.mkdir(parents=True, exist_ok=True)
        with self.closures_path.open("a") as f:
            f.write(json.dumps(rec) + "\n")

    def closures(self) -> dict[str, dict]:
        """Latest autonomous-closure event per alert_id."""
        out: dict[str, dict] = {}
        if not self.closures_path.exists():
            return out
        for line in self.closures_path.read_text().splitlines():
            line = line.strip()
            if line:
                rec = json.loads(line)
                out[rec["alert_id"]] = rec
        return out

    def record(self, alert: Alert, investigation: Investigation) -> None:
        """Append a record for a completed investigation.

        The summary fields (verdict, iocs, techniques...) are what memory
        lookups read on every alert; the full alert and investigation dumps
        exist so the copilot can later answer questions about its own
        reasoning (--ask) instead of remembering only its conclusion.
        Records written before these fields existed simply lack them.
        """
        rec = {
            "alert_id": alert.alert_id,
            # The alert's own time vs when the copilot worked it: memory
            # correlates on the former, the daily digest windows on the
            # latter. Records written before investigated_at existed
            # simply lack it (and fall outside any digest window).
            "timestamp": alert.timestamp.isoformat(),
            "investigated_at": datetime.now(timezone.utc).isoformat(),
            "title": alert.title,
            "verdict": investigation.verdict,
            "confidence": investigation.confidence,
            "host": alert_host(alert),
            "iocs": alert_iocs(alert),
            "attack_techniques": investigation.attack_techniques,
            # Flattened beside the summary fields (not only inside the
            # investigation dump) so cost/latency reporting never has to
            # parse a full record per row.
            "cost_usd": tel.cost_usd if (tel := investigation.telemetry) else None,
            "duration_seconds": tel.duration_seconds if tel else None,
            # Flattened so dedup's anchor scan and the digest can skip
            # suppressed records without parsing the investigation dump.
            "duplicate_of": investigation.duplicate_of,
            "alert": alert.model_dump(mode="json"),
            "investigation": investigation.model_dump(mode="json"),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(json.dumps(rec) + "\n")

    def latest_record(self, alert_id: str) -> dict | None:
        """The most recent investigation record for an alert, with the
        analyst's ruling (if any) joined in under "ruling"."""
        found: dict | None = None
        for rec in self._iter_records():
            if rec["alert_id"] == alert_id:
                found = rec  # file order: last line wins
        if found is None:
            return None
        ruling = self.dispositions().get(alert_id)
        if ruling:
            found = {**found, "ruling": ruling}
        return found

    def prior_sightings(self, alert: Alert) -> list[PriorSighting]:
        """Past investigations (excluding this alert_id) that share an IOC.

        Most recent first. Each prior alert appears once, with all of its
        overlapping indicators collected into matched_iocs.
        """
        current = set(alert_iocs(alert))
        if not current:
            return []

        rulings = self.dispositions()
        sightings: list[PriorSighting] = []
        seen_alert_ids: set[str] = set()
        for rec in self._iter_records():
            if rec["alert_id"] == alert.alert_id:
                continue  # don't match an alert against itself
            if rec["alert_id"] in seen_alert_ids:
                continue
            matched = sorted(current & set(rec.get("iocs", [])))
            if not matched:
                continue
            seen_alert_ids.add(rec["alert_id"])
            ruling = rulings.get(rec["alert_id"], {})
            sightings.append(
                PriorSighting(
                    alert_id=rec["alert_id"],
                    timestamp=rec["timestamp"],
                    verdict=rec["verdict"],
                    confidence=rec["confidence"],
                    title=rec["title"],
                    matched_iocs=matched,
                    human_verdict=ruling.get("human_verdict"),
                    human_summary=ruling.get("summary"),
                )
            )

        sightings.sort(key=lambda s: s.timestamp, reverse=True)
        return sightings

    def correlate(
        self,
        alert: Alert,
        techniques: list[str] | None = None,
        window_hours: int = DEFAULT_WINDOW_HOURS,
    ) -> Correlation:
        """Assess whether this alert clusters with recent prior alerts.

        Two alerts are "related" when they fall within window_hours of each
        other AND share at least one infrastructure/target signal (an exact
        IOC, a /24-adjacent IP, or the same host). A shared technique family is
        recorded as a corroborating signal but is never the sole link — that
        keeps generic TTPs (e.g. every phishing alert uses T1566) from
        producing spurious campaigns. is_campaign is True once enough related
        priors accumulate.

        `techniques` is optional so this can run BEFORE investigation (on
        alert-level signals alone, to inform the escalation decision) and again
        AFTER (with the final technique mapping, to record technique
        corroboration). Because relatedness rests on infrastructure/target
        signals, is_campaign is stable whether or not techniques are supplied.
        """
        current_iocs = set(alert_iocs(alert))
        current_ips = _ipv4s(list(current_iocs))
        current_host = alert_host(alert)
        current_techs = _parent_tcodes(techniques or [])
        window = timedelta(hours=window_hours)

        related: list[RelatedAlert] = []
        seen_alert_ids: set[str] = set()
        for rec in self._iter_records():
            if rec["alert_id"] == alert.alert_id:
                continue
            if rec["alert_id"] in seen_alert_ids:
                continue
            rec_time = datetime.fromisoformat(rec["timestamp"])
            if abs(alert.timestamp - rec_time) > window:
                continue

            rec_iocs = set(rec.get("iocs", []))
            signals: list[str] = []

            for shared in sorted(current_iocs & rec_iocs):
                signals.append(f"shared_ioc:{shared}")

            rec_ips = _ipv4s(list(rec_iocs))
            for a in current_ips:
                for b in rec_ips:
                    if _same_24(a, b):
                        signals.append(f"related_ip:{b}/24")

            rec_host = rec.get("host")
            if current_host and rec_host and current_host == rec_host:
                signals.append(f"shared_host:{current_host}")

            # Infrastructure/target overlap is required to be "related".
            if not signals:
                continue

            # Shared technique family corroborates an already-related pair.
            shared_techs = current_techs & _parent_tcodes(
                rec.get("attack_techniques", [])
            )
            for code in sorted(shared_techs):
                signals.append(f"shared_technique:{code}")

            seen_alert_ids.add(rec["alert_id"])
            related.append(
                RelatedAlert(
                    alert_id=rec["alert_id"],
                    timestamp=rec_time,
                    verdict=rec["verdict"],
                    signals=signals,
                )
            )

        related.sort(key=lambda r: r.timestamp, reverse=True)
        is_campaign = len(related) >= CAMPAIGN_MIN_RELATED

        if is_campaign:
            summary = (
                f"Possible coordinated campaign: {len(related) + 1} related "
                f"alerts within {window_hours}h "
                f"(this alert + {len(related)} prior)."
            )
        elif related:
            summary = (
                f"{len(related)} related prior alert(s) within {window_hours}h "
                f"— related activity, below campaign threshold."
            )
        else:
            summary = f"No related prior alerts within {window_hours}h."

        return Correlation(
            is_campaign=is_campaign,
            window_hours=window_hours,
            related_alerts=related,
            summary=summary,
        )

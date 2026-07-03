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
from datetime import datetime, timedelta
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
    """Persist investigations and look them up by shared indicator."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _iter_records(self) -> Iterator[dict]:
        if not self.path.exists():
            return
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if line:
                yield json.loads(line)

    def record(self, alert: Alert, investigation: Investigation) -> None:
        """Append a record for a completed investigation."""
        rec = {
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp.isoformat(),
            "title": alert.title,
            "verdict": investigation.verdict,
            "confidence": investigation.confidence,
            "host": alert.raw_log.get("host") if isinstance(alert.raw_log, dict) else None,
            "iocs": alert_iocs(alert),
            "attack_techniques": investigation.attack_techniques,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(json.dumps(rec) + "\n")

    def prior_sightings(self, alert: Alert) -> list[PriorSighting]:
        """Past investigations (excluding this alert_id) that share an IOC.

        Most recent first. Each prior alert appears once, with all of its
        overlapping indicators collected into matched_iocs.
        """
        current = set(alert_iocs(alert))
        if not current:
            return []

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
            sightings.append(
                PriorSighting(
                    alert_id=rec["alert_id"],
                    timestamp=rec["timestamp"],
                    verdict=rec["verdict"],
                    confidence=rec["confidence"],
                    title=rec["title"],
                    matched_iocs=matched,
                )
            )

        sightings.sort(key=lambda s: s.timestamp, reverse=True)
        return sightings

    def correlate(
        self,
        alert: Alert,
        investigation: Investigation,
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
        """
        current_iocs = set(alert_iocs(alert))
        current_ips = _ipv4s(list(current_iocs))
        current_host = (
            alert.raw_log.get("host") if isinstance(alert.raw_log, dict) else None
        )
        current_techs = _parent_tcodes(investigation.attack_techniques)
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

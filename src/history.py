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
import json
from collections.abc import Iterator
from pathlib import Path

from .models import Alert, Investigation, PriorSighting


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

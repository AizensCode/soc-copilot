"""Shared fixture loader: one function, both alert shapes.

Native fixtures are Alert JSON. ECS-shaped fixtures are raw Elastic hits
({"_id": ..., "_source": {...}}) and are loaded through the REAL
normalizer (soc_copilot/elastic.py normalize_hit) — so the harness evaluates the
same code path a production alert takes, normalization included. A
divergence between the two paths (observed live before this existed) is
exactly what these fixtures are for.
"""
import json
from pathlib import Path

from soc_copilot.elastic import normalize_hit
from soc_copilot.models import Alert

SAMPLE_ALERTS_DIR = Path("data/sample_alerts")


def load_alert_fixture(path: Path) -> Alert:
    with path.open() as f:
        data = json.load(f)
    if "_source" in data:
        return normalize_hit(data)
    data.pop("_comment", None)
    return Alert(**data)


def load_all_fixtures() -> dict[str, Alert]:
    return {
        p.name: load_alert_fixture(p)
        for p in sorted(SAMPLE_ALERTS_DIR.glob("*.json"))
    }

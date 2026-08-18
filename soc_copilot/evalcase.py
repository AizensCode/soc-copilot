"""Turn analyst rulings into eval-harness cases.

The scorecard's whole point is that disagreement rows drive improvement
— but carrying one into the eval harness was a manual act of fixture
authoring. This module closes that gap: any investigation a human has
ruled on can be exported as a labeled case under data/evals/cases/,
where the live regression test (tests/test_regression_cases.py) replays
it and checks the copilot's verdict against the ANALYST's ruling — the
one label in this project that is ground truth rather than taste.

Two honesty rules:
- Only rulings can label a case. An unruled investigation has nothing
  but the copilot's own opinion to grade against, and self-graded
  regression is an echo chamber.
- Only full records can be exported. Pre-upgrade summary-only records
  lack the alert itself, so there is nothing to replay; the fix is to
  re-investigate the alert (which records a full dump), not to guess.

Whether the copilot AGREED with the ruling at export time is stamped on
the case: agreement cases are regression armor (a later model or prompt
change must not lose them), disagreement cases are declared improvement
targets (expected-to-fail until the copilot earns them — the regression
test xfails those instead of breaking the suite).
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from .history import AlertHistoryStore

CASES_DIR = Path("data/evals/cases")


def export_case(
    store: AlertHistoryStore,
    alert_id: str,
    dest_dir: Path = CASES_DIR,
) -> Path:
    """Export one ruled, fully-recorded investigation as a labeled case.

    Overwrites an existing export for the same alert — the latest
    record and latest ruling are the case. Raises ValueError with a
    what-to-do-instead message when the alert is ineligible.
    """
    record = store.latest_record(alert_id)
    if record is None:
        raise ValueError(f"No investigation on record for {alert_id!r}.")
    ruling = record.get("ruling")
    if ruling is None:
        raise ValueError(
            f"{alert_id} has no analyst ruling — only a human ruling can "
            f"label an eval case (self-graded regression is an echo "
            f"chamber). Sync feedback after an analyst works the case."
        )
    if "alert" not in record:
        raise ValueError(
            f"{alert_id} was investigated before full-record storage, so "
            f"the alert itself was not kept and cannot be replayed. "
            f"Re-investigate the alert to record a full dump, then export."
        )
    if record.get("duplicate_of"):
        raise ValueError(
            f"{alert_id} was suppressed as a near-duplicate of "
            f"{record['duplicate_of']} — its verdict was borrowed, not "
            f"produced by investigating this alert, so it cannot label an "
            f"eval case. Export the anchor instead."
        )

    case = {
        "alert_id": alert_id,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "alert": record["alert"],
        "label": {
            "human_verdict": ruling["human_verdict"],
            "source": ruling.get("source", "?"),
            "summary": ruling.get("summary"),
        },
        "copilot_verdict_at_export": record["verdict"],
        "agreed_at_export": record["verdict"] == ruling["human_verdict"],
    }
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / f"{alert_id}.json"
    path.write_text(json.dumps(case, indent=2) + "\n")
    return path


def exportable_alert_ids(store: AlertHistoryStore) -> list[str]:
    """Alert IDs that are both ruled and fully recorded, in store order."""
    ids: list[str] = []
    rulings = store.dispositions()
    latest: dict[str, dict] = {}
    for rec in store.iter_records():
        latest[rec["alert_id"]] = rec
    for alert_id, rec in latest.items():
        if alert_id in rulings and "alert" in rec and not rec.get("duplicate_of"):
            ids.append(alert_id)
    return ids

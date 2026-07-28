"""CLI entry point.

    # Investigate a local alert file
    uv run python -m src.main <alert.json> [--agentic] [--report [out.html]]

    # Pull open detection alerts from Elastic and investigate each
    uv run python -m src.main --from-elastic [N] [--agentic] [--push] [--report]
"""
import asyncio
import json
import sys
from pathlib import Path

from .copilot import SOCCopilot
from .models import Alert, Investigation

USAGE = (
    "Usage:\n"
    "  python -m src.main <path/to/alert.json> [--agentic] [--report [out.html]]\n"
    "  python -m src.main --from-elastic [N] [--agentic] [--push] [--report]"
)


def _arg_after(flag: str) -> str | None:
    """Return the value following a flag, if present and not another flag."""
    if flag not in sys.argv:
        return None
    idx = sys.argv.index(flag)
    if idx + 1 < len(sys.argv) and not sys.argv[idx + 1].startswith("-"):
        return sys.argv[idx + 1]
    return None


async def _investigate(
    copilot: SOCCopilot, alert: Alert, agentic: bool
) -> Investigation:
    if agentic:
        print("[mode: agentic — model decides tool calls]")
        return await copilot.investigate_agentic(alert)
    print("[mode: phase one — fixed enrichment pipeline]")
    return await copilot.investigate(alert)


def _write_report(alert: Alert, inv: Investigation, out: Path) -> None:
    from .report import render_report

    out.write_text(render_report(alert, inv))
    print(f"HTML report written to {out}")


async def _run_file(agentic: bool) -> None:
    alert_path = Path(sys.argv[1])
    with alert_path.open() as f:
        alert = Alert(**json.load(f))

    copilot = SOCCopilot()
    investigation = await _investigate(copilot, alert, agentic)

    debug_path = Path("last_run_debug.json")
    with debug_path.open("w") as f:
        json.dump(
            {
                "mode": "agentic" if agentic else "phase_one",
                "alert": alert.model_dump(mode="json"),
                "evidence_raw": [
                    e.model_dump(mode="json") for e in investigation.evidence
                ],
                "investigation": investigation.model_dump(mode="json"),
            },
            f,
            indent=2,
            default=str,
        )
    print(f"Full debug written to {debug_path}")

    if "--report" in sys.argv:
        out = Path(_arg_after("--report") or "investigation_report.html")
        _write_report(alert, investigation, out)

    print(investigation.model_dump_json(indent=2))


async def _run_elastic(agentic: bool) -> None:
    from .elastic import ElasticAlertSource

    limit = int(_arg_after("--from-elastic") or 3)
    try:
        source = ElasticAlertSource()
    except RuntimeError as e:
        print(e)
        sys.exit(1)
    print(f"Fetching up to {limit} open detection alerts from Elastic...")
    alerts = await source.fetch_alerts(limit=limit)
    if not alerts:
        print("No open alerts found.")
        return

    copilot = SOCCopilot()
    for alert in alerts:
        print(f"\n=== {alert.alert_id} — {alert.title} ===")
        investigation = await _investigate(copilot, alert, agentic)

        campaign = bool(
            investigation.correlation and investigation.correlation.is_campaign
        )
        print(
            f"verdict={investigation.verdict} "
            f"confidence={investigation.confidence} "
            f"escalate={investigation.escalation_recommended} "
            f"campaign={campaign} "
            f"injection_flags={len(investigation.injection_flags)}"
        )

        if "--report" in sys.argv:
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            _write_report(
                alert, investigation, reports_dir / f"{alert.alert_id}.html"
            )

        if "--push" in sys.argv:
            doc_id = await source.push_investigation(alert, investigation)
            print(f"Pushed investigation to Elastic (doc id: {doc_id})")


async def main() -> None:
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(1)

    agentic = "--agentic" in sys.argv
    if sys.argv[1] == "--from-elastic":
        await _run_elastic(agentic)
    else:
        await _run_file(agentic)


if __name__ == "__main__":
    asyncio.run(main())

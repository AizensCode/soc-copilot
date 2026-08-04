"""CLI entry point.

    # Investigate a local alert file
    uv run python -m src.main <alert.json> [--agentic] [--report [out.html]]

    # Pull open detection alerts from Elastic and investigate each
    uv run python -m src.main --from-elastic [N] [--agentic] [--push] [--report]

    # Stay running: poll Elastic, investigate every new open alert,
    # push the result, acknowledge the alert. With --auto-close, alerts
    # whose investigation passes the closure policy (high-confidence
    # false positive, no escalation/injection/campaign) are closed
    # autonomously instead of acknowledged.
    uv run python -m src.main --watch [interval_seconds] [--agentic] [--auto-close]
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
    "  python -m src.main --from-elastic [N] [--agentic] [--push] [--report]\n"
    "  python -m src.main --watch [interval_seconds] [--agentic] [--auto-close]"
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


async def _run_watch(agentic: bool) -> None:
    """Continuous mode: the copilot works the open-alert queue by itself.

    Each cycle: fetch open alerts, investigate each, push the result,
    acknowledge the alert in Elastic (which removes it from the next
    poll — acknowledgement IS the dedupe). A per-session seen-set guards
    against re-investigating if an acknowledgement fails; a failed alert
    is logged and retried on a later cycle rather than killing the loop.

    With --auto-close, investigations that pass the deterministic closure
    policy (src/closure.py: high-confidence false positive, no
    escalation/injection/campaign signals) close the alert autonomously,
    with the policy reason recorded in the results index. Everything else
    is acknowledged for a human, exactly as without the flag.
    """
    from .closure import should_auto_close
    from .elastic import ElasticAlertSource

    interval = int(_arg_after("--watch") or 60)
    try:
        source = ElasticAlertSource()
    except RuntimeError as e:
        print(e)
        sys.exit(1)

    auto_close = "--auto-close" in sys.argv
    copilot = SOCCopilot()
    seen: set[str] = set()
    mode = "agentic" if agentic else "phase one"
    # flush every line: when watch runs under nohup/systemd its output is
    # the operator's only heartbeat, and block-buffering would hide it
    print(
        f"Watching {source.alerts_index} every {interval}s ({mode} mode"
        f"{', auto-close on' if auto_close else ''}). Ctrl+C to stop.",
        flush=True,
    )
    while True:
        try:
            hits = await source.fetch_alert_hits(limit=10, status="open")
            fresh = [(d, a) for d, a in hits if d not in seen]
            for doc_id, alert in fresh:
                print(f"\n=== {alert.alert_id} — {alert.title} ===", flush=True)
                try:
                    investigation = await _investigate(copilot, alert, agentic)
                    close, reason = (
                        should_auto_close(investigation)
                        if auto_close
                        else (False, None)
                    )
                    result_id = await source.push_investigation(
                        alert,
                        investigation,
                        auto_closed=close,
                        closure_reason=reason,
                    )
                    await source.set_alert_status(
                        doc_id, "closed" if close else "acknowledged"
                    )
                    seen.add(doc_id)
                    disposition = (
                        f"alert CLOSED autonomously ({reason})"
                        if close
                        else "alert acknowledged"
                    )
                    print(
                        f"verdict={investigation.verdict} "
                        f"confidence={investigation.confidence} "
                        f"escalate={investigation.escalation_recommended} "
                        f"-> pushed {result_id}, {disposition}",
                        flush=True,
                    )
                except Exception as e:
                    print(f"FAILED (will retry next cycle): {e}", flush=True)
        except Exception as e:
            print(
                f"Poll cycle failed (retrying in {interval}s): {e}", flush=True
            )
        await asyncio.sleep(interval)


async def main() -> None:
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(1)

    agentic = "--agentic" in sys.argv
    if sys.argv[1] == "--from-elastic":
        await _run_elastic(agentic)
    elif sys.argv[1] == "--watch":
        try:
            await _run_watch(agentic)
        except KeyboardInterrupt:
            print("\nWatch stopped.")
    else:
        await _run_file(agentic)


if __name__ == "__main__":
    asyncio.run(main())

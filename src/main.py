"""CLI entry point.

    # Investigate a local alert file
    uv run python -m src.main <alert.json> [--agentic] [--report [out.html]] [--case]

    # Pull open detection alerts from Elastic and investigate each
    uv run python -m src.main --from-elastic [N] [--agentic] [--push] [--report] [--case]

    # Stay running: poll Elastic, investigate every new open alert,
    # push the result, acknowledge the alert. With --auto-close, alerts
    # whose investigation passes the closure policy (high-confidence
    # false positive, no escalation/injection/campaign) are closed
    # autonomously instead of acknowledged.
    uv run python -m src.main --watch [interval_seconds] [--agentic] [--auto-close] [--case]

    --case opens a TheHive alert for investigations a human should own
    (escalated, true-positive, or campaign-correlated). Requires
    THEHIVE_URL and THEHIVE_API_KEY.

    # Pull analyst rulings from TheHive back into the copilot's memory:
    # prior sightings then carry the human's verdict beside the
    # copilot's own, and a ruling outranks the recorded opinion.
    uv run python -m src.main --sync-feedback
"""
import asyncio
import json
import sys
from pathlib import Path

from .copilot import SOCCopilot
from .models import Alert, Investigation

# How often watch mode pulls analyst rulings back from TheHive. Rulings
# change on a human cadence, so minutes — not poll cycles — is the unit.
FEEDBACK_SYNC_INTERVAL = 300

USAGE = (
    "Usage:\n"
    "  python -m src.main <path/to/alert.json> [--agentic] [--report [out.html]] [--case]\n"
    "  python -m src.main --from-elastic [N] [--agentic] [--push] [--report] [--case]\n"
    "  python -m src.main --watch [interval_seconds] [--agentic] [--auto-close] [--case]\n"
    "  python -m src.main --sync-feedback"
)


async def _annotate_elastic(changed: list[dict]) -> None:
    """Stamp new rulings onto the investigations index, when Elastic is
    configured — this is what puts the human's verdict next to the
    copilot's on the dashboard. Never fatal: the ruling is already safe
    in the history store."""
    if not changed:
        return
    from .elastic import ElasticAlertSource

    try:
        source = ElasticAlertSource()
    except RuntimeError:
        return  # no Elastic configured — memory still has the rulings
    for d in changed:
        try:
            n = await source.annotate_disposition(
                d["alert_id"], d["human_verdict"], d.get("summary")
            )
            if n:
                print(
                    f"  -> stamped onto {n} investigation doc(s) in Elastic",
                    flush=True,
                )
        except Exception as e:
            print(f"  -> Elastic annotation failed: {e}", flush=True)


def _print_rulings(changed: list[dict], known: set[str]) -> None:
    for d in changed:
        marker = (
            "" if d["alert_id"] in known
            else " (no local investigation on record)"
        )
        note = f' — "{d["summary"]}"' if d.get("summary") else ""
        print(
            f"{d['alert_id']}: analyst ruled {d['human_verdict']} "
            f"[{d['source']}]{note}{marker}",
            flush=True,
        )


async def _run_sync_feedback() -> None:
    """Pull analyst rulings from TheHive into the copilot's memory.

    After this, prior sightings carry the human's verdict beside the
    copilot's own — memory stops being an echo chamber of the copilot's
    opinions. Watch mode does this by itself on a timer; the CLI form
    exists for cron jobs and one-off catch-ups.
    """
    from .casemgmt import TheHiveClient, sync_dispositions
    from .config import settings
    from .history import AlertHistoryStore

    store = AlertHistoryStore(settings.HISTORY_PATH)
    known = {r["alert_id"] for r in store._iter_records()}
    try:
        changed, total = await sync_dispositions(TheHiveClient(), store)
    except RuntimeError as e:
        print(e)
        sys.exit(1)
    if total == 0:
        print("No analyst rulings found in TheHive yet.")
        return
    _print_rulings(changed, known)
    await _annotate_elastic(changed)
    print(
        f"{len(changed)} new/changed ruling(s), "
        f"{total - len(changed)} already known "
        f"({store.dispositions_path})"
    )


async def _maybe_open_case(alert: Alert, investigation: Investigation) -> None:
    """Open a TheHive alert when --case is set and the policy says a human
    should own this. Never fatal: case management is an output channel, so
    a TheHive outage must not lose an investigation that already succeeded.
    """
    if "--case" not in sys.argv:
        return
    from .casemgmt import TheHiveClient, should_open_case

    open_case, reason = should_open_case(investigation)
    if not open_case:
        print(f"No case opened ({reason})", flush=True)
        return
    try:
        case_id = await TheHiveClient().create_alert(alert, investigation)
        print(f"Opened TheHive alert {case_id} ({reason})", flush=True)
    except RuntimeError as e:
        print(f"Case creation failed: {e}", flush=True)


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

    await _maybe_open_case(alert, investigation)

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

        await _maybe_open_case(alert, investigation)


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

    When TheHive is configured, analyst rulings are synced back every
    FEEDBACK_SYNC_INTERVAL seconds — the copilot keeps learning from the
    humans working its cases without an operator remembering to run
    --sync-feedback. A sync failure is logged and retried next time,
    never fatal.
    """
    import time

    from .closure import should_auto_close
    from .config import settings
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
    feedback = bool(settings.THEHIVE_URL and settings.THEHIVE_API_KEY)
    last_feedback_sync = float("-inf")
    # flush every line: when watch runs under nohup/systemd its output is
    # the operator's only heartbeat, and block-buffering would hide it
    print(
        f"Watching {source.alerts_index} every {interval}s ({mode} mode"
        f"{', auto-close on' if auto_close else ''}"
        f"{', analyst-feedback sync on' if feedback else ''}). "
        f"Ctrl+C to stop.",
        flush=True,
    )
    while True:
        if feedback and time.monotonic() - last_feedback_sync >= FEEDBACK_SYNC_INTERVAL:
            last_feedback_sync = time.monotonic()
            try:
                from .casemgmt import TheHiveClient, sync_dispositions

                changed, _ = await sync_dispositions(
                    TheHiveClient(), copilot.history
                )
                if changed:
                    print("Analyst feedback synced from TheHive:", flush=True)
                    known = {
                        r["alert_id"]
                        for r in copilot.history._iter_records()
                    }
                    _print_rulings(changed, known)
                    await _annotate_elastic(changed)
            except Exception as e:
                print(
                    f"Feedback sync failed (will retry): {e}", flush=True
                )
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
                    # An auto-closed alert needs no human owner by
                    # definition, so it never generates case-management
                    # noise; everything else is offered to the policy.
                    if not close:
                        await _maybe_open_case(alert, investigation)
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
    if sys.argv[1] == "--sync-feedback":
        await _run_sync_feedback()
    elif sys.argv[1] == "--from-elastic":
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

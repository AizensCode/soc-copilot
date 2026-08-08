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
    uv run python -m src.main --watch [interval_seconds] [--agentic] [--auto-close] [--case] [--notify]

    --case opens a TheHive alert for investigations a human should own
    (escalated, true-positive, or campaign-correlated). Requires
    THEHIVE_URL and THEHIVE_API_KEY.

    --notify POSTs a webhook for escalations and campaigns only (never
    routine acknowledgements), so an unattended --watch can page an
    on-call analyst. Requires WEBHOOK_URL.

    # Pull analyst rulings from TheHive back into the copilot's memory:
    # prior sightings then carry the human's verdict beside the
    # copilot's own, and a ruling outranks the recorded opinion.
    uv run python -m src.main --sync-feedback

    # Interrogate a recorded investigation: one-shot with a question,
    # or an interactive session without one. Answers are grounded in
    # the stored record — no new tool calls, no re-investigation.
    uv run python -m src.main --ask ALERT_ID ["question"]

    # The SOC morning digest: what the copilot investigated in the
    # window, what rulings came back, what needs a human first.
    uv run python -m src.main --digest [hours]

    # Export analyst-ruled investigations as labeled eval cases under
    # data/evals/cases/, replayed by tests/test_regression_cases.py.
    # Without an ID, exports everything eligible.
    uv run python -m src.main --export-case [ALERT_ID]
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
    "  python -m src.main --watch [interval_seconds] [--agentic] [--auto-close] [--case] [--notify]\n"
    "  python -m src.main --sync-feedback\n"
    "  python -m src.main --scorecard\n"
    "  python -m src.main --ask ALERT_ID [\"question\"]\n"
    "  python -m src.main --digest [hours]\n"
    "  python -m src.main --export-case [ALERT_ID]"
)


async def _run_export_case() -> None:
    """Export ruled investigations as labeled eval cases.

    With an alert ID, exports that one (and says exactly why not, when
    it can't). Without, exports everything eligible and lists the ruled
    alerts that can't be exported yet so the operator knows what a
    re-investigation would unlock.
    """
    from .config import settings
    from .evalcase import export_case, exportable_alert_ids
    from .history import AlertHistoryStore

    store = AlertHistoryStore(settings.HISTORY_PATH)
    alert_id = sys.argv[2] if len(sys.argv) > 2 else None

    if alert_id:
        try:
            path = export_case(store, alert_id)
        except ValueError as e:
            print(e)
            sys.exit(1)
        print(f"Exported {alert_id} -> {path}")
        return

    eligible = exportable_alert_ids(store)
    for aid in eligible:
        print(f"Exported {aid} -> {export_case(store, aid)}")
    known = {r["alert_id"] for r in store._iter_records()}
    blocked = [
        aid for aid in store.dispositions()
        if aid in known and aid not in eligible
    ]
    for aid in blocked:
        print(
            f"Skipped {aid}: ruled, but the record predates full-record "
            f"storage — re-investigate to make it exportable."
        )
    if not eligible and not blocked:
        print(
            "Nothing to export: no analyst-ruled investigations on "
            "record. Sync feedback after analysts work the queue."
        )


async def _run_digest() -> None:
    """Print the SOC briefing for the reporting window (default 24h).

    A quiet window is answered deterministically — no API call is spent
    narrating an empty day.
    """
    from .config import settings
    from .digest import build_digest_data, render_quiet, write_briefing
    from .history import AlertHistoryStore

    hours = _positive_int_after("--digest", 24, "window hours")
    store = AlertHistoryStore(settings.HISTORY_PATH)
    data = build_digest_data(store, since_hours=hours)
    if data["quiet"]:
        print(render_quiet(data))
        return
    # Only the narrated path spends the API — require the key here, not
    # up front, so a quiet digest still costs nothing (and needs no key).
    settings.require("ANTHROPIC_KEY")
    print(await write_briefing(data))


async def _run_ask() -> None:
    """Follow-up mode: interrogate a recorded investigation.

    With a question argument, answers once and exits (scriptable).
    Without one, holds an interactive session — later questions ride on
    the same conversation, so "and why high confidence?" works.
    """
    from .config import settings
    from .followup import FollowUpSession
    from .history import AlertHistoryStore

    if len(sys.argv) < 3:
        print(USAGE)
        sys.exit(1)
    settings.require("ANTHROPIC_KEY")  # every answer is an LLM call
    alert_id = sys.argv[2]
    store = AlertHistoryStore(settings.HISTORY_PATH)
    try:
        session = FollowUpSession(alert_id, history_store=store)
    except KeyError:
        known = list(dict.fromkeys(r["alert_id"] for r in store._iter_records()))
        print(f"No investigation on record for {alert_id!r}.")
        if known:
            print("Investigated alerts (oldest first):")
            for aid in known:
                print(f"  {aid}")
        sys.exit(1)

    question = sys.argv[3] if len(sys.argv) > 3 else None
    if question:
        print(await session.ask(question))
        return

    print(
        f"Follow-up session on {alert_id} — answers come from the stored "
        f"record only. Empty line or Ctrl+D to exit.",
        flush=True,
    )
    while True:
        try:
            q = input("ask> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not q:
            break
        print(await session.ask(q), flush=True)
        print(flush=True)


async def _run_scorecard() -> None:
    """Print the copilot-vs-analyst accuracy record from local memory."""
    from .config import settings
    from .history import AlertHistoryStore
    from .scorecard import build_scorecard, render_scorecard

    store = AlertHistoryStore(settings.HISTORY_PATH)
    print(render_scorecard(build_scorecard(store)))


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


async def _maybe_open_case(
    alert: Alert, investigation: Investigation
) -> str | None:
    """Open a TheHive alert when --case is set and the policy says a human
    should own this. Returns the created TheHive alert id (so a caller can
    link to it), or None. Never fatal: case management is an output
    channel, so a TheHive outage must not lose an investigation that
    already succeeded.
    """
    if "--case" not in sys.argv:
        return None
    from .casemgmt import TheHiveClient, should_open_case

    open_case, reason = should_open_case(investigation)
    if not open_case:
        print(f"No case opened ({reason})", flush=True)
        return None
    try:
        case_id = await TheHiveClient().create_alert(alert, investigation)
        print(f"Opened TheHive alert {case_id} ({reason})", flush=True)
        return case_id
    except RuntimeError as e:
        print(f"Case creation failed: {e}", flush=True)
        return None


async def _maybe_notify(
    alert: Alert,
    investigation: Investigation,
    thehive_alert_id: str | None = None,
) -> None:
    """Page a webhook when --notify is set and the investigation is an
    escalation or campaign. Never fatal: a webhook outage must not lose an
    investigation. Fires only for page-worthy findings — routine
    acknowledgements stay silent so the channel doesn't become noise.
    """
    if "--notify" not in sys.argv:
        return
    from .config import settings
    from .notify import WebhookClient, build_notification, should_notify

    page, reason = should_notify(investigation)
    if not page:
        return
    case_link = None
    if thehive_alert_id and settings.THEHIVE_URL:
        base = settings.THEHIVE_URL.rstrip("/")
        case_link = f"{base}/index.html#!/alert/{thehive_alert_id}/details"
    try:
        await WebhookClient().post(
            build_notification(alert, investigation, case_link)
        )
        print(f"Notified webhook ({reason})", flush=True)
    except RuntimeError as e:
        print(f"Webhook notification failed: {e}", flush=True)


def _arg_after(flag: str) -> str | None:
    """Return the value following a flag, if present and not another flag."""
    if flag not in sys.argv:
        return None
    idx = sys.argv.index(flag)
    if idx + 1 < len(sys.argv) and not sys.argv[idx + 1].startswith("-"):
        return sys.argv[idx + 1]
    return None


def _positive_int_after(flag: str, default: int, what: str) -> int:
    """The numeric value following a flag, validated, or the default.

    _arg_after's leading-dash check (there so a following flag like
    --agentic isn't consumed as a value) also swallows negative numbers
    — `--digest -1` would silently run with the default. A numeric
    token is always the user's intended value, so parse it even with a
    leading dash, then reject anything that isn't a positive integer
    loudly instead of guessing.
    """
    idx = sys.argv.index(flag)
    if idx + 1 >= len(sys.argv):
        return default
    raw = sys.argv[idx + 1]
    if raw.startswith("-") and not raw.lstrip("-").isdigit():
        return default  # another flag, not a value
    try:
        value = int(raw)
    except ValueError:
        print(f"{flag}: {what} must be a positive integer, got {raw!r}")
        sys.exit(2)
    if value <= 0:
        print(f"{flag}: {what} must be a positive integer, got {value}")
        sys.exit(2)
    return value


def _telemetry_line(inv: Investigation) -> str:
    """One-line cost/latency summary, or '' when nothing was recorded."""
    tel = inv.telemetry
    if not tel:
        return ""
    from .pricing import is_priced

    cost = f"${tel.cost_usd:.4f}" if is_priced(tel.model) else "cost unpriced"
    tools = f" tools={tel.tool_calls}" if tel.tool_calls else ""
    retries = f" retries={tel.retries}" if tel.retries else ""
    return (
        f"[{cost} · {tel.duration_seconds:.1f}s · "
        f"{tel.input_tokens}in/{tel.output_tokens}out · "
        f"{tel.api_calls} call(s){tools}{retries}]"
    )


def _require_investigation_keys() -> None:
    """Every real investigation calls the model and the enrichment tools;
    demand those keys up front so a keyless run fails fast and legibly
    (the library itself stays lazy — see src/config.py)."""
    from .config import settings

    settings.require(
        "ANTHROPIC_KEY", "ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "URLSCAN_KEY"
    )


async def _investigate(
    copilot: SOCCopilot, alert: Alert, agentic: bool
) -> Investigation:
    if agentic:
        print("[mode: agentic — model decides tool calls]")
        inv = await copilot.investigate_agentic(alert)
    else:
        print("[mode: phase one — fixed enrichment pipeline]")
        inv = await copilot.investigate(alert)
    line = _telemetry_line(inv)
    if line:
        print(line, flush=True)
    return inv


def _write_report(alert: Alert, inv: Investigation, out: Path) -> None:
    from .report import render_report

    out.write_text(render_report(alert, inv))
    print(f"HTML report written to {out}")


async def _run_file(agentic: bool) -> None:
    _require_investigation_keys()
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

    _require_investigation_keys()
    limit = _positive_int_after("--from-elastic", 3, "alert limit")
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

    _require_investigation_keys()
    interval = _positive_int_after("--watch", 60, "poll interval seconds")
    try:
        source = ElasticAlertSource()
    except RuntimeError as e:
        print(e)
        sys.exit(1)

    auto_close = "--auto-close" in sys.argv
    notify = "--notify" in sys.argv
    if notify and not settings.WEBHOOK_URL:
        # Fail loudly at startup rather than silently never paging.
        print("--notify requires WEBHOOK_URL in your .env")
        sys.exit(1)
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
        f"{', notifications on' if notify else ''}"
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
                    # noise or a page; everything else is offered to the
                    # policies. The page links to the case when one opened.
                    if not close:
                        case_id = await _maybe_open_case(alert, investigation)
                        await _maybe_notify(alert, investigation, case_id)
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
    elif sys.argv[1] == "--scorecard":
        await _run_scorecard()
    elif sys.argv[1] == "--ask":
        await _run_ask()
    elif sys.argv[1] == "--digest":
        await _run_digest()
    elif sys.argv[1] == "--export-case":
        await _run_export_case()
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
    try:
        asyncio.run(main())
    except RuntimeError as e:
        # A missing-key (or other configuration) error should read as one
        # clear line, not a stack trace — the message already names the
        # exact environment variable to set.
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

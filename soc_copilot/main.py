"""CLI entry point.

    # Investigate a local alert file
    uv run soc-copilot <alert.json> [--agentic] [--report [out.html]] [--case] [--debug [out.json]]

    # Pull open detection alerts from Elastic and investigate each
    uv run soc-copilot --from-elastic [N] [--agentic] [--push] [--report] [--case]

    # Stay running: poll Elastic, investigate every new open alert,
    # push the result, acknowledge the alert. With --auto-close, alerts
    # whose investigation passes the closure policy (high-confidence
    # false positive, no escalation/injection/campaign) are closed
    # autonomously instead of acknowledged.
    uv run soc-copilot --watch [interval_seconds] [--agentic] [--auto-close] [--case] [--notify] [--dedup [WINDOW_H]]

    --dedup suppresses near-duplicate repeats of recent high-confidence
    false positives instead of re-investigating them (soc_copilot/dedup.py
    spells out the gates; window in hours, default 24).

    --tiered runs a cheap first-pass model and promotes only the alerts
    that are not a clean high-confidence false positive to the strong
    model (soc_copilot/routing.py spells out the gates). Composes with
    --dedup: dedup suppresses repeats first, then --tiered handles the
    first look at whatever is left.

    --case opens a TheHive alert for investigations a human should own
    (escalated, true-positive, or campaign-correlated). Requires
    THEHIVE_URL and THEHIVE_API_KEY.

    --notify POSTs a webhook for escalations and campaigns only (never
    routine acknowledgements), so an unattended --watch can page an
    on-call analyst. Requires WEBHOOK_URL.

    # Pull analyst rulings from TheHive back into the copilot's memory:
    # prior sightings then carry the human's verdict beside the
    # copilot's own, and a ruling outranks the recorded opinion.
    uv run soc-copilot --sync-feedback

    # Interrogate a recorded investigation: one-shot with a question,
    # or an interactive session without one. Answers are grounded in
    # the stored record — no new tool calls, no re-investigation.
    uv run soc-copilot --ask ALERT_ID ["question"]

    # The SOC morning digest: what the copilot investigated in the
    # window, what rulings came back, what needs a human first.
    uv run soc-copilot --digest [hours]

    # Export analyst-ruled investigations as labeled eval cases under
    # data/evals/cases/, replayed by tests/test_regression_cases.py.
    # Without an ID, exports everything eligible.
    uv run soc-copilot --export-case [ALERT_ID]
"""
import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from .copilot import SOCCopilot
from .dedup import DEFAULT_WINDOW_HOURS as DEDUP_WINDOW_HOURS
from .logsetup import alert_context, configure_logging
from .models import Alert, Investigation
from .watchdog import CycleReport, Watchdog

# The CLI's voice (configured in cli() via logsetup.configure_logging —
# nowhere else). The split this module holds: a command's PRODUCT (an
# investigation JSON, the scorecard, the digest, usage) is print() on
# stdout, pipeable; everything that NARRATES — progress, failures,
# health — goes through this logger to stderr, where it carries a level
# and, in JSON mode, a timestamp and the alert id being worked.
# The name is pinned, NOT __name__: under `python -m soc_copilot.main`
# this module runs as "__main__", which sits outside the "soc_copilot"
# hierarchy configure_logging configures — every INFO line would vanish
# into the stdlib's lastResort handler (review catch).
log = logging.getLogger("soc_copilot.main")

# How often watch mode pulls analyst rulings back from TheHive. Rulings
# change on a human cadence, so minutes — not poll cycles — is the unit.
FEEDBACK_SYNC_INTERVAL = 300

USAGE = (
    "Usage:\n"
    "  soc-copilot <path/to/alert.json> [--agentic] [--tiered] [--report [out.html]] [--case] [--debug [out.json]]\n"
    "  soc-copilot --from-elastic [N] [--agentic] [--tiered] [--push] [--report] [--case]\n"
    "  soc-copilot --watch [interval_seconds] [--agentic] [--tiered] [--auto-close] [--case] [--notify] [--dedup [WINDOW_H]]\n"
    "  soc-copilot --sync-feedback\n"
    "  soc-copilot --scorecard\n"
    "  soc-copilot --ask ALERT_ID [\"question\"]\n"
    "  soc-copilot --digest [hours]\n"
    "  soc-copilot --export-case [ALERT_ID]"
)


async def _run_export_case(args: argparse.Namespace) -> None:
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
    alert_id = args.alert_id

    if alert_id:
        try:
            path = export_case(store, alert_id)
        except ValueError as e:
            log.error("%s", e)
            sys.exit(1)
        print(f"Exported {alert_id} -> {path}")
        return

    eligible = exportable_alert_ids(store)
    for aid in eligible:
        # The product: the list of what was exported, on stdout, pipeable.
        print(f"Exported {aid} -> {export_case(store, aid)}")
    known = {r["alert_id"] for r in store._iter_records()}
    blocked = [
        aid for aid in store.dispositions()
        if aid in known and aid not in eligible
    ]
    for aid in blocked:
        log.info(
            "Skipped %s: ruled, but the record predates full-record "
            "storage — re-investigate to make it exportable.", aid,
        )
    if not eligible and not blocked:
        log.info(
            "Nothing to export: no analyst-ruled investigations on "
            "record. Sync feedback after analysts work the queue."
        )


async def _run_digest(args: argparse.Namespace) -> None:
    """Print the SOC briefing for the reporting window (default 24h).

    A quiet window is answered deterministically — no API call is spent
    narrating an empty day.
    """
    from .config import settings
    from .digest import build_digest_data, render_quiet, write_briefing
    from .history import AlertHistoryStore

    store = AlertHistoryStore(settings.HISTORY_PATH)
    data = build_digest_data(store, since_hours=args.hours)
    if data["quiet"]:
        print(render_quiet(data))
        return
    # Only the narrated path spends the API — require the key here, not
    # up front, so a quiet digest still costs nothing (and needs no key).
    settings.require("ANTHROPIC_KEY")
    print(await write_briefing(data))


async def _run_ask(args: argparse.Namespace) -> None:
    """Follow-up mode: interrogate a recorded investigation.

    With a question argument, answers once and exits (scriptable).
    Without one, holds an interactive session — later questions ride on
    the same conversation, so "and why high confidence?" works.
    """
    from .config import settings
    from .followup import FollowUpSession
    from .history import AlertHistoryStore

    settings.require("ANTHROPIC_KEY")  # every answer is an LLM call
    alert_id = args.alert_id
    store = AlertHistoryStore(settings.HISTORY_PATH)
    try:
        session = FollowUpSession(alert_id, history_store=store)
    except KeyError:
        known = list(dict.fromkeys(r["alert_id"] for r in store._iter_records()))
        log.error("No investigation on record for %r.", alert_id)
        if known:
            log.info(
                "Investigated alerts (oldest first):\n%s",
                "\n".join(f"  {aid}" for aid in known),
            )
        sys.exit(1)

    question = args.question
    if question:
        print(await session.ask(question))
        return

    log.info(
        "Follow-up session on %s — answers come from the stored "
        "record only. Empty line or Ctrl+D to exit.", alert_id,
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
                log.info(
                    "  -> stamped onto %d investigation doc(s) in Elastic", n
                )
        except Exception as e:
            log.warning("  -> Elastic annotation failed: %s", e)


def _print_rulings(changed: list[dict], known: set[str]) -> None:
    for d in changed:
        marker = (
            "" if d["alert_id"] in known
            else " (no local investigation on record)"
        )
        note = f' — "{d["summary"]}"' if d.get("summary") else ""
        log.info(
            "%s: analyst ruled %s [%s]%s%s",
            d["alert_id"], d["human_verdict"], d["source"], note, marker,
        )


_REJECT_EXPLAIN = {
    # A different TheHive object reused an alert id we cased: a probable
    # spoof, and the one rejection that is genuinely alarming.
    "thehive-id-mismatch": "a different TheHive object reused an alert id "
                           "this copilot created — probable spoof",
    # No local record we ever worked this alert: forged, from another feed,
    # or (benignly) handled before provenance tracking existed. Reported,
    # but not asserted to be an attack.
    "no-local-record": "no record this copilot investigated or created this "
                       "alert (forged, foreign, or predates provenance "
                       "tracking)",
}


def _print_rejected_rulings(rejected: list[dict]) -> None:
    """A rejected ruling did not enter memory: its alert has no provenance
    tying it to this copilot, so trusting it would let a self-asserted
    'soc-copilot' TheHive alert poison the accuracy record and the
    precedent-aware closure signal. A thehive-id-mismatch is the alarming
    kind (a spoof of an alert we cased); a no-local-record is reported but
    not accused — on an upgrade with an empty ledger it is simply the
    operator's own pre-provenance history, and re-casing those alerts (or a
    fresh deployment) resolves it."""
    spoof = [r for r in rejected if r["reason"] == "thehive-id-mismatch"]
    lead = "⚠ " if spoof else ""
    log.warning(
        "%s%d ruling(s) not applied (no provenance linking the alert to "
        "this copilot):", lead, len(rejected),
    )
    for r in rejected:
        why = _REJECT_EXPLAIN.get(r["reason"], r["reason"])
        log.warning(
            "  %s: %s (thehive id %s)", r["alert_id"], why, r.get("thehive_id")
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
        changed, total, rejected = await sync_dispositions(TheHiveClient(), store)
    except RuntimeError as e:
        log.error("%s", e)
        sys.exit(1)
    if rejected:
        _print_rejected_rulings(rejected)
    if total == 0:
        log.info("No analyst rulings found for alerts this copilot created.")
        return
    _print_rulings(changed, known)
    await _annotate_elastic(changed)
    log.info(
        "%d new/changed ruling(s), %d already known (%s)",
        len(changed), total - len(changed), store.dispositions_path,
    )


async def _maybe_open_case(
    alert: Alert, investigation: Investigation, case: bool, store=None
) -> str | None:
    """Open a TheHive alert when --case is set and the policy says a human
    should own this. Returns the created TheHive alert id (so a caller can
    link to it), or None. Never fatal: case management is an output
    channel, so a TheHive outage must not lose an investigation that
    already succeeded.

    When `store` is given, the created alert is recorded to the provenance
    ledger — the gate that lets --sync-feedback later trust a ruling for
    this alert. Skipping that recording would make the ruling un-trustable,
    so the ledger write matters as much as the POST.
    """
    if not case:
        return None
    from .casemgmt import TheHiveClient, should_open_case

    open_case, reason = should_open_case(investigation)
    if not open_case:
        log.info("No case opened (%s)", reason)
        return None
    try:
        case_id = await TheHiveClient().create_alert(alert, investigation)
    except RuntimeError as e:
        log.warning("Case creation failed: %s", e)
        return None
    log.info("Opened TheHive alert %s (%s)", case_id, reason)
    if store is not None:
        # The provenance write is what lets a future ruling on this alert
        # be trusted, so it matters — but a disk error here must not undo a
        # case that already succeeded (the "never fatal" contract), so its
        # own failure is caught. A dropped ledger line degrades to that
        # alert's later ruling reporting as no-local-record, not a crash.
        try:
            store.record_created_alert(alert.alert_id, case_id)
        except OSError as e:
            log.warning(
                "Opened alert %s but failed to record its provenance (%s); "
                "a later ruling on %s may not sync.",
                case_id, e, alert.alert_id,
            )
    return case_id


async def _maybe_notify(
    alert: Alert,
    investigation: Investigation,
    notify: bool,
    thehive_alert_id: str | None = None,
) -> None:
    """Page a webhook when --notify is set and the investigation is an
    escalation or campaign. Never fatal: a webhook outage must not lose an
    investigation. Fires only for page-worthy findings — routine
    acknowledgements stay silent so the channel doesn't become noise.
    """
    if not notify:
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
        log.info("Notified webhook (%s)", reason)
    except RuntimeError as e:
        log.warning("Webhook notification failed: %s", e)


def positive_int(what: str):
    """An argparse `type` that accepts only positive integers, rejecting
    anything else loudly. A numeric token is always the user's intended
    value — argparse treats a lone `-1` as a value here (no option looks
    like a negative number), so `--digest -1` is rejected, never silently
    defaulted."""

    def _parse(raw: str) -> int:
        try:
            value = int(raw)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"{what} must be a positive integer, got {raw!r}"
            )
        if value <= 0:
            raise argparse.ArgumentTypeError(
                f"{what} must be a positive integer, got {value}"
            )
        return value

    return _parse


# Command token -> (canonical name, parser-builder). The token keeps the
# historical `--command` shape so every documented invocation still works;
# each command gets its OWN argparse parser, so an unknown or misspelled
# flag (a typo'd --auto-close in a systemd unit) is now REJECTED with a
# clear error instead of silently ignored — the whole point of this
# change, since a swallowed flag silently changes autonomous behavior.
def _p(prog: str) -> argparse.ArgumentParser:
    # allow_abbrev=False is load-bearing: with argparse's default (True) a
    # truncated flag like `--au` is silently accepted as `--auto-close`,
    # which would re-open the exact silent-autonomous-behavior hole this
    # change exists to close. Only exact flag names are accepted.
    return argparse.ArgumentParser(
        prog=f"soc-copilot {prog}", add_help=True, allow_abbrev=False
    )


def _parse_args(argv: list[str]) -> tuple[str, argparse.Namespace]:
    """Pick the command from argv[0] and parse the rest with that
    command's parser. Returns (command, namespace). Exits (argparse's
    own code 2) on an unknown command or flag, or a bad value."""
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE)
        sys.exit(0 if argv else 1)

    cmd, rest = argv[0], argv[1:]

    if not cmd.startswith("-"):
        # Default command: investigate a local alert file.
        p = _p("<alert.json>")
        p.add_argument("file")
        p.add_argument("--agentic", action="store_true")
        p.add_argument("--tiered", action="store_true")
        p.add_argument(
            "--report", nargs="?", const="investigation_report.html",
            default=None, metavar="OUT.html",
        )
        p.add_argument(
            "--debug", nargs="?", const="last_run_debug.json",
            default=None, metavar="OUT.json",
            help="also dump the full alert/evidence/investigation JSON",
        )
        p.add_argument("--case", action="store_true")
        return "file", p.parse_args(argv)

    if cmd == "--from-elastic":
        p = _p("--from-elastic")
        p.add_argument("limit", nargs="?", type=positive_int("alert limit"),
                       default=3)
        p.add_argument("--agentic", action="store_true")
        p.add_argument("--tiered", action="store_true")
        p.add_argument("--push", action="store_true")
        p.add_argument("--report", action="store_true")
        p.add_argument("--case", action="store_true")
        return "from-elastic", p.parse_args(rest)

    if cmd == "--watch":
        p = _p("--watch")
        p.add_argument("interval", nargs="?",
                       type=positive_int("poll interval seconds"), default=60)
        p.add_argument("--agentic", action="store_true")
        p.add_argument("--tiered", action="store_true")
        p.add_argument("--auto-close", action="store_true")
        p.add_argument("--case", action="store_true")
        p.add_argument("--notify", action="store_true")
        p.add_argument(
            "--dedup", nargs="?", const=DEDUP_WINDOW_HOURS,
            type=positive_int("dedup window hours"), default=None,
            metavar="WINDOW_H",
            help="suppress near-duplicate repeats of recent high-confidence "
                 "false positives instead of re-investigating them",
        )
        return "watch", p.parse_args(rest)

    if cmd == "--ask":
        # The question is free text and can legitimately begin with a dash
        # ("--why did you escalate?"), so it must NOT pass through
        # argparse's option detection — parse it verbatim, exactly as the
        # old sys.argv[2]/[3] handling did.
        if not rest:
            print(f"--ask requires an ALERT_ID.\n\n{USAGE}", file=sys.stderr)
            sys.exit(2)
        return "ask", argparse.Namespace(
            alert_id=rest[0],
            question=rest[1] if len(rest) > 1 else None,
        )

    if cmd == "--digest":
        p = _p("--digest")
        p.add_argument("hours", nargs="?", type=positive_int("window hours"),
                       default=24)
        return "digest", p.parse_args(rest)

    if cmd == "--export-case":
        p = _p("--export-case")
        p.add_argument("alert_id", nargs="?", default=None)
        return "export-case", p.parse_args(rest)

    if cmd in ("--sync-feedback", "--scorecard"):
        _p(cmd).parse_args(rest)  # accepts nothing; rejects stray args
        return cmd.lstrip("-"), argparse.Namespace()

    # A leading-dash token that is not a known command: don't silently
    # treat it as a filename — say so and exit.
    print(f"Unknown command '{cmd}'.\n\n{USAGE}", file=sys.stderr)
    sys.exit(2)


def _telemetry_line(inv: Investigation) -> str:
    """One-line cost/latency summary, or '' when nothing was recorded."""
    tel = inv.telemetry
    if not tel:
        return ""
    from .pricing import is_priced

    cost = f"${tel.cost_usd:.4f}" if is_priced(tel.model) else "cost unpriced"
    tools = f" tools={tel.tool_calls}" if tel.tool_calls else ""
    retries = f" retries={tel.retries}" if tel.retries else ""
    routing = f"\n  routing: {tel.routing}" if tel.routing else ""
    return (
        f"[{cost} · {tel.duration_seconds:.1f}s · "
        f"{tel.input_tokens}in/{tel.output_tokens}out · "
        f"{tel.api_calls} call(s){tools}{retries}]{routing}"
    )


def _require_investigation_keys() -> None:
    """Every real investigation calls the model and the enrichment tools;
    demand those keys up front so a keyless run fails fast and legibly
    (the library itself stays lazy — see soc_copilot/config.py)."""
    from .config import settings

    settings.require(
        "ANTHROPIC_KEY", "ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "URLSCAN_KEY"
    )


async def _investigate(
    copilot: SOCCopilot, alert: Alert, agentic: bool, tiered: bool = False
) -> Investigation:
    mode = "agentic — model decides tool calls" if agentic else (
        "phase one — fixed enrichment pipeline"
    )
    if tiered:
        log.info("[mode: %s; tiered — cheap first pass, promote if in doubt]",
                 mode)
        inv = await copilot.investigate_tiered(alert, agentic=agentic)
    else:
        log.info("[mode: %s]", mode)
        inv = (
            await copilot.investigate_agentic(alert)
            if agentic
            else await copilot.investigate(alert)
        )
    line = _telemetry_line(inv)
    if line:
        log.info("%s", line)
    return inv


def _write_report(alert: Alert, inv: Investigation, out: Path) -> None:
    from .report import render_report

    out.write_text(render_report(alert, inv))
    log.info("HTML report written to %s", out)


async def _run_file(args: argparse.Namespace) -> None:
    _require_investigation_keys()
    alert_path = Path(args.file)
    with alert_path.open() as f:
        alert = Alert(**json.load(f))

    copilot = SOCCopilot()
    with alert_context(alert.alert_id):
        investigation = await _investigate(
            copilot, alert, args.agentic, getattr(args, "tiered", False)
        )

        # Opt-in: a tool should not drop files into the operator's working
        # directory unasked. The investigation JSON still prints to stdout
        # below, so nothing is lost by default.
        if args.debug:
            debug_path = Path(args.debug)
            with debug_path.open("w") as f:
                json.dump(
                    {
                        "mode": "agentic" if args.agentic else "phase_one",
                        "alert": alert.model_dump(mode="json"),
                        "evidence_raw": [
                            e.model_dump(mode="json")
                            for e in investigation.evidence
                        ],
                        "investigation": investigation.model_dump(mode="json"),
                    },
                    f,
                    indent=2,
                    default=str,
                )
            log.info("Full debug written to %s", debug_path)

        if args.report:
            _write_report(alert, investigation, Path(args.report))

        await _maybe_open_case(alert, investigation, args.case, copilot.history)

    # The deliverable: stdout, print — `soc-copilot alert.json | jq` works
    # because every narrated line above went to stderr.
    print(investigation.model_dump_json(indent=2))


async def _run_elastic(args: argparse.Namespace) -> None:
    from .elastic import ElasticAlertSource

    _require_investigation_keys()
    limit = args.limit
    try:
        source = ElasticAlertSource()
    except RuntimeError as e:
        log.error("%s", e)
        sys.exit(1)
    log.info("Fetching up to %d open detection alerts from Elastic...", limit)
    alerts = await source.fetch_alerts(limit=limit)
    if not alerts:
        log.info("No open alerts found.")
        return

    copilot = SOCCopilot()
    for alert in alerts:
        with alert_context(alert.alert_id):
            log.info("\n=== %s — %s ===", alert.alert_id, alert.title)
            investigation = await _investigate(
                copilot, alert, args.agentic, getattr(args, "tiered", False)
            )

            campaign = bool(
                investigation.correlation
                and investigation.correlation.is_campaign
            )
            log.info(
                "verdict=%s confidence=%s escalate=%s campaign=%s "
                "injection_flags=%d",
                investigation.verdict, investigation.confidence,
                investigation.escalation_recommended, campaign,
                len(investigation.injection_flags),
            )

            if args.report:
                reports_dir = Path("reports")
                reports_dir.mkdir(exist_ok=True)
                _write_report(
                    alert, investigation,
                    reports_dir / f"{alert.alert_id}.html",
                )

            if args.push:
                doc_id = await source.push_investigation(alert, investigation)
                log.info("Pushed investigation to Elastic (doc id: %s)", doc_id)

            await _maybe_open_case(
                alert, investigation, args.case, copilot.history
            )


def _prioritize(
    copilot: SOCCopilot, fresh: list[tuple[str, Alert]]
) -> list[tuple[str, Alert, str]]:
    """Order this cycle's fresh alerts the way a human lead would — a
    coordinated campaign and recurring true positives ahead of raw
    severity — using only deterministic pre-LLM signals (severity, prior
    sightings, a correlation pass). Returns (doc_id, alert, reason),
    highest priority first; ties keep Elastic's recency order.

    The signals are recomputed from the store here, cheaply and without
    the API, so a backlog is triaged before any model call is spent —
    the investigation recomputes the same memory internally, which is a
    small duplicate read the summary-index roadmap item will remove.
    """
    from .config import settings
    from .triage import priority_score

    scored = []
    for doc_id, alert in fresh:
        priors = copilot.history.prior_sightings(alert)
        correlation = copilot.history.correlate(
            alert, window_hours=settings.CORRELATION_WINDOW_HOURS
        )
        score, why = priority_score(alert, priors, correlation)
        scored.append((score, doc_id, alert, why))
    scored.sort(key=lambda t: t[0], reverse=True)  # stable: ties keep order
    return [(doc_id, alert, why) for _, doc_id, alert, why in scored]


async def _work_alert(
    copilot: SOCCopilot,
    source,
    doc_id: str,
    alert: Alert,
    seen: set[str],
    *,
    agentic: bool,
    tiered: bool,
    auto_close: bool,
    notify: bool,
    case: bool,
    dedup_window: int | None,
) -> bool:
    """Work ONE alert from the watch queue: investigate (or borrow a
    dedup-suppressed conclusion), push the result, set the alert's
    status, and offer the outcome to the case/notify policies. Raises on
    failure — the cycle catches and retries the alert next poll.

    The ORDER of effects is the contract this seam exists to pin, and the
    tests in tests/test_watch.py hold it:

    1. push_investigation  — the result lands in Elastic first
    2. set_alert_status    — closed (auto-close) or acknowledged
    3. record_closure      — LAST, only after both Elastic writes, so the
       local log asserts what HAPPENED, not what was about to happen. A
       push failure leaves no phantom closure (review catch from the
       scorecard increment); a crash between the status write and the
       record undercounts automation instead — the safe direction.
    4. seen.add            — only a fully-recorded alert is marked done
    5. case/notify         — never for an auto-closed alert (it needs no
       human owner, so it must generate no case noise and no page)
    """
    from .closure import should_auto_close

    suppressed_reason = None
    if dedup_window:
        from .dedup import try_suppress

        result = try_suppress(copilot.history, alert, dedup_window)
        if result:
            investigation, suppressed_reason = result
            log.info("[dedup: %s — no model call spent]", suppressed_reason)
    if suppressed_reason is None:
        investigation = await _investigate(copilot, alert, agentic, tiered)
    close, reason = (
        should_auto_close(investigation) if auto_close else (False, None)
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
    if close:
        copilot.history.record_closure(alert.alert_id, reason)
    seen.add(doc_id)
    if not close:
        case_id = await _maybe_open_case(
            alert, investigation, case, copilot.history
        )
        await _maybe_notify(alert, investigation, notify, case_id)
    disposition = (
        f"alert CLOSED autonomously ({reason})"
        if close
        else "alert acknowledged"
    )
    log.info(
        "verdict=%s confidence=%s escalate=%s -> pushed %s, %s",
        investigation.verdict, investigation.confidence,
        investigation.escalation_recommended, result_id, disposition,
    )
    # Whether this completion was a dedup-borrowed conclusion (no model
    # call) — the watchdog must not count those as proof the
    # investigation pipeline is alive.
    return suppressed_reason is not None


async def _watch_once(
    copilot: SOCCopilot,
    source,
    seen: set[str],
    *,
    agentic: bool,
    tiered: bool,
    auto_close: bool,
    notify: bool,
    case: bool,
    dedup_window: int | None,
) -> CycleReport:
    """One poll cycle: fetch open alerts, work the fresh ones in priority
    order. A single alert's failure is contained to that alert — logged,
    left un-acknowledged (and out of `seen`), and so retried next cycle
    — never allowed to kill the cycle or the alerts queued behind it.
    Raises only when the FETCH itself fails; the loop shell logs that as
    a failed cycle and retries after the interval.

    Returns a CycleReport of what was accomplished — the watchdog's
    input. Counting here rather than in the shell keeps the judgment
    testable: the per-alert catch below is exactly the spot that
    swallows an every-alert failure (expired API key) so quietly that
    only these counts can surface it.
    """
    report = CycleReport()
    hits = await source.fetch_alert_hits(limit=10, status="open")
    fresh = [(d, a) for d, a in hits if d not in seen]
    for doc_id, alert, why in _prioritize(copilot, fresh):
        # The correlation id: every line logged while THIS alert is being
        # worked — the mode line, tool chatter, the failure — carries its
        # id in JSON mode, so one alert's story greps out of the night.
        with alert_context(alert.alert_id):
            log.info(
                "\n=== %s — %s [priority: %s] ===",
                alert.alert_id, alert.title, why,
            )
            try:
                borrowed = await _work_alert(
                    copilot, source, doc_id, alert, seen,
                    agentic=agentic, tiered=tiered, auto_close=auto_close,
                    notify=notify, case=case, dedup_window=dedup_window,
                )
                if borrowed:
                    report.borrowed += 1
                else:
                    report.worked += 1
            except Exception as e:
                report.failed += 1
                report.failed_ids.add(alert.alert_id)
                log.error("FAILED (will retry next cycle): %s", e)
    return report


async def _page_watch_health(text: str) -> None:
    """Best-effort page about the copilot's OWN health.

    Uses the webhook channel whenever WEBHOOK_URL is configured — even
    without --notify. That flag gates per-alert noise; this is the desk
    reporting itself down, which is the one message the channel exists
    for. No URL, or a failed POST (the webhook may share the outage),
    degrades to a loud line: never fatal, and never silent.
    """
    from .config import settings
    from .notify import WebhookClient

    if not settings.WEBHOOK_URL:
        log.warning("HEALTH: %s (no WEBHOOK_URL configured; cannot page)",
                    text)
        return
    try:
        # Top-level `text` is the channel's contract (see notify.py): it is
        # what Slack/Mattermost/generic hooks render, and they 400-reject a
        # payload without it — which would have turned this page into the
        # exact silent failure it exists to announce (review catch). The
        # structured fields ride beside it for programmatic consumers.
        await WebhookClient().post({
            "text": f"🤒 {text}",
            "kind": "copilot-health",
            "summary": text,
        })
        log.warning("HEALTH: paged webhook — %s", text)
    except Exception as e:
        # Broad on purpose: this is the best-effort path of last resort,
        # and anything escaping here would kill the loop at the exact
        # moment it first tried to report sickness — httpx.InvalidURL from
        # a typo'd WEBHOOK_URL is not an httpx.HTTPError, so the narrower
        # RuntimeError-only catch did exactly that (review catch).
        log.error("HEALTH: could not page webhook (%s) — %s", e, text)


async def _act_on_watch_health(
    action: str | None,
    sick_cycles: int,
    *,
    systemic: bool = True,
    stuck_ids: frozenset[str] = frozenset(),
) -> None:
    """Carry out the watchdog's verdict. Split from the loop shell so the
    page-once and exit-nonzero behaviors are pinned by tests rather than
    read off an infinite loop.

    The page must tell the truth about what happens next, and that
    depends on which kind of sick the desk is: a systemic streak really
    is counting down to an exit, but a confined streak (one poisoned
    alert) pages and then HOLDS — observe() never returns "exit" for it —
    so promising "will exit for a supervisor restart" there asserts a
    restart that never comes to the one person acting on the page
    (review catch)."""
    if action == "page":
        if systemic:
            await _page_watch_health(
                f"soc-copilot watch loop is unhealthy: {sick_cycles} "
                f"consecutive cycles completed no work. Still retrying; "
                f"will exit for a supervisor restart if this persists."
            )
        else:
            ids = ", ".join(sorted(stuck_ids)) or "one alert"
            await _page_watch_health(
                f"soc-copilot watch loop is stuck: {sick_cycles} "
                f"consecutive cycles completed no work, all failing on "
                f"{ids}. The process stays up and keeps retrying — ack or "
                f"fix that alert in Elastic. It escalates to an exit only "
                f"if more alerts start failing."
            )
    elif action == "exit":
        await _page_watch_health(
            f"soc-copilot watch loop is exiting after {sick_cycles} "
            f"consecutive failed cycles so a supervisor can restart it."
        )
        log.error(
            "Watch loop exiting: %d consecutive cycles completed no work. "
            "A supervisor (systemd/docker) should restart the process; "
            "without one, restart it manually.", sick_cycles,
        )
        raise SystemExit(2)


async def _run_watch_cycle(
    copilot: SOCCopilot,
    source,
    seen: set[str],
    watchdog: Watchdog,
    args: argparse.Namespace,
) -> None:
    """One SUPERVISED cycle: work the queue, report to the watchdog, act.

    This is the seam that keeps the health wiring testable — the crash
    path (a failed fetch becomes a crashed CycleReport, never a healthy
    one) and the observe→act handoff both live here, not in the infinite
    loop (review catch: as shell code, a mutant discarding the action
    survived every test).
    """
    try:
        report = await _watch_once(
            copilot, source, seen,
            agentic=args.agentic, tiered=args.tiered,
            auto_close=args.auto_close, notify=args.notify,
            case=args.case, dedup_window=args.dedup,
        )
    except Exception as e:
        report = CycleReport(crashed=True)
        log.error("Poll cycle failed (retrying in %ds): %s", args.interval, e)
    prev_sick = watchdog.consecutive_sick
    action = watchdog.observe(report)
    _log_watch_health(watchdog, action, prev_sick)
    await _act_on_watch_health(
        action, watchdog.consecutive_sick,
        systemic=watchdog.systemic, stuck_ids=watchdog.streak_failed_ids,
    )


def _log_watch_health(
    watchdog: Watchdog, action: str | None, prev_sick: int
) -> None:
    """The heartbeat between the thresholds. The page (at 3) and the
    exit (at 30) each announce themselves, but the 26 cycles between
    them used to pass in silence — an operator reading the log during an
    outage had per-cycle FAILED lines and no way to know how deep into
    the countdown the desk was, or whether the streak even COULD end in
    an exit. Every sick cycle that takes no action now says where the
    streak stands and which kind of sick it is (systemic — counting
    down to a supervisor restart — or one poisoned alert that pages and
    holds forever). Recovery is announced at the same WARNING level the
    sickness was, so a level-filtered view that saw the outage start
    also sees it end."""
    if prev_sick and not watchdog.consecutive_sick:
        log.warning(
            "HEALTH: recovered — work is completing again after %d sick "
            "cycle(s).", prev_sick,
        )
        return
    if action is not None or not watchdog.consecutive_sick:
        return  # page/exit speak for themselves; healthy needs no pulse
    if watchdog.systemic:
        scope = (
            f"systemic — exits for a supervisor restart at "
            f"{watchdog.exit_after}"
        )
    else:
        ids = ", ".join(sorted(watchdog.streak_failed_ids))
        scope = (
            f"confined to {ids} — pages then holds; a lone failing alert "
            f"never exits the desk (ack or fix it in Elastic)"
        )
    # After the threshold, the page already fired (or was attempted and
    # said so at ERROR) — phrasing it as still ahead would misreport the
    # outage's own timeline (review catch).
    page_word = (
        "paged at" if watchdog.consecutive_sick >= watchdog.page_after
        else "pages at"
    )
    log.warning(
        "HEALTH: sick streak at %d consecutive cycle(s), %s %d (%s).",
        watchdog.consecutive_sick, page_word, watchdog.page_after, scope,
    )


async def _run_watch(args: argparse.Namespace) -> None:
    """Continuous mode: the copilot works the open-alert queue by itself.

    Each cycle: fetch open alerts, order them by deterministic priority
    (soc_copilot/triage.py — campaign and recurring-true-positive signals ahead
    of raw severity, so a backlog is worked the way a human lead would),
    investigate each, push the result, acknowledge the alert in Elastic
    (which removes it from the next poll — acknowledgement IS the dedupe;
    the per-session seen-set is a second guard for the window where a
    status write hasn't taken effect). A failed alert is logged and
    retried on a later cycle rather than killing the loop.

    With --auto-close, investigations that pass the deterministic closure
    policy (soc_copilot/closure.py: high-confidence false positive, no
    escalation/injection/campaign signals) close the alert autonomously,
    with the policy reason recorded in the results index. Everything else
    is acknowledged for a human, exactly as without the flag.

    When TheHive is configured, analyst rulings are synced back every
    FEEDBACK_SYNC_INTERVAL seconds — the copilot keeps learning from the
    humans working its cases without an operator remembering to run
    --sync-feedback. A sync failure is logged and retried next time,
    never fatal.

    The loop also watches ITSELF: every cycle reports what it
    accomplished to a Watchdog (soc_copilot/watchdog.py), and a desk
    that stops completing work — the fetch failing outright, or every
    attempted alert failing the way an expired API key makes them —
    pages the webhook once per outage and, if the outage persists, exits
    non-zero so a supervisor can restart it. Before this, that state was
    an endless per-cycle FAILED line printed to nobody.

    This shell owns only what cannot run under a test: real construction,
    the infinite loop, the sleep, and the feedback-sync timer. Everything
    the loop DOES is _watch_once/_work_alert — the seam
    tests/test_watch.py pins, so the ordering contract above is held by
    tests rather than by careful reading — and everything the watchdog
    DECIDES and the health actions DO is pinned the same way
    (tests/test_watchdog.py).
    """
    import time

    from .config import settings
    from .elastic import ElasticAlertSource

    _require_investigation_keys()
    interval = args.interval
    try:
        source = ElasticAlertSource()
    except RuntimeError as e:
        log.error("%s", e)
        sys.exit(1)

    if args.notify and not settings.WEBHOOK_URL:
        # Fail loudly at startup rather than silently never paging.
        log.error("--notify requires WEBHOOK_URL in your .env")
        sys.exit(1)
    if settings.WEBHOOK_URL:
        # The health watchdog pages this URL even without --notify, so a
        # malformed value must fail HERE, not at 03:00 when the first page
        # fires and httpx.InvalidURL is all the operator gets (review
        # catch: startup previously checked truthiness only).
        import httpx

        try:
            httpx.URL(settings.WEBHOOK_URL)
        except httpx.InvalidURL as e:
            log.error("WEBHOOK_URL is not a usable URL (%s): %r",
                      e, settings.WEBHOOK_URL)
            sys.exit(1)
    copilot = SOCCopilot()
    seen: set[str] = set()
    watchdog = Watchdog()
    mode = "agentic" if args.agentic else "phase one"
    feedback = bool(settings.THEHIVE_URL and settings.THEHIVE_API_KEY)
    last_feedback_sync = float("-inf")
    # When watch runs under nohup/systemd its output is the operator's
    # only heartbeat; the logging handler flushes per record, so nothing
    # here needs flush=True anymore.
    log.info(
        "Watching %s every %ds (%s mode%s%s%s%s%s). Ctrl+C to stop.",
        source.alerts_index, interval, mode,
        ", tiered on" if args.tiered else "",
        ", auto-close on" if args.auto_close else "",
        ", notifications on" if args.notify else "",
        f", dedup on ({args.dedup}h window)" if args.dedup else "",
        ", analyst-feedback sync on" if feedback else "",
    )
    while True:
        if feedback and time.monotonic() - last_feedback_sync >= FEEDBACK_SYNC_INTERVAL:
            last_feedback_sync = time.monotonic()
            try:
                from .casemgmt import TheHiveClient, sync_dispositions

                changed, _, rejected = await sync_dispositions(
                    TheHiveClient(), copilot.history
                )
                if rejected:
                    _print_rejected_rulings(rejected)
                if changed:
                    log.info("Analyst feedback synced from TheHive:")
                    known = {
                        r["alert_id"]
                        for r in copilot.history._iter_records()
                    }
                    _print_rulings(changed, known)
                    await _annotate_elastic(changed)
            except Exception as e:
                log.warning("Feedback sync failed (will retry): %s", e)
        await _run_watch_cycle(copilot, source, seen, watchdog, args)
        await asyncio.sleep(interval)


async def _dispatch(command: str, args: argparse.Namespace) -> None:
    if command == "sync-feedback":
        await _run_sync_feedback()
    elif command == "scorecard":
        await _run_scorecard()
    elif command == "ask":
        await _run_ask(args)
    elif command == "digest":
        await _run_digest(args)
    elif command == "export-case":
        await _run_export_case(args)
    elif command == "from-elastic":
        await _run_elastic(args)
    elif command == "watch":
        await _run_watch(args)
    else:
        await _run_file(args)


def cli() -> None:
    """Console entry point (`soc-copilot`), also used by `python -m`."""
    # Parse synchronously (argparse exits with code 2 on a bad flag/value,
    # which is the whole safety point) before entering the event loop.
    command, args = _parse_args(sys.argv[1:])
    configured = False
    try:
        from .config import settings

        # The one place logging is configured — before any dispatch, so
        # every narrated line of every command speaks through it.
        configure_logging(settings.LOG_FORMAT, settings.LOG_LEVEL)
        configured = True
        asyncio.run(_dispatch(command, args))
    except KeyboardInterrupt:
        # Must live OUTSIDE asyncio.run: on Python 3.12 a SIGINT reaches
        # the coroutine as CancelledError and KeyboardInterrupt is raised
        # only at the run() boundary, so a handler inside _dispatch was
        # dead code and Ctrl+C died with a traceback (review catch).
        # stderr like all narration — a piped stdout product stays clean.
        print("\nStopped.", file=sys.stderr)
        sys.exit(130)
    except RuntimeError as e:
        # A missing-key (or other configuration) error should read as one
        # clear line, not a stack trace — the message already names the
        # exact environment variable to set. Spoken through the logger
        # when it exists (so JSON mode stays JSON to the last line), and
        # through bare stderr when the logging config ITSELF was the
        # broken thing.
        if configured:
            log.error("Configuration error: %s", e)
        else:
            print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    cli()

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

    # Age old records out of the history store into a timestamped
    # archive (retention, not performance). Nothing is deleted, and the
    # two files that are SAFETY inputs — analyst rulings and the TheHive
    # provenance ledger — are held back unless asked for explicitly.
    uv run soc-copilot --rotate-history [DAYS] [--dry-run] [--include-human-records]
"""
import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path

from .copilot import SOCCopilot
from .dedup import DEFAULT_WINDOW_HOURS as DEDUP_WINDOW_HOURS
from .logsetup import alert_context, configure_logging
from .models import Alert, Investigation
from .rotate import DEFAULT_RETENTION_DAYS as ROTATE_RETENTION_DAYS
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
    "  soc-copilot --export-case [ALERT_ID]\n"
    "  soc-copilot --rotate-history [DAYS] [--dry-run] [--include-human-records]"
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


async def _run_rotate_history(args: argparse.Namespace) -> None:
    """Age old records out of the history store into a timestamped archive.

    Retention, not performance — see soc_copilot/rotate.py. The report is
    the PRODUCT (stdout, pipeable); the warnings around it are narration.
    Nothing is deleted: rotation splits each file and moves the old part.
    """
    from .config import settings
    from .history import AlertHistoryStore
    from .rotate import (
        ConcurrentWriteError,
        apply_rotation,
        plan_rotation,
    )

    store = AlertHistoryStore(settings.HISTORY_PATH)
    plan = plan_rotation(
        store, args.days,
        include_human_records=args.include_human_records,
    )

    print(f"Retention: {args.days} days (records before "
          f"{plan.cutoff.isoformat()} are archived)")
    if not plan.files:
        print("Nothing to rotate: no record is older than the cutoff.")
        _warn_held_back(plan)
        return

    for fp in plan.files:
        notes = []
        if fp.pinned:
            notes.append(f"{fp.pinned} pinned by an analyst ruling")
        if fp.unclassifiable:
            notes.append(f"{fp.unclassifiable} unclassifiable")
        print(f"  {fp.name}: {len(fp.archived)} archived, "
              f"{len(fp.retained)} retained"
              + (f" ({', '.join(notes)}, all kept)" if notes else ""))
    _warn_held_back(plan)

    if args.dry_run:
        print(f"\nDry run — nothing was changed. Archive would be written "
              f"to {plan.archive_dir}")
        return

    log.warning(
        "Rotating with the watch loop RUNNING would lose records written "
        "between the read and the replace. That race is detected and "
        "aborted, but detection is not avoidance — stop the service first."
    )
    try:
        archive = apply_rotation(plan)
    except ConcurrentWriteError as e:
        log.error("%s", e)
        sys.exit(1)
    except OSError as e:
        # Deliberately does NOT claim the live files are untouched. The
        # replaces run in sequence, so a failure on the second of three
        # leaves the first already rotated — and an earlier version of
        # this message told the operator otherwise, which would have
        # steered them to delete the archive holding the only surviving
        # copy of those records (review catch).
        log.error(
            "Rotation failed partway (%s). Some live files may ALREADY be "
            "rotated and others not. Do not delete %s — it holds the only "
            "copy of anything that was archived. Compare each live file "
            "against its archived counterpart before re-running.",
            e, plan.archive_dir,
        )
        sys.exit(1)
    print(f"\nArchived {plan.archived_total} record(s) to {archive}")


def _warn_held_back(plan) -> None:
    """Name what was deliberately NOT rotated, and what rotating it would
    cost. Silence here would let an operator believe a retention policy
    had been applied to files this command left alone."""
    for note in plan.held_back:
        log.warning(
            "HELD BACK (pass --include-human-records to rotate it too) — %s",
            note,
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


async def _annotate_elastic(
    changed: list[dict], stop: asyncio.Event | None = None
) -> None:
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
        if stop is not None and stop.is_set():
            # A stop landing mid-sync must not chain another ruling's
            # 20s-plus-retry write: with enough rulings this loop alone
            # could outlast the supervisor's grace and turn a drain into
            # a SIGKILL (review catch). The rulings are already safe in
            # the history store; the stamp is retried next start.
            log.warning(
                "Draining for shutdown: %d Elastic annotation(s) "
                "deferred to the next start.",
                len(changed) - changed.index(d),
            )
            return
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

    if cmd == "--rotate-history":
        p = _p("--rotate-history")
        p.add_argument(
            "days", nargs="?", type=positive_int("retention days"),
            default=ROTATE_RETENTION_DAYS,
            help="archive records older than this many days",
        )
        p.add_argument(
            "--dry-run", action="store_true",
            help="report what would move, change nothing",
        )
        p.add_argument(
            "--include-human-records", action="store_true",
            help="ALSO rotate analyst rulings and the TheHive provenance "
                 "ledger; both are safety inputs and are held back by "
                 "default (the command explains what each one costs)",
        )
        return "rotate-history", p.parse_args(rest)

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


async def _already_indexed(source, alert_id: str, since) -> bool:
    """Did the interrupted run's own push land? Any failure to ask
    answers "no".

    Every gate in soc_copilot/resume.py fails toward a fresh
    investigation; this one lives outside that function and used to be
    the exception — an unreachable or unreadable results index (a 404
    before anything has ever been pushed, or a least-privilege key with
    write but not read) turned a RuntimeError loose and failed the alert
    INSTEAD of completing it. That failure was self-perpetuating: the
    state that triggers a resume is exactly the state a failed resume
    preserves, so every resumable alert failed on every cycle for the
    whole window — worked==0 with failures, which the watchdog scores as
    sick, pages at 3 cycles and exits(2) at 30 (review catch, two
    lenses). Degrading to "assume not indexed" costs at worst the one
    duplicate results row this check exists to avoid, and keeps the
    alert moving.
    """
    try:
        return await source.has_investigation(alert_id, since.isoformat())
    except Exception as e:
        log.warning(
            "Could not check whether the interrupted run already indexed "
            "%s (%s); pushing the result rather than risking losing it — "
            "this may leave a duplicate results row.", alert_id, e,
        )
        return False


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
    resume_window: int = 0,
) -> str:
    """Work ONE alert from the watch queue: investigate (or resume an
    interrupted run, or borrow a dedup-suppressed conclusion), push the
    result, set the alert's status, and offer the outcome to the
    case/notify policies. Returns how the conclusion was reached —
    "worked", "resumed", or "borrowed" — which is what keeps the
    watchdog from reading a model-free completion as proof the model
    pipeline is alive. Raises on failure — the cycle catches and retries
    the alert next poll.

    The ORDER of effects is the contract this seam exists to pin, and the
    tests in tests/test_watch.py hold it:

    1. push_investigation  — the result lands in Elastic first
    2. set_alert_status    — closed (auto-close) or acknowledged
    3. record_closure      — LAST, only after both Elastic writes, so the
       local log asserts what HAPPENED, not what was about to happen. A
       push failure leaves no phantom closure (review catch from the
       scorecard increment); a crash between the status write and the
       record undercounts automation instead — the safe direction.
    4. seen.add + progress "completed" — only a fully-recorded alert is
       marked done, in memory for this process and on disk for the next
    5. case/notify         — never for an auto-closed alert (it needs no
       human owner, so it must generate no case noise and no page)

    That order is what makes the resume path (soc_copilot/resume.py)
    necessary: the history record is written inside the investigate call,
    BEFORE step 1, so every crash from there to step 2 leaves a paid-for
    verdict on disk and an alert still open.

    What makes it SAFE is the progress ledger, written either side of that
    span (step 0 "started", step 4 "completed"). An earlier draft argued
    instead that steps 3-5 could not have run in a resumable state,
    "because if step 2 had completed the alert would not be in the open
    queue" — which inverts the implication. Step 2 completing means the
    alert LEFT the queue then, not that it cannot be back in it now: any
    workflow_status reset (an analyst demanding a second look, a Kibana
    bulk action, a SOAR playbook) puts a fully-worked alert back. Three
    review lenses found it, and the reproduction showed a resume undoing
    an analyst's re-open, opening a SECOND TheHive case, paging twice and
    appending a duplicate closure. The ledger makes the premise true by
    construction rather than by inference: a "completed" alert is never
    resumed, so a re-open gets the fresh look it asked for.
    """
    from .closure import should_auto_close

    outcome = "worked"
    investigation = None
    resumed_at = None
    if resume_window:
        from .resume import find_resumable

        found = find_resumable(copilot.history, alert, resume_window)
        if found:
            investigation, resumed_at = found.investigation, found.investigated_at
            outcome = "resumed"
            # WARNING, not INFO: an alert acknowledged with a verdict this
            # process never computed is the one line an operator must be
            # able to find when reconstructing what a crash cost them.
            log.warning("[resume: %s]", found.reason)
    # Step 0 of the ordering contract: claim the alert BEFORE spending
    # anything on it, so a crash from here to step 4 is legible as an
    # interruption rather than inferred from circumstance.
    copilot.history.record_watch_progress(alert.alert_id, doc_id, "started")
    if investigation is None and dedup_window:
        from .dedup import try_suppress

        result = try_suppress(copilot.history, alert, dedup_window)
        if result:
            investigation, suppressed_reason = result
            outcome = "borrowed"
            log.info("[dedup: %s — no model call spent]", suppressed_reason)
    if investigation is None:
        investigation = await _investigate(copilot, alert, agentic, tiered)
    close, reason = (
        should_auto_close(investigation) if auto_close else (False, None)
    )
    # A resumed run may already have pushed before it died — the push is
    # the write immediately before the status write it never reached. /_doc
    # mints a new id every time, so an unconditional re-push would index a
    # second row for one investigation and double-count its cost in every
    # dashboard. One search settles it, scoped to results indexed since
    # THIS run's investigation so an older row for the same alert cannot
    # answer for it.
    if outcome == "resumed" and await _already_indexed(
        source, alert.alert_id, resumed_at
    ):
        result_id = "(already indexed by the interrupted run)"
        log.info("Result already in the index from the interrupted run; "
                 "not indexing a second copy.")
    else:
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
    # The durable twin of seen.add, and the fact that stops this alert
    # being mistaken for an interrupted one if it is ever re-opened.
    copilot.history.record_watch_progress(alert.alert_id, doc_id, "completed")
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
    # Which of the three ways this completed. Both model-free ways
    # ("resumed", "borrowed") must stay out of the watchdog's `worked`
    # count: neither is proof the investigation pipeline is alive.
    return outcome


def _die_by_signal(loop: asyncio.AbstractEventLoop, sig: int) -> None:
    """Terminate the way the signal itself would have, had nothing been
    listening: restore the default disposition and re-raise on ourselves,
    so the wait status is WIFSIGNALED — what a supervisor calls a clean
    stop — rather than an exit CODE of 143, which systemd classifies as
    a failure (review catch).

    A module-level seam so tests can observe the death without dying:
    patching os._exit is not enough once the process really does die by
    signal, and a handler bug then takes the whole test runner with it —
    which is exactly what happened when this fix first landed.
    """
    loop.remove_signal_handler(sig)
    os.kill(os.getpid(), sig)


def _install_stop_handler(
    stop: asyncio.Event, sig: int = signal.SIGTERM
) -> None:
    """Make SIGTERM a DRAIN, not a kill: `systemctl stop` and
    `docker stop` both deliver it, and until now it cut down whatever
    alert was mid-investigation — safe by write ordering, but paid for
    (the model call was spent and the verdict discarded). The handler
    sets the stop event; the watch loop finishes the alert in flight,
    starts nothing new, and exits 0.

    A SECOND signal is the operator saying "now": the process dies BY
    that signal rather than exiting with its number. Both report 143 to
    a shell, but only death-by-signal is what supervisors call a clean
    stop — an exit CODE of 143 is a failure to systemd, which with
    `Restart=on-failure` would leave the unit failed or, outside a stop
    job, restart the process the operator just force-stopped (review
    catch: the docstring claimed dashboards read both shapes alike, and
    systemd is exactly the supervisor that does not).

    Unix-only (loop.add_signal_handler), like the deployment itself; a
    loop without signal support says so plainly instead of surfacing an
    empty configuration error."""
    loop = asyncio.get_running_loop()

    def _on_signal() -> None:
        if stop.is_set():
            log.error(
                "Second stop signal — exiting immediately. Mid-alert "
                "work is discarded (safe by write ordering)."
            )
            # Nothing runs after this: the signal is unblocked and
            # delivered to this thread immediately.
            _die_by_signal(loop, sig)
            return
        log.warning(
            "Stop signal received — finishing the alert in flight, then "
            "exiting cleanly. Send the signal again to exit immediately "
            "(`systemctl kill`, or repeat `docker stop`)."
        )
        stop.set()

    try:
        loop.add_signal_handler(sig, _on_signal)
    except NotImplementedError as e:
        # Only reachable on an event loop without Unix signal support
        # (native Windows). Left as a RuntimeError so cli() prints one
        # line, but WITH a message: NotImplementedError subclasses
        # RuntimeError and arrives empty, so the operator got a bare
        # "Configuration error:" blaming a config that is fine.
        raise RuntimeError(
            "--watch needs a Unix event loop for its graceful stop "
            "(SIGTERM drain); this platform's loop has no signal support"
        ) from e


def _should_sync_feedback(
    feedback: bool, stop: asyncio.Event, last_sync: float, now: float
) -> bool:
    """Whether this cycle should pull analyst rulings from TheHive.

    A predicate rather than an inline condition so the STOP clause is
    pinned by a test: starting a full TheHive sync after a stop signal
    can spend a chunk of the supervisor's grace on work no one is
    waiting for, and as shell code inside the loop nothing executed it
    (review catch)."""
    if not feedback or stop.is_set():
        return False
    return now - last_sync >= FEEDBACK_SYNC_INTERVAL


async def _sleep_or_stop(stop: asyncio.Event, interval: float) -> bool:
    """The poll-cycle sleep, interruptible by the stop event. Returns
    True to keep looping, False when the shutdown drain should begin —
    immediately if the stop already happened during the cycle, mid-sleep
    if the signal lands there (a stop must never wait out the interval;
    at the default 60s that would eat most of a supervisor's grace
    period doing nothing)."""
    if stop.is_set():
        return False
    try:
        await asyncio.wait_for(stop.wait(), timeout=interval)
    except TimeoutError:
        return True
    return False


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
    resume_window: int = 0,
    stop: asyncio.Event | None = None,
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
    if stop is not None and stop.is_set():
        # The stop landed before this cycle began (during the previous
        # sleep or the feedback sync). Fetching now would spend up to
        # ~41s of the supervisor's grace — a 20s timeout plus a
        # replayable retry — to build a queue we are about to abandon
        # (review catch).
        log.warning("Draining for shutdown: skipping this poll cycle.")
        return report
    hits = await source.fetch_alert_hits(limit=10, status="open")
    fresh = [(d, a) for d, a in hits if d not in seen]
    prioritized = _prioritize(copilot, fresh)
    for worked_ahead, (doc_id, alert, why) in enumerate(prioritized):
        # The drain point: a stop landing mid-alert lets THAT alert
        # finish (its model call is already paid for; the write ordering
        # completes it honestly), and everything behind it stays open in
        # Elastic for the next start. Checked between alerts only —
        # in-flight work is never cancelled.
        if stop is not None and stop.is_set():
            log.warning(
                "Draining for shutdown: leaving %d fresh alert(s) "
                "unstarted — they stay open in Elastic for the next "
                "start.", len(prioritized) - worked_ahead,
            )
            break
        # The correlation id: every line logged while THIS alert is being
        # worked — the mode line, tool chatter, the failure — carries its
        # id in JSON mode, so one alert's story greps out of the night.
        with alert_context(alert.alert_id):
            log.info(
                "\n=== %s — %s [priority: %s] ===",
                alert.alert_id, alert.title, why,
            )
            try:
                outcome = await _work_alert(
                    copilot, source, doc_id, alert, seen,
                    agentic=agentic, tiered=tiered, auto_close=auto_close,
                    notify=notify, case=case, dedup_window=dedup_window,
                    resume_window=resume_window,
                )
                if outcome == "borrowed":
                    report.borrowed += 1
                elif outcome == "resumed":
                    report.resumed += 1
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
    stop: asyncio.Event | None = None,
) -> None:
    """One SUPERVISED cycle: work the queue, report to the watchdog, act.

    This is the seam that keeps the health wiring testable — the crash
    path (a failed fetch becomes a crashed CycleReport, never a healthy
    one) and the observe→act handoff both live here, not in the infinite
    loop (review catch: as shell code, a mutant discarding the action
    survived every test).
    """
    from .config import settings

    # Read OUTSIDE the try: a configuration problem is not a poll-cycle
    # failure, and laundering it into one would report "retrying in 60s"
    # about something no retry can fix, while sickening the watchdog
    # toward an exit(2) restart loop that reruns the same bad config.
    resume_window = settings.RESUME_WINDOW_MINUTES
    try:
        report = await _watch_once(
            copilot, source, seen,
            agentic=args.agentic, tiered=args.tiered,
            auto_close=args.auto_close, notify=args.notify,
            case=args.case, dedup_window=args.dedup,
            resume_window=resume_window, stop=stop,
        )
    except Exception as e:
        report = CycleReport(crashed=True)
        if stop is not None and stop.is_set():
            # Promising a retry here would be a lie the very next line
            # contradicts: the drain exits without another cycle (review
            # catch).
            log.error(
                "Poll cycle failed during shutdown drain (not retried; "
                "open alerts stay open in Elastic): %s", e,
            )
        else:
            log.error(
                "Poll cycle failed (retrying in %ds): %s", args.interval, e
            )
    if stop is not None and stop.is_set():
        # A drained cycle is NOT evidence: it was cut short on purpose.
        # Observing it would let a partially-quiet drain fake a recovery
        # mid-outage (resetting the sick streak with a "recovered" line
        # while nothing recovered), and a sick drained cycle could page
        # — or raise the watchdog's exit(2) — during an operator stop
        # that is about to exit 0. The watchdog judges full cycles only.
        return
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

    Dedupe survives a restart too, but not by remembering doc ids. The
    loop records its own progress on each alert (started before it
    commits, completed once every effect has landed — the durable twin
    of `seen`), so a crash between the model call and the
    acknowledgement is a recorded fact rather than an inference. The
    next start FINISHES that run from its own record instead of buying
    the same conclusion again (soc_copilot/resume.py,
    RESUME_WINDOW_MINUTES). The alert then leaves the queue the normal
    way, which is the property a naive "never work this id twice"
    blacklist would have destroyed — and a COMPLETED alert is never
    resumed, so re-opening one in Elastic still gets a fresh look.

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

    Stopping is a DRAIN, not a kill: SIGTERM (systemctl stop, docker
    stop) lets the alert in flight finish — its model call is already
    paid for — starts nothing new, and exits 0; a second SIGTERM exits
    immediately. The drain point sits between alerts in _watch_once and
    inside the interruptible sleep, both tested seams; in-flight work is
    never cancelled, so the write-ordering contract needs no new cases.

    This shell owns only what cannot run under a test: real construction,
    the infinite loop, and the feedback-sync timer. Everything the loop
    DOES is _watch_once/_work_alert — the seam tests/test_watch.py pins,
    so the ordering contract above is held by tests rather than by
    careful reading — everything the watchdog DECIDES and the health
    actions DO is pinned the same way (tests/test_watchdog.py), and the
    stop path (drain point, signal handler, interruptible sleep) is
    pinned beside them.
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
    stop = asyncio.Event()
    _install_stop_handler(stop)
    mode = "agentic" if args.agentic else "phase one"
    feedback = bool(settings.THEHIVE_URL and settings.THEHIVE_API_KEY)
    last_feedback_sync = float("-inf")
    # When watch runs under nohup/systemd its output is the operator's
    # only heartbeat; the logging handler flushes per record, so nothing
    # here needs flush=True anymore.
    log.info(
        "Watching %s every %ds (%s mode%s%s%s%s%s%s). Ctrl+C to stop.",
        source.alerts_index, interval, mode,
        ", tiered on" if args.tiered else "",
        ", auto-close on" if args.auto_close else "",
        ", notifications on" if args.notify else "",
        f", dedup on ({args.dedup}h window)" if args.dedup else "",
        ", analyst-feedback sync on" if feedback else "",
        f", resume window {settings.RESUME_WINDOW_MINUTES}m"
        if settings.RESUME_WINDOW_MINUTES > 0 else ", resume off",
    )
    while True:
        if _should_sync_feedback(
            feedback, stop, last_feedback_sync, time.monotonic()
        ):
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
                    await _annotate_elastic(changed, stop=stop)
            except Exception as e:
                log.warning("Feedback sync failed (will retry): %s", e)
        await _run_watch_cycle(copilot, source, seen, watchdog, args, stop=stop)
        if not await _sleep_or_stop(stop, interval):
            # The drain's clean end: in-flight work finished, nothing
            # started since the signal, exit 0 — a supervisor reads it
            # as a stop, not a failure to restart.
            log.info(
                "Stopped cleanly: drained in-flight work; unstarted "
                "alerts stay open in Elastic for the next start."
            )
            return


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
    elif command == "rotate-history":
        await _run_rotate_history(args)
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

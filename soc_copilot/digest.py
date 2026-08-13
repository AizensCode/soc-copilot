"""The SOC morning digest — what the copilot did, what came back from
the humans, and what needs a human first.

Composes the store's layers into one daily artifact: investigations in
the reporting window, analyst rulings that arrived, campaign flags, and
the standing copilot-vs-analyst disagreements. Assembly is deterministic
Python over the history store — the same grounding-by-construction rule
as everywhere else; the model only narrates the assembled data and
cannot add an alert, ruling, or number to it.

Windowing uses investigated_at / recorded_at (wall-clock, when the
copilot did the work), not the alert's own timestamp: a digest answers
"what happened on this desk since yesterday", and an alert from last
April investigated overnight belongs in it. Records that predate these
fields fall outside every window by design.
"""
import json
from datetime import datetime, timedelta, timezone

from anthropic import AsyncAnthropic

from .config import settings
from .history import AlertHistoryStore
from .prompts.digest import DIGEST_SYSTEM_PROMPT
from .scorecard import build_scorecard

# Briefings are a page of markdown, but adaptive thinking spends output
# tokens before the text block — budget well above the visible answer.
MAX_BRIEFING_TOKENS = 8000


def _in_window(iso: str | None, cutoff: datetime) -> bool:
    if not iso:
        return False
    return datetime.fromisoformat(iso) >= cutoff


def build_digest_data(
    store: AlertHistoryStore,
    since_hours: int = 24,
    now: datetime | None = None,
) -> dict:
    """Assemble the digest deterministically from the store.

    Latest record per alert, filtered to the window; analyst rulings
    joined in (the current ruling always rides its investigation, and
    rulings SYNCED inside the window are additionally listed as news).
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=since_hours)

    latest: dict[str, dict] = {}
    for rec in store._iter_records():
        latest[rec["alert_id"]] = rec  # file order: last line wins

    rulings = store.dispositions()
    # The scorecard already decides which autonomous closures still STAND
    # (a closure superseded by a later re-investigation or analyst ruling
    # is human work, not automation) — reuse that judgment rather than
    # re-deriving it. Built before the entry loop so each in-window entry
    # can say whether it is waiting on a human at all.
    card = build_scorecard(store)
    closures = store.closures()

    investigated: list[dict] = []
    counts = {
        "true_positive": 0, "false_positive": 0, "inconclusive": 0,
        "escalations": 0, "campaigns": 0, "auto_closed": 0,
    }
    for rec in latest.values():
        if not _in_window(rec.get("investigated_at"), cutoff):
            continue
        inv = rec.get("investigation", {})
        correlation = inv.get("correlation") or {}
        ruling = rulings.get(rec["alert_id"])
        auto_closed = rec["alert_id"] in card.auto_closed_ids
        entry = {
            "alert_id": rec["alert_id"],
            "title": rec.get("title", ""),
            "verdict": rec["verdict"],
            "confidence": rec.get("confidence", "?"),
            "escalation_recommended": bool(inv.get("escalation_recommended")),
            "is_campaign": bool(correlation.get("is_campaign")),
            "hypothesis": inv.get("hypothesis", ""),
            "investigated_at": rec.get("investigated_at"),
            "cost_usd": rec.get("cost_usd"),
            "duration_seconds": rec.get("duration_seconds"),
            "duplicate_of": rec.get("duplicate_of"),
            # An alert the desk closed by policy is NOT in the human
            # queue — until this flag the digest could not tell one from
            # an acknowledged alert waiting for review (roadmap item,
            # named by the scorecard review).
            "auto_closed": auto_closed,
        }
        if auto_closed:
            entry["closure_reason"] = closures[rec["alert_id"]].get("reason")
        if ruling:
            entry["analyst_ruled"] = ruling["human_verdict"]
        investigated.append(entry)
        counts[rec["verdict"]] = counts.get(rec["verdict"], 0) + 1
        counts["escalations"] += entry["escalation_recommended"]
        counts["campaigns"] += entry["is_campaign"]
        counts["auto_closed"] += auto_closed
    investigated.sort(key=lambda e: e["investigated_at"], reverse=True)

    new_rulings: list[dict] = []
    for alert_id, ruling in rulings.items():
        if not _in_window(ruling.get("recorded_at"), cutoff):
            continue
        entry = {
            "alert_id": alert_id,
            "human_verdict": ruling["human_verdict"],
            "source": ruling.get("source", "?"),
            "summary": ruling.get("summary"),
        }
        rec = latest.get(alert_id)
        if rec:
            entry["copilot_verdict"] = rec["verdict"]
            entry["agrees"] = rec["verdict"] == ruling["human_verdict"]
        else:
            entry["note"] = "no local investigation on record"
        new_rulings.append(entry)

    # Cost/latency for the window. Summed over the SAME latest-per-alert
    # set the rest of the digest reports on, so "12 investigated, $0.41"
    # is internally consistent. Records without telemetry contribute
    # nothing and are counted as unmeasured rather than as zero.
    # Suppressed duplicates are their own bucket: their genuine $0.00 would
    # otherwise drag the mean cost of a REAL investigation — the number a
    # tiering decision is made from. Savings are estimated honestly: each
    # suppression avoided re-running its specific anchor, so the estimate
    # is the sum of those anchors' recorded costs, and duplicates whose
    # anchor cost is unrecorded are counted rather than guessed at.
    suppressed = [e for e in investigated if e.get("duplicate_of")]
    real = [e for e in investigated if not e.get("duplicate_of")]
    measured = [e for e in real if e.get("cost_usd") is not None]
    anchor_costs = [
        latest[e["duplicate_of"]].get("cost_usd")
        for e in suppressed
        if e["duplicate_of"] in latest
    ]
    known_savings = [c for c in anchor_costs if c is not None]
    spend = {
        "measured_investigations": len(measured),
        "unmeasured_investigations": len(real) - len(measured),
        "total_cost_usd": round(sum(e["cost_usd"] for e in measured), 4),
        "mean_cost_usd": round(
            sum(e["cost_usd"] for e in measured) / len(measured), 4
        ) if measured else None,
        "mean_duration_seconds": round(
            sum(e.get("duration_seconds") or 0 for e in measured) / len(measured), 1
        ) if measured else None,
        "suppressed_duplicates": len(suppressed),
        "estimated_savings_usd": round(sum(known_savings), 4),
        "suppressed_with_unknown_saving": len(suppressed) - len(known_savings),
    }

    return {
        "generated_at": now.isoformat(),
        "window_hours": since_hours,
        "spend": spend,
        "quiet": not investigated and not new_rulings,
        "investigated": investigated,
        "counts": {"total": len(investigated), **counts},
        "new_rulings": new_rulings,
        "standing_disagreements": [
            {
                "alert_id": r.alert_id,
                "copilot_verdict": r.copilot_verdict,
                "human_verdict": r.human_verdict,
                "analyst_note": r.summary,
                "title": r.title,
            }
            for r in card.disagreements
        ],
        "accuracy_record": {
            "alerts_investigated_all_time": card.investigated,
            "ruled_by_analysts": card.ruled,
            "agreements": card.agreements,
        },
    }


def render_quiet(data: dict) -> str:
    """The no-API-call answer for a window with nothing in it."""
    return (
        f"SOC digest — last {data['window_hours']}h: quiet. "
        f"No investigations, no new analyst rulings."
    )


async def write_briefing(data: dict, client: AsyncAnthropic | None = None) -> str:
    """Narrate the assembled digest. The model sees only the data."""
    client = client or AsyncAnthropic(api_key=settings.ANTHROPIC_KEY)
    response = await client.messages.create(
        model=settings.MODEL,
        max_tokens=MAX_BRIEFING_TOKENS,
        system=DIGEST_SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": (
                    "# Digest data (assembled deterministically from the "
                    "copilot's case store)\n"
                    f"```json\n{json.dumps(data, indent=2)}\n```\n\n"
                    "Write the briefing now."
                ),
            }
        ],
    )
    # content may lead with thinking blocks; take the text block.
    text = next((b.text for b in response.content if b.type == "text"), None)
    if text is None:
        raise RuntimeError("Model response contained no text block")
    return text

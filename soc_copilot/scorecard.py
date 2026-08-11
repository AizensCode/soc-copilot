"""The copilot's accuracy record, computed from analyst rulings.

Joins the history store (the copilot's verdicts) with the dispositions
file (the humans' rulings, synced from case management) into a small
scorecard: how often the copilot's final verdict matched the analyst's,
and — more useful than the rate — the list of disagreements, which is
where prompt work, fixtures, and inventory entries come from. Every
improvement this project made started as one of those rows.

v2 measures the desk, not only the verdicts:

- **Agreement sliced by stated confidence.** Auto-close bets on the
  confidence gate being meaningful; `autoclose_safe` measures that bet
  against harness labels, this measures it against real analyst rulings.
  A `high` row that agrees no more often than `medium` is the gate
  telling you it isn't one.
- **Escalation precision.** A dismissed escalation is alert-fatigue cost;
  a ruled-true-positive the copilot did NOT escalate is the dangerous
  kind, and is listed by name, never averaged away.
- **Automation rate.** What fraction of worked alerts consumed no human
  attention — autonomous closures (recorded per event by watch mode) plus
  suppressed near-duplicates. Counted from what the desk actually DID,
  never from what would-have qualified — and a closure SUPERSEDED by
  later human work (a re-investigation or an analyst ruling recorded
  after it) drops out of the numerator: an alert autonomy failed on is
  not a win for autonomy.
- **Time to verdict.** Alert fired -> first REAL verdict recorded, median
  and p90. Suppressed duplicates don't contribute a sample — borrowing a
  verdict in zero seconds is dedup's savings (the digest reports those),
  not evidence the pipeline is fast — but an alert suppressed first and
  genuinely investigated later is timed on that real verdict.

Pure functions over the store; no API, no network. The Kibana console
shows the accuracy numbers live (the "Analyst agreement" tile, fed by the
per-doc human_agrees stamp); this module is the CLI/offline view.
"""
import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .history import AlertHistoryStore

_CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Ruling:
    alert_id: str
    title: str
    copilot_verdict: str
    copilot_confidence: str
    human_verdict: str
    agrees: bool
    source: str
    summary: str | None
    # None means the record predates the flattened flag — unknown is
    # excluded from escalation metrics, never assumed either way.
    escalated: bool | None = None


@dataclass
class Scorecard:
    investigated: int              # distinct alerts the copilot has judged
    ruled: int                     # of those, how many a human has ruled on
    agreements: int
    rulings: list[Ruling] = field(default_factory=list)
    # --- the desk (v2) ---
    worked: int = 0                # distinct alerts incl. suppressed dupes
    auto_closed: int = 0           # closures still standing (not superseded)
    suppressed: int = 0            # alerts whose latest record is a dedup
    automated: int = 0             # |auto-closed ∪ suppressed| (no double count)
    closures_superseded: int = 0   # closures later overtaken by human work
    time_to_verdict_s: list[float] = field(default_factory=list)

    @property
    def disagreements(self) -> list[Ruling]:
        return [r for r in self.rulings if not r.agrees]

    @property
    def agreement_rate(self) -> float | None:
        """None (not 100%) when nothing has been ruled yet — an empty
        denominator is 'no data', never 'perfect record'."""
        if self.ruled == 0:
            return None
        return self.agreements / self.ruled

    @property
    def by_confidence(self) -> dict[str, tuple[int, int]]:
        """confidence -> (agreements, ruled), high/medium/low first."""
        out: dict[str, tuple[int, int]] = {}
        for r in self.rulings:
            a, n = out.get(r.copilot_confidence, (0, 0))
            out[r.copilot_confidence] = (a + r.agrees, n + 1)
        return dict(sorted(
            out.items(), key=lambda kv: _CONFIDENCE_ORDER.get(kv[0], 99)
        ))

    @property
    def escalations_ruled(self) -> list[Ruling]:
        return [r for r in self.rulings if r.escalated is True]

    @property
    def escalations_confirmed(self) -> int:
        return sum(
            1 for r in self.escalations_ruled
            if r.human_verdict == "true_positive"
        )

    @property
    def escalations_dismissed(self) -> int:
        return sum(
            1 for r in self.escalations_ruled
            if r.human_verdict == "false_positive"
        )

    @property
    def missed_escalations(self) -> list[Ruling]:
        """Ruled true positive, copilot explicitly did not escalate — the
        dangerous error class, listed by name."""
        return [
            r for r in self.rulings
            if r.escalated is False and r.human_verdict == "true_positive"
        ]

    @property
    def automation_rate(self) -> float | None:
        if self.worked == 0:
            return None
        return self.automated / self.worked

    @property
    def time_to_verdict_median_s(self) -> float | None:
        if not self.time_to_verdict_s:
            return None
        return statistics.median(self.time_to_verdict_s)

    @property
    def time_to_verdict_p90_s(self) -> float | None:
        """Nearest-rank p90 — deterministic, no interpolation."""
        if not self.time_to_verdict_s:
            return None
        ordered = sorted(self.time_to_verdict_s)
        return ordered[max(0, math.ceil(0.9 * len(ordered)) - 1)]


def _aware(ts: datetime) -> datetime:
    """Records may carry naive alert timestamps (source-dependent);
    treat naive as UTC so the subtraction is defined rather than a
    TypeError three weeks after a new source is added."""
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def build_scorecard(store: AlertHistoryStore) -> Scorecard:
    """Join the copilot's LATEST verdict per alert with the analyst's
    latest ruling, and fold in what the desk did (closures, suppressions,
    latency).

    Latest-per-alert on both sides: an alert investigated three times is
    judged on the copilot's final opinion (the one that stood when the
    human ruled), and a re-opened case's newest resolution supersedes the
    old one. Rulings (and closure events) for alerts with no local record
    (e.g. a store reset) are ignored rather than guessed about.
    """
    # Suppressed duplicates carry a BORROWED verdict, not a model judgment
    # this copilot made about that alert — scoring them would count one
    # anchor opinion N+1 times and let an analyst ruling on a copy inflate
    # or deflate an accuracy record the model never earned. They are
    # excluded from the accuracy join, but they ARE desk work: they count
    # in `worked` and in the automation numerator.
    latest_any: dict[str, dict] = {}
    first_real: dict[str, dict] = {}
    last_real_at: dict[str, str] = {}
    for rec in store._iter_records():
        latest_any[rec["alert_id"]] = rec  # file order: last line wins
        if not rec.get("duplicate_of"):
            # First REAL record per alert (an alert suppressed first and
            # genuinely investigated later is timed on the real verdict,
            # not silently dropped — review catch), and the latest real
            # investigation time (for closure supersession below).
            first_real.setdefault(rec["alert_id"], rec)
            if rec.get("investigated_at"):
                last_real_at[rec["alert_id"]] = rec["investigated_at"]
    latest = {
        aid: rec for aid, rec in latest_any.items()
        if not rec.get("duplicate_of")
    }
    suppressed_ids = {
        aid for aid, rec in latest_any.items() if rec.get("duplicate_of")
    }

    # A recorded closure counts as automation only while it STANDS. A later
    # real investigation or analyst ruling means a human took the alert
    # over — autonomy failed on it, and counting it would inflate the rate
    # on exactly those alerts (review catch). Events for alerts with no
    # local record are ignored, like dispositions.
    dispositions = store.dispositions()
    closure_ids: set[str] = set()
    superseded = 0
    for aid, event in store.closures().items():
        if aid not in latest_any:
            continue
        closed_raw = event.get("closed_at")
        if closed_raw:
            closed = _aware(datetime.fromisoformat(closed_raw))
            inv_raw = last_real_at.get(aid)
            inv_after = inv_raw and _aware(
                datetime.fromisoformat(inv_raw)
            ) > closed
            ruled_raw = dispositions.get(aid, {}).get("recorded_at")
            ruled_after = ruled_raw and _aware(
                datetime.fromisoformat(ruled_raw)
            ) > closed
            if inv_after or ruled_after:
                superseded += 1
                continue
        closure_ids.add(aid)

    time_to_verdict: list[float] = []
    for rec in first_real.values():
        if not rec.get("investigated_at"):
            continue  # legacy record: no sample, never a crash
        fired = _aware(datetime.fromisoformat(rec["timestamp"]))
        done = _aware(datetime.fromisoformat(rec["investigated_at"]))
        time_to_verdict.append((done - fired).total_seconds())

    rulings: list[Ruling] = []
    agreements = 0
    for alert_id, ruling in dispositions.items():
        rec = latest.get(alert_id)
        if rec is None:
            continue
        agrees = rec["verdict"] == ruling["human_verdict"]
        agreements += agrees
        rulings.append(
            Ruling(
                alert_id=alert_id,
                title=rec.get("title", ""),
                copilot_verdict=rec["verdict"],
                copilot_confidence=rec.get("confidence", "?"),
                human_verdict=ruling["human_verdict"],
                agrees=agrees,
                source=ruling.get("source", "?"),
                summary=ruling.get("summary"),
                escalated=rec.get("investigation", {}).get(
                    "escalation_recommended"
                ),
            )
        )

    rulings.sort(key=lambda r: (r.agrees, r.alert_id))  # disagreements first
    return Scorecard(
        investigated=len(latest),
        ruled=len(rulings),
        agreements=agreements,
        rulings=rulings,
        worked=len(latest_any),
        auto_closed=len(closure_ids),
        suppressed=len(suppressed_ids),
        automated=len(closure_ids | suppressed_ids),
        closures_superseded=superseded,
        time_to_verdict_s=time_to_verdict,
    )


def _fmt_duration(seconds: float) -> str:
    sign = "-" if seconds < 0 else ""
    s = abs(seconds)
    if s < 60:
        return f"{sign}{s:.0f}s"
    if s < 3600:
        return f"{sign}{int(s // 60)}m{int(s % 60):02d}s"
    if s < 86400:
        return f"{sign}{int(s // 3600)}h{int(s % 3600 // 60):02d}m"
    return f"{sign}{int(s // 86400)}d{int(s % 86400 // 3600):02d}h"


def render_scorecard(card: Scorecard) -> str:
    """Human-readable scorecard for the CLI."""
    lines = ["SOC copilot scorecard — copilot vs analyst rulings", ""]
    lines.append(f"Alerts investigated (distinct): {card.investigated}")

    if card.agreement_rate is None:
        lines.append(
            "Analyst rulings synced: 0 — no accuracy data yet. "
            "Run --sync-feedback after analysts work the TheHive queue."
        )
    else:
        lines.append(f"Ruled on by an analyst:         {card.ruled}")
        lines.append(
            f"Agreement:                      {card.agreements}/{card.ruled} "
            f"({card.agreement_rate:.0%})"
        )
        by_conf = ", ".join(
            f"{conf} {a}/{n} ({a / n:.0%})"
            for conf, (a, n) in card.by_confidence.items()
        )
        lines.append(f"  by stated confidence:         {by_conf}")
        lines.append(
            "  (auto-close bets on the high row being trustworthy — "
            "watch it)"
        )

        known = [r for r in card.rulings if r.escalated is not None]
        if known:
            ruled_esc = card.escalations_ruled
            other = (len(ruled_esc) - card.escalations_confirmed
                     - card.escalations_dismissed)
            lines.append("")
            lines.append(
                f"Escalation precision ({len(ruled_esc)} escalation(s) "
                f"ruled on):"
            )
            lines.append(
                f"  confirmed true positive:      {card.escalations_confirmed}"
            )
            lines.append(
                f"  dismissed as false positive:  {card.escalations_dismissed}"
                + ("   <- alert-fatigue cost"
                   if card.escalations_dismissed else "")
            )
            if other:
                lines.append(f"  other rulings:                {other}")
            if card.missed_escalations:
                lines.append(
                    f"  MISSED ({len(card.missed_escalations)}) — ruled true "
                    f"positive, copilot did NOT escalate:"
                )
                for r in card.missed_escalations:
                    lines.append(
                        f"    {r.alert_id}: copilot said {r.copilot_verdict} "
                        f"({r.copilot_confidence}) without escalation"
                    )

    if card.worked:
        humans = card.worked - card.automated
        # auto_closed + suppressed can exceed automated (an alert can be
        # both); say so, or the line's arithmetic silently disagrees with
        # itself (review catch).
        overlap = card.auto_closed + card.suppressed - card.automated
        lines.append("")
        lines.append("Desk automation:")
        lines.append(
            f"  alerts worked: {card.worked} — auto-closed: "
            f"{card.auto_closed}, suppressed duplicates: {card.suppressed}"
            + (f" (overlap counted once: {overlap})" if overlap else "")
            + f", left for humans: {humans}"
        )
        rate = card.automation_rate
        lines.append(
            f"  automation rate:  {card.automated}/{card.worked} ({rate:.0%})"
        )
        if card.closures_superseded:
            lines.append(
                f"  ({card.closures_superseded} closure(s) superseded by "
                f"later human work — not counted as automated)"
            )
    if card.time_to_verdict_s:
        lines.append(
            f"Time to verdict (alert fired -> first real verdict): "
            f"median {_fmt_duration(card.time_to_verdict_median_s)}"
            f", p90 {_fmt_duration(card.time_to_verdict_p90_s)} "
            f"(n={len(card.time_to_verdict_s)})"
        )

    if card.agreement_rate is not None:
        if card.disagreements:
            lines.append("")
            lines.append("Disagreements (the rows worth studying):")
            for r in card.disagreements:
                lines.append(
                    f"  {r.alert_id}: copilot said {r.copilot_verdict} "
                    f"({r.copilot_confidence}), analyst ruled {r.human_verdict} "
                    f"[{r.source}]"
                )
                if r.summary:
                    lines.append(f'    analyst note: "{r.summary}"')
                if r.title:
                    lines.append(f"    alert: {r.title}")
        else:
            lines.append("No disagreements on record.")
    return "\n".join(lines)

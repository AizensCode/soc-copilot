"""The copilot's accuracy record, computed from analyst rulings.

Joins the history store (the copilot's verdicts) with the dispositions
file (the humans' rulings, synced from case management) into a small
scorecard: how often the copilot's final verdict matched the analyst's,
and — more useful than the rate — the list of disagreements, which is
where prompt work, fixtures, and inventory entries come from. Every
improvement this project made started as one of those rows.

Pure functions over the store; no API, no network. The Kibana console
shows the same numbers live (the "Analyst agreement" tile, fed by the
per-doc human_agrees stamp); this module is the CLI/offline view.
"""
from dataclasses import dataclass, field

from .history import AlertHistoryStore


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


@dataclass
class Scorecard:
    investigated: int              # distinct alerts the copilot has judged
    ruled: int                     # of those, how many a human has ruled on
    agreements: int
    rulings: list[Ruling] = field(default_factory=list)

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


def build_scorecard(store: AlertHistoryStore) -> Scorecard:
    """Join the copilot's LATEST verdict per alert with the analyst's
    latest ruling.

    Latest-per-alert on both sides: an alert investigated three times is
    judged on the copilot's final opinion (the one that stood when the
    human ruled), and a re-opened case's newest resolution supersedes the
    old one. Rulings for alerts with no local investigation record (e.g.
    a store reset) are ignored rather than guessed about.
    """
    # Suppressed duplicates carry a BORROWED verdict, not a model judgment
    # this copilot made about that alert — scoring them would count one
    # anchor opinion N+1 times and let an analyst ruling on a copy inflate
    # or deflate an accuracy record the model never earned. They are
    # excluded from both the investigated count and the ruling join.
    latest: dict[str, dict] = {}
    for rec in store._iter_records():
        if rec.get("duplicate_of"):
            continue
        latest[rec["alert_id"]] = rec  # file order: last line wins

    rulings: list[Ruling] = []
    agreements = 0
    for alert_id, ruling in store.dispositions().items():
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
            )
        )

    rulings.sort(key=lambda r: (r.agrees, r.alert_id))  # disagreements first
    return Scorecard(
        investigated=len(latest),
        ruled=len(rulings),
        agreements=agreements,
        rulings=rulings,
    )


def render_scorecard(card: Scorecard) -> str:
    """Human-readable scorecard for the CLI."""
    lines = ["SOC copilot scorecard — copilot vs analyst rulings", ""]
    lines.append(f"Alerts investigated (distinct): {card.investigated}")
    if card.agreement_rate is None:
        lines.append(
            "Analyst rulings synced: 0 — no accuracy data yet. "
            "Run --sync-feedback after analysts work the TheHive queue."
        )
        return "\n".join(lines)
    lines.append(f"Ruled on by an analyst:         {card.ruled}")
    lines.append(
        f"Agreement:                      {card.agreements}/{card.ruled} "
        f"({card.agreement_rate:.0%})"
    )
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

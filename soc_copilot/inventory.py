"""Proposing environment context, without ever writing it.

The asset inventory is this project's trust anchor. `assets.py` says so
outright: alert content is attacker-influenced, so a prose claim of
legitimacy inside a log proves nothing, while the same claim in
`data/asset_context.json` is trusted BY PROVENANCE — the operator wrote
it. That single asymmetry is what lets the model cite "this is
sanctioned infrastructure" at all. The inventory's own header states the
other half of the contract: *the model may cite them but can never add
to them*, and *a stale entry that blesses a decommissioned scanner is an
attacker's best friend*.

So a feature that learns environment context has to be built to keep
that contract, not around it. This module mines the desk's record for
entities that keep turning up in alerts a HUMAN closed as false
positives, and emits **proposals**. It writes nothing. It cannot write
anything: `propose_entries` is a pure function over the store and a
loaded inventory dict, and the CLI prints its output.

Three rules do the work, and each one is a refusal.

- **Only analyst rulings count as evidence — never the copilot's own
  verdicts.** This is a stricter bar than any other report here, and the
  reason is circularity. Everywhere else, a copilot verdict is an
  opinion the operator can weigh. Here it would become an inventory
  entry, and the inventory is the one source the model is permitted to
  cite as authoritative about legitimacy. Learning from its own output
  would let the desk talk itself into trusting an asset, then cite that
  trust back at itself: exactly the naive learning loop that makes this
  roadmap item dangerous. A human closing the alert is what breaks the
  loop, and nothing else does. (It has a useful side effect: an
  injection-flagged alert can only contribute if a human ruled on it
  anyway, so the gate every other module needs explicitly is already
  implied here.)

- **The copilot proposes the ENTITY and the EVIDENCE. The operator
  writes the CLAIM.** `role` is not filled in, and that is not
  laziness — the role *is* the trust assertion. "authorized
  vulnerability scanner" is the sentence a future investigation will
  cite when it decides an authentication burst is routine, and nothing
  in the desk's record establishes it. What the record does establish is
  that this entity recurred in alerts humans dismissed, under these
  detections, with these closing notes. That is evidence for a decision,
  not the decision.

- **Recurrence must be recurrence.** Three sightings inside one burst is
  one event seen three times; the sightings have to span separate days
  before "this keeps happening" is a claim the data supports.

And one scoping rule carried over from the tuning report, where getting
it wrong was reproduced end to end: the window bounds the EVIDENCE, never
the disqualifier. An entity an analyst has ever confirmed in a true
positive is refused whatever `days` was passed, because an inventory
entry does not expire the way a report does — it will be consulted by
every future alert that names the entity.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .assets import HOST_KEYS
from .history import AlertHistoryStore
from .textsafe import one_line, sanitize_lines

# Sightings needed before an entity is worth an operator's attention.
MIN_SIGHTINGS = 3

# ...spread over at least this many distinct days. A scan window that
# fires twenty alerts in one hour is one occurrence, however many rows
# it leaves behind, and "recurring" has to mean it happened again.
MIN_DISTINCT_DAYS = 2

# Where an identifier was observed -> the inventory section that holds
# it. The mapping follows the OBSERVATION, not a guess about what the
# entity is; see `Proposal.caveat` for the one that matters.
_SECTIONS = (
    ("ips", "ips"),
    ("users", "service_accounts"),
)


@dataclass
class Proposal:
    """One entity the record says an operator should look at.

    Deliberately not an inventory entry: it carries no `role`, because
    the role is the trust assertion and the desk has not established it.
    """

    entity: str
    section: str                                    # hosts / ips / service_accounts
    sightings: list[str] = field(default_factory=list)      # ruled-FP alert ids
    days: set[str] = field(default_factory=set)             # distinct UTC dates
    detections: list[str] = field(default_factory=list)     # alert titles, deduped
    notes: list[str] = field(default_factory=list)          # analyst closing notes
    # Ruled true positives naming this entity, from the WHOLE store. Any
    # entry here refuses the proposal and is printed with it.
    confirmed_against: list[str] = field(default_factory=list)
    # Alerts of any verdict that name it — what an entry would reach.
    reach: int = 0
    already_inventoried: bool = False

    @property
    def recurs(self) -> bool:
        return (
            len(self.sightings) >= MIN_SIGHTINGS
            and len(self.days) >= MIN_DISTINCT_DAYS
        )

    @property
    def eligible(self) -> bool:
        return (
            self.recurs
            and not self.confirmed_against
            and not self.already_inventoried
        )

    @property
    def caveat(self) -> str | None:
        """The trap this particular section carries, or None.

        A section is chosen from where the identifier was observed, not
        from what the entity is, and for user accounts those two are
        routinely different things.
        """
        if self.section == "service_accounts":
            return (
                "the section follows where the identifier was observed. A "
                "PERSON's account recurring in dismissed alerts is a case "
                "for training or a detection change — not an inventory "
                "entry that blesses it as sanctioned automation"
            )
        if self.section == "ips":
            return (
                "an `ips` entry is only a pointer to a `hosts` entry; on "
                "its own it grants the bare role 'inventoried asset'"
            )
        return None


@dataclass
class InventoryProposals:
    proposals: list[Proposal] = field(default_factory=list)
    window_days: int | None = None
    rulings_considered: int = 0

    @property
    def eligible(self) -> list[Proposal]:
        return sorted(
            (p for p in self.proposals if p.eligible),
            key=lambda p: (-len(p.sightings), p.section, p.entity),
        )

    @property
    def refused(self) -> list[Proposal]:
        """Recurred often enough, and refused anyway — the rows worth
        reading, because each one is an entry someone might have written
        by hand."""
        return sorted(
            (p for p in self.proposals
             if p.recurs and p.confirmed_against and not p.already_inventoried),
            key=lambda p: (-len(p.sightings), p.entity),
        )

    @property
    def already_known(self) -> list[Proposal]:
        """Recurring, and the operator already has an entry — nothing to
        propose. Excludes the contradicted ones, which are not a
        reassurance (see `stale`)."""
        return sorted(
            (p for p in self.proposals
             if p.recurs and p.already_inventoried and not p.confirmed_against),
            key=lambda p: p.entity,
        )

    @property
    def stale(self) -> list[Proposal]:
        """Already inventoried, and an analyst has CONFIRMED a true
        positive on the same entity since.

        The inventory's own header names this the dangerous case: "a
        stale entry that blesses a decommissioned scanner is an
        attacker's best friend". Reporting it under "already in the
        inventory" read as reassurance about the one row that is the
        opposite of reassuring (review catch)."""
        return sorted(
            (p for p in self.proposals
             if p.already_inventoried and p.confirmed_against),
            key=lambda p: p.entity,
        )


def _entities(rec: dict) -> list[tuple[str, str]]:
    """(identifier, inventory section) pairs this record names, deduped.

    Typed access through the stored alert's own `indicators`, not the
    flattened `iocs` list, because the section depends on WHICH kind of
    indicator carried the value.

    Hostnames come from the same keys `assets.match_assets` reads, not
    just the one `history.alert_host` flattens: the matcher looks at
    `source_host` and `destination_host` too, so reading only `host`
    would leave this blind to entities an inventory entry WOULD match —
    which matters most in the disqualifying direction (review catch).

    Deduped per record, because a value that appears twice in one
    alert's indicators is one sighting. Counting it twice would let a
    single alert clear half of MIN_SIGHTINGS on its own, and an attacker
    who can repeat an indicator chooses how fast their host recurs.

    An identifier that is not a single printable line is dropped rather
    than normalized: a hostname containing a newline is not a hostname,
    and an inventory key derived from one would match nothing while
    reading, to an operator, exactly like one that would.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(value: object, section: str) -> None:
        if not isinstance(value, str) or not value or one_line(value) != value:
            return
        key = (value, section)
        if key not in seen:
            seen.add(key)
            out.append(key)

    alert = rec.get("alert")
    raw = alert.get("raw_log") if isinstance(alert, dict) else None
    if isinstance(raw, dict):
        for key in HOST_KEYS:
            value = raw.get(key)
            if isinstance(value, dict):
                value = value.get("name")
            add(value, "hosts")
    else:
        # A record written before the full alert dump existed carries only
        # the flattened host, and cannot be classified any further.
        add(rec.get("host"), "hosts")

    indicators = alert.get("indicators") if isinstance(alert, dict) else None
    if not isinstance(indicators, dict):
        return out
    for key, section in _SECTIONS:
        values = indicators.get(key)
        if not isinstance(values, list):
            continue
        for value in values:
            add(value, section)
    return out


def _day(rec: dict) -> str | None:
    """The UTC date the desk worked this alert, for the distinct-days
    test. Missing means the record predates `investigated_at`; it counts
    as a sighting but cannot support the recurrence claim."""
    raw = rec.get("investigated_at")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        when = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return when.astimezone(timezone.utc).date().isoformat() if when.tzinfo \
        else when.date().isoformat()


def _in_window(rec: dict, cutoff: datetime | None) -> bool:
    if cutoff is None:
        return True
    raw = rec.get("investigated_at")
    if not isinstance(raw, str) or not raw:
        return False
    try:
        when = datetime.fromisoformat(raw)
    except ValueError:
        return False
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when >= cutoff


def _inventoried(inventory: dict, entity: str, section: str) -> bool:
    known = inventory.get(section)
    if isinstance(known, dict) and entity in known:
        return True
    # A host already reachable through an `ips` pointer is inventoried
    # too — proposing it again would be noise about an entry that exists.
    if section == "ips":
        ips = inventory.get("ips")
        if isinstance(ips, dict) and entity in ips:
            return True
    return False


def propose_entries(
    store: AlertHistoryStore,
    inventory: dict | None = None,
    days: int | None = None,
    now: datetime | None = None,
) -> InventoryProposals:
    """Mine analyst-ruled false positives for entities worth an entry.

    Latest record per alert, as everywhere. The `days` window bounds the
    false-positive EVIDENCE only: the true-positive disqualifier and the
    reach count read the whole store, because an inventory entry is
    consulted by every future alert that names the entity and does not
    expire when a report's window does.
    """
    inventory = inventory or {}
    cutoff = None
    if days is not None:
        cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)

    latest: dict[str, dict] = {}
    for rec in store._iter_records():
        latest[rec["alert_id"]] = rec        # file order: last line wins

    rulings = store.dispositions()
    found: dict[tuple[str, str], Proposal] = {}

    def proposal(entity: str, section: str) -> Proposal:
        key = (entity, section)
        item = found.get(key)
        if item is None:
            item = found[key] = Proposal(
                entity=entity,
                section=section,
                already_inventoried=_inventoried(inventory, entity, section),
            )
        return item

    rulings_seen = 0
    for alert_id, rec in latest.items():
        entities = _entities(rec)
        ruling = rulings.get(alert_id)
        human = (ruling or {}).get("human_verdict")

        # Reach and the disqualifier read EVERY record, suppressed
        # duplicates included. A duplicate is a real alert that names the
        # entity, so an entry would have matched it; and since dedup only
        # ever borrows a FALSE-POSITIVE anchor, the one way a suppressed
        # record is a true positive is that a human ruled it one — which
        # is the strongest fact in the store about that entity. Skipping
        # these before reading the ruling is the same mistake the tuning
        # report shipped with, made again in a new module (review catch,
        # four lenses).
        for entity, section in entities:
            item = proposal(entity, section)
            item.reach += 1
            if human == "true_positive":
                item.confirmed_against.append(alert_id)   # never windowed

        if rec.get("duplicate_of"):
            # ...but a duplicate is not a separate SIGHTING. Its verdict
            # was borrowed from an anchor, so counting it would let one
            # benign event look like a pattern purely because dedup
            # fired, and the pattern is the whole claim being made here.
            continue
        if human != "false_positive":
            continue
        if not _in_window(rec, cutoff):
            continue
        # Counted after the window, so the rendered "N considered" is the
        # number that actually became evidence under the scope printed
        # beside it (review catch, five lenses).
        rulings_seen += 1
        title = rec.get("title")
        note = (ruling or {}).get("summary")
        day = _day(rec)
        for entity, section in entities:
            item = proposal(entity, section)
            item.sightings.append(alert_id)
            if day:
                item.days.add(day)
            # Prose, so normalized rather than dropped: these are quoted
            # back to the operator, and a title carrying newlines could
            # otherwise forge a row of the report.
            for value, bucket in ((title, item.detections), (note, item.notes)):
                if isinstance(value, str) and one_line(value) \
                        and one_line(value) not in bucket:
                    bucket.append(one_line(value))

    for item in found.values():
        item.confirmed_against = sorted(set(item.confirmed_against))

    return InventoryProposals(
        proposals=list(found.values()),
        window_days=days,
        rulings_considered=rulings_seen,
    )


def as_fragment(proposals: list[Proposal]) -> dict:
    """The eligible proposals shaped like `data/asset_context.json`, with
    the trust assertion left blank.

    `role`, `owner` and `notes` are placeholders an operator has to
    replace. That is the point: paste-ready would mean the desk had
    written the claim, and it has not — it has only shown that these
    identifiers keep appearing in alerts humans dismissed.
    """
    out: dict[str, dict] = {}
    for item in proposals:
        section = out.setdefault(item.section, {})
        if item.section == "ips":
            # An ips entry is a pointer; the operator says to which host.
            section[item.entity] = {"host": "TODO: hostname this address belongs to"}
            continue
        section[item.entity] = {
            "role": "TODO: what this is FOR (the operator's claim, not the desk's)",
            "owner": "TODO: team accountable for it",
            "notes": (
                f"Proposed from {len(item.sightings)} analyst-dismissed alert(s) "
                f"across {len(item.days)} day(s): "
                + "; ".join(item.detections[:3])
            ),
            "expected_activity": [],
        }
    return out


def render_proposals(result: InventoryProposals) -> str:
    """The operator's view. Every line is evidence or a refusal; the
    file is never touched."""
    import json

    window = (
        f"last {result.window_days} day(s)" if result.window_days is not None
        else "all recorded history"
    )
    lines = [
        "Environment-context proposals — evidence for entries YOU write",
        "",
        f"Scope: {window}. {result.rulings_considered} analyst-dismissed "
        f"alert(s) considered; the copilot's own verdicts are not evidence "
        f"here, and nothing below has been written to "
        f"data/asset_context.json.",
    ]

    if result.eligible:
        lines.append("")
        lines.append(
            f"CANDIDATES ({len(result.eligible)}) — recurred in "
            f"{MIN_SIGHTINGS}+ dismissed alerts across "
            f"{MIN_DISTINCT_DAYS}+ days:"
        )
        for item in result.eligible:
            lines.append("")
            lines.append(f"  {item.entity}   -> {item.section}")
            lines.append(
                f"    {len(item.sightings)} dismissal(s) over "
                f"{len(item.days)} day(s); names {item.reach} alert(s) in "
                f"all of history"
            )
            lines.append(f"    seen under: {'; '.join(item.detections[:3])}")
            for note in item.notes[:2]:
                lines.append(f'    analyst note: "{note}"')
            if item.caveat:
                lines.append(f"    ! {item.caveat}")
    else:
        lines.append("")
        lines.append(
            f"No entity recurs in {MIN_SIGHTINGS}+ analyst-dismissed alerts "
            f"across {MIN_DISTINCT_DAYS}+ days. That is the ordinary "
            f"answer on a small or young store."
        )

    if result.refused:
        lines.append("")
        lines.append(
            f"REFUSED ({len(result.refused)}) — recurred, and an analyst has "
            f"CONFIRMED a true positive on the same entity:"
        )
        for item in result.refused:
            lines.append(
                f"  {item.entity}: {len(item.sightings)} dismissal(s), but "
                f"confirmed in {', '.join(item.confirmed_against)}"
            )
            lines.append(
                "    an entry here would tell every future investigation "
                "this is sanctioned — on an entity the desk has already "
                "been wrong about once"
            )

    if result.stale:
        lines.append("")
        lines.append(
            f"STALE ENTRIES ({len(result.stale)}) — already in your "
            f"inventory, and an analyst has since CONFIRMED a true "
            f"positive on the same entity:"
        )
        for item in result.stale:
            lines.append(
                f"  {item.entity} ({item.section}): confirmed in "
                f"{', '.join(item.confirmed_against)}"
            )
            lines.append(
                "    the inventory's own header names this the dangerous "
                "case — an entry that blesses an asset the desk has been "
                "wrong about. Re-read it before the next alert cites it."
            )

    if result.already_known:
        lines.append("")
        lines.append(
            f"({len(result.already_known)} recurring entit"
            f"{'y is' if len(result.already_known) == 1 else 'ies are'} "
            f"already in the inventory: "
            f"{', '.join(p.entity for p in result.already_known)})"
        )

    if result.eligible:
        lines.append("")
        lines.append(
            "Paste-ready? No — deliberately. `role` is the sentence a "
            "future investigation will cite to call activity routine, and "
            "nothing in this record establishes it. Fill in the TODOs:"
        )
        lines.append(json.dumps(as_fragment(result.eligible), indent=2))
    return "\n".join(sanitize_lines(lines))

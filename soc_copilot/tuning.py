"""What the desk learned about the DETECTIONS, not about the alerts.

The scorecard measures the copilot against the analysts. This measures
the *detections* against reality: which rules spend analyst attention on
nothing, which confirmed compromises arrived ranked as routine, and —
where the evidence supports it — the one entity an exception could
safely be written around. That is the step from consuming detections to
contributing to them.

Deterministic Python over the history store: no API, no network, no
model. A document that recommends narrowing a sensor is exactly the
artifact you do not want an LLM authoring.

**A tuning report is a proposal to make a sensor blind**, and that
framing sets every rule below.

- **The two directions are not symmetric.** Quieting a detection can
  lose an attack; raising one costs attention. So the quieting
  direction is gated — a minimum firing count, a high false-positive
  threshold, named blockers — and the loudening direction (a confirmed
  true positive that arrived as `low`) is reported with no threshold at
  all. One confirmed compromise ranked as routine is a finding.

- **Volume is never the finding.** A rule that fires constantly and is
  constantly right is a good rule having a bad week. The finding needs
  the false-positive *rate*, and a rate needs a denominator worth
  quoting — hence MIN_FIRINGS.

- **Analyst rulings outrank the copilot's verdicts**, here as
  everywhere. A rule's rate is reported with how much of it a human
  actually confirmed, so nobody tunes a production sensor on the
  strength of an LLM's opinion without knowing that is what they are
  doing.

- **Injection-flagged content earns no vote — in one direction.** This
  feature is the obvious channel for talking a SOC into switching off
  the detection that sees you: generate alerts, get them called benign,
  collect a recommendation to except your own infrastructure. So a
  record whose investigation flagged an injection attempt in untrusted
  content contributes no false-positive evidence — unless a human ruled
  on it, because a human ruling is ground truth and this project defers
  to it everywhere else. It still contributes its TRUE-positive
  evidence: see `build_tuning_report`, where getting that asymmetry
  wrong handed the attacker the switch instead of taking it away.

  The flag is investigation-scoped, not alert-scoped — `copilot.py`
  raises it for alert content, for tool output, and for titles replayed
  from memory. That deliberately over-triggers, and over-triggering is
  safe here in a way it would not have been in the first draft: an
  exclusion now only removes false-positive evidence, so the most an
  attacker gains by planting injection text anywhere in the enrichment
  path is a QUIETER report.

- **An exception is checked against the rule's own true positives.**
  The entity shared by every false positive is usually the scanner, the
  backup account, the patch server — and if that same entity also
  appears in an alert this rule caught for real, excepting it would
  have hidden that alert. The report says so and refuses the
  recommendation rather than quietly ranking it second. Refused
  candidates are printed whether or not a safe one was found, because
  "we also considered your build host and would not" is the sentence an
  operator needs before writing a rule exception by hand.

- **The window picks the detections; it never scopes the safety.**
  `--tuning-report DAYS` bounds which detections are in the report and
  the volume figures inside it. Everything the report then SAYS about a
  listed detection — its blockers, the true positives an exception is
  checked against, the alias map, the confirmed techniques — reads the
  whole store. An exception is a permanent change to a sensor and must
  not get easier to recommend because the operator typed a smaller
  number.

The scope boundary, stated rather than blurred: this reports on
detections that FIRED. It cannot see an attack that no rule caught, and
absence of alerts is not evidence of coverage. There is no detection
inventory in this repo to diff against, so nothing here is an ATT&CK
coverage map — the technique table at the end is a record of what this
desk confirmed, which is a different claim.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .history import AlertHistoryStore
from .scorecard import build_scorecard

# Below this many firings a rate is noise about noise: 2-for-2 is not a
# 100% false-positive rule, it is two alerts. Groups under the floor are
# counted and named, never turned into a recommendation.
MIN_FIRINGS = 5

# ...and the two floors are not the same floor. Firings count every
# alert the rule raised, INCLUDING near-duplicates the desk suppressed
# without judging; this one counts the judgments the rate is actually
# computed from. Without it a rule that fired 40 times, 39 of them
# suppressed as repeats of one investigated alert, reads as "100% false
# positive over 40 firings" on the strength of a single verdict — the
# volume floor cleared, the denominator still one.
MIN_EVIDENCE = 2

# How false a detection has to look before the report will say so.
NOISE_THRESHOLD = 0.8

# Severities at which a confirmed true positive is under-ranked.
_ROUTINE_SEVERITIES = ("low", "medium")

# Anything that is not printable-on-one-line. C0/C1 controls (which
# includes ESC, so an alert title cannot drive the operator's terminal)
# plus every flavour of whitespace.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_RUNS = re.compile(r"\s+")

# Enough for a Kibana rule name; short enough that one row stays one row.
_MAX_NAME = 120


def one_line(value: str) -> str:
    """Collapse a string to a single printable line.

    Detection names, IOCs, hostnames and alert ids all reach this report
    from alert content, which this project treats as hostile everywhere
    else. Unescaped, a title carrying newlines emits extra lines that
    are indistinguishable from the report's own — the review reproduced
    one alert forging a whole "NOISY DETECTIONS" section, complete with
    a fabricated count, a fabricated analyst basis and a fabricated
    exception recommendation for the attacker's own address.
    """
    return _RUNS.sub(" ", _CONTROL.sub(" ", value)).strip()

# Where a source records the identity of the rule that fired, most
# specific first. An explicit allowlist, like assets.py's host keys and
# elastic.py's ECS paths: each entry is a shape some real source writes,
# and anything else falls back to the alert title rather than being
# guessed at. Only STRING values are accepted, so a probe that lands on
# a container (ECS's `rule` object) declines instead of stringifying it.
_RULE_PATHS = (
    "detection.rule_name",   # what elastic.py normalize_hit writes
    "detection.rule",
    "detection_rule",        # native fixture spelling
    "signal.rule.name",      # pre-8.x Elastic signals
    "rule.name",
    "rule_name",
    "rule",
)


def _dig(doc: dict, path: str):
    """Follow a dotted path through nested dicts; None if it doesn't
    resolve or runs into a non-dict on the way."""
    node = doc
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def detection_of(rec: dict) -> tuple[str, str]:
    """(name, provenance) for the detection behind one record.

    Provenance is "rule" when the source named the rule itself and
    "title" when the name is derived from the alert title. It is part of
    the GROUP KEY, not a label on the group: a title-keyed record and a
    rule-keyed record never share a row even when the strings match, so
    an alert title can never merge into a named rule's counts or borrow
    its credibility.

    What remains is fragmentation, and that is the safe direction on
    purpose. Kibana falls back to `kibana.alert.reason`, which is
    templated with entity values, so every firing becomes its own
    "detection", every group lands under MIN_FIRINGS, and no
    recommendation is made. A fragmented key hides noise; a conflated
    one invents it, and only one of those two mistakes can make a SOC
    blind.

    The name is collapsed to one printable line here rather than only at
    render time, because it is a key: nothing downstream — a future JSON
    export, a log line — should have to remember that this string came
    from alert content.
    """
    alert = rec.get("alert")
    raw = alert.get("raw_log") if isinstance(alert, dict) else None
    if isinstance(raw, dict):
        for path in _RULE_PATHS:
            value = _dig(raw, path)
            if isinstance(value, str) and one_line(value):
                return one_line(value), "rule"
    title = rec.get("title")
    if isinstance(title, str) and one_line(title):
        return one_line(title), "title"
    return "(unnamed detection)", "title"


def _entities(rec: dict) -> set[str]:
    """Every identifier this record could carry an exception for: the
    host, the alert's IOCs, and the inventory entries they matched.

    Inventory names are included beside the observed entity so an IP and
    the host it resolves to are both candidates — the operator writes
    the exception in whichever vocabulary their rule speaks.
    """
    out: set[str] = set()
    host = rec.get("host")
    if isinstance(host, str) and host:
        out.add(host)
    for ioc in rec.get("iocs") or ():
        if isinstance(ioc, str) and ioc:
            out.add(ioc)
    inv = rec.get("investigation")
    matches = inv.get("asset_matches") if isinstance(inv, dict) else None
    for match in matches or ():
        if not isinstance(match, dict):
            continue
        for key in ("entity", "name"):
            value = match.get(key)
            if isinstance(value, str) and value:
                out.add(value)
    return out


def _inventory_roles(rec: dict) -> dict[str, str]:
    """entity/name -> the sanctioned role the operator's inventory gives
    it. The inventory is trusted by provenance (see assets.py); an
    exception candidate the operator already documented is the one worth
    proposing first."""
    roles: dict[str, str] = {}
    inv = rec.get("investigation")
    matches = inv.get("asset_matches") if isinstance(inv, dict) else None
    for match in matches or ():
        if not isinstance(match, dict):
            continue
        role = match.get("role")
        if not isinstance(role, str) or not role:
            continue
        for key in ("entity", "name"):
            value = match.get(key)
            if isinstance(value, str) and value:
                roles.setdefault(value, role)
    return roles


class _AliasMap:
    """Which identifiers name the SAME asset.

    The operator's inventory says an IP belongs to a host, so an alert
    that matched by IP and one that matched by hostname are talking
    about one machine. Without that, the true-positive check below is
    trivially bypassable — and was: in this feature's first smoke run
    the scanner's IP was correctly refused for appearing in a confirmed
    true positive, and the report went on to recommend excepting
    `scanner-01`, the same box under its inventory name, with the words
    "no true positive on this detection has involved it". A record only
    carries the aliases the inventory matched FOR IT, so one alert
    naming the machine by IP and another by hostname is the ordinary
    case, not the exotic one.

    Union-find, built from every record in the store and deliberately
    greedy: two identifiers that ever appeared as the entity and name of
    one inventory match stay linked, across detections. Over-linking can
    only refuse an exception that might have been fine; under-linking
    recommends blinding a sensor to an asset it has already caught
    something on.
    """

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def _root(self, item: str) -> str:
        self._parent.setdefault(item, item)
        while self._parent[item] != item:
            self._parent[item] = self._parent[self._parent[item]]
            item = self._parent[item]
        return item

    def link(self, a: str, b: str) -> None:
        ra, rb = self._root(a), self._root(b)
        if ra != rb:
            # Lexicographic, not insertion order: the report must not
            # change with the order records happen to sit in the file.
            self._parent[max(ra, rb)] = min(ra, rb)

    def names(self, entity: str, entities: set[str]) -> bool:
        """Does any of `entities` name the same asset as `entity`?"""
        root = self._root(entity)
        return any(self._root(e) == root for e in entities)


def _learn_aliases(rec: dict, aliases: _AliasMap) -> None:
    """Link the identifiers an inventory match gives one asset. Read
    from EVERY record, whatever its verdict — that an IP belongs to a
    host is a fact about the environment, not about the alert."""
    inv = rec.get("investigation")
    matches = inv.get("asset_matches") if isinstance(inv, dict) else None
    for match in matches or ():
        if not isinstance(match, dict):
            continue
        entity, name = match.get("entity"), match.get("name")
        if (
            isinstance(entity, str) and entity
            and isinstance(name, str) and name
        ):
            aliases.link(entity, name)


def _has_injection(rec: dict) -> bool:
    inv = rec.get("investigation")
    flags = inv.get("injection_flags") if isinstance(inv, dict) else None
    return bool(flags)


def _escalated(rec: dict) -> bool:
    inv = rec.get("investigation")
    return bool(inv.get("escalation_recommended")) if isinstance(inv, dict) else False


def _severity(rec: dict) -> str | None:
    alert = rec.get("alert")
    sev = alert.get("severity") if isinstance(alert, dict) else None
    return sev if isinstance(sev, str) else None


@dataclass
class ExceptionCandidate:
    """An entity present in EVERY false positive a detection produced —
    the shape of the exception an operator would write.

    `blinded` is the safety gate: alert ids of that same detection's
    true positives which also carry this entity. Non-empty means writing
    the exception would have hidden one, so the candidate is refused and
    shown, not silently dropped to second place.
    """

    entity: str
    role: str | None            # inventory role, when the operator wrote one
    shared_by: int              # false positives carrying it (all of them)
    blinded: list[str] = field(default_factory=list)
    # Of `blinded`, the ones an analyst ruled true positive. The rest are
    # the copilot's own verdict — still disqualifying (an exception is
    # forever; an unconfirmed hit is not nothing), but the report must not
    # call an unruled verdict a confirmed catch.
    blinded_confirmed: list[str] = field(default_factory=list)

    @property
    def safe(self) -> bool:
        return not self.blinded


@dataclass
class Detection:
    """One detection's record on this desk. Lists, not counts, because
    every number here should be able to name its alerts."""

    name: str
    provenance: str                                        # "rule" | "title"
    firings: list[str] = field(default_factory=list)       # distinct alerts
    suppressed: list[str] = field(default_factory=list)    # dedup'd repeats
    injection_excluded: list[str] = field(default_factory=list)
    # admissible == fp + tp + inconclusive, always. The three exclusions
    # above (suppressed, injection-flagged, out of window) are the only
    # ways a firing leaves that identity, and each one is counted.
    admissible: list[str] = field(default_factory=list)    # the evidence pool
    fp: list[str] = field(default_factory=list)            # effective verdict
    tp: list[str] = field(default_factory=list)
    inconclusive: list[str] = field(default_factory=list)
    ruled: list[str] = field(default_factory=list)         # human ground truth
    analyst_backed_fp: list[str] = field(default_factory=list)
    escalated: list[str] = field(default_factory=list)
    # Of `fp`: closed by policy, so no analyst ever opened them. They are
    # desk cost, not analyst attention, and the ranking says which it is
    # measuring (review catch).
    fp_auto_closed: list[str] = field(default_factory=list)
    # --- counter-evidence: whole-store, never windowed, never excluded.
    # These can name alerts that are NOT in `firings` — an exception is a
    # permanent change to a sensor, so what the rule has caught is not
    # scoped to the window the operator asked about.
    ruled_tp: list[str] = field(default_factory=list)
    overturned_fp: list[str] = field(default_factory=list)
    under_ranked: list[str] = field(default_factory=list)  # ruled TP, low/med
    # technique -> the analyst-ruled true positives that mapped it.
    technique_alerts: dict[str, set[str]] = field(default_factory=dict)
    exception: ExceptionCandidate | None = None
    refused: list[ExceptionCandidate] = field(default_factory=list)

    @property
    def fp_rate(self) -> float | None:
        """None (not 0.0) with nothing admissible: an empty denominator
        is 'no evidence', never 'this rule is clean'."""
        if not self.admissible:
            return None
        return len(self.fp) / len(self.admissible)

    @property
    def analyst_attention(self) -> int:
        """False positives a human actually opened. An autonomously
        closed alert cost the desk a model call and cost the analyst
        nothing, so it does not belong in a count of what to tune for
        their sake."""
        return len(self.fp) - len(self.fp_auto_closed)

    @property
    def blockers(self) -> list[str]:
        """Why this detection must not simply be turned down. Stated
        beside the rate, never averaged into it."""
        out: list[str] = []
        if self.ruled_tp:
            out.append(
                f"caught {len(self.ruled_tp)} analyst-confirmed true "
                f"positive(s): {', '.join(sorted(self.ruled_tp))}"
            )
        if self.overturned_fp:
            out.append(
                f"the copilot's false-positive call was OVERTURNED on "
                f"{len(self.overturned_fp)} alert(s) "
                f"({', '.join(sorted(self.overturned_fp))}) — its unruled "
                f"verdicts on this rule are not reliable evidence"
            )
        return out

    @property
    def is_noisy(self) -> bool:
        rate = self.fp_rate
        return (
            rate is not None
            and rate >= NOISE_THRESHOLD
            and len(self.firings) >= MIN_FIRINGS
            and len(self.admissible) >= MIN_EVIDENCE
        )

    @property
    def below_floor(self) -> bool:
        """Looks false, but on too little: too few firings, too few
        judgments behind the rate, or both. Reported as a watchlist
        entry — which is what "we do not know yet" looks like — never as
        a recommendation."""
        rate = self.fp_rate
        return rate is not None and rate >= NOISE_THRESHOLD and not self.is_noisy


@dataclass
class TuningReport:
    detections: list[Detection] = field(default_factory=list)
    window_days: int | None = None
    records_considered: int = 0
    undated_excluded: int = 0     # no investigated_at, so no window slot

    @property
    def noisy(self) -> list[Detection]:
        """Worst first, measured in false positives an analyst actually
        opened — not in rate, because a 100%-false rule that fired 6
        times costs less than a 90%-false rule that fired 400, and not
        in raw false positives, because a rule whose output the desk
        closes by itself costs model spend rather than analyst time
        (review catch: the first version claimed the former and counted
        the latter)."""
        return sorted(
            (d for d in self.detections if d.is_noisy),
            key=lambda d: (-d.analyst_attention, -len(d.fp), d.name),
        )

    @property
    def watchlist(self) -> list[Detection]:
        return sorted(
            (d for d in self.detections if d.below_floor),
            key=lambda d: (-len(d.firings), d.name),
        )

    @property
    def under_ranked(self) -> list[Detection]:
        return sorted(
            (d for d in self.detections if d.under_ranked),
            key=lambda d: (-len(d.under_ranked), d.name),
        )

    @property
    def confirmed_techniques(self) -> list[tuple[str, int, list[str]]]:
        """(technique, confirmed alerts, detections that surfaced it),
        from analyst-ruled true positives only, over the whole store for
        each detection the report lists. A record of what this desk has
        confirmed — NOT a coverage map (see module docstring).
        """
        counts: dict[str, set[str]] = {}
        sources: dict[str, set[str]] = {}
        for det in self.detections:
            for technique, alerts in det.technique_alerts.items():
                counts.setdefault(technique, set()).update(alerts)
                sources.setdefault(technique, set()).add(det.name)
        return sorted(
            (
                (t, len(alerts), sorted(sources[t]))
                for t, alerts in counts.items()
            ),
            key=lambda row: (-row[1], row[0]),
        )


def _effective_verdict(rec: dict, ruling: dict | None) -> str | None:
    """The analyst's ruling when there is one, else the copilot's own
    verdict. Ground truth outranks opinion, here as everywhere."""
    if ruling and isinstance(ruling.get("human_verdict"), str):
        return ruling["human_verdict"]
    verdict = rec.get("verdict")
    return verdict if isinstance(verdict, str) else None


def _in_window(rec: dict, cutoff: datetime | None) -> bool | None:
    """True/False against the window, or None when the record carries no
    investigated_at to place it with (counted separately, never silently
    treated as recent)."""
    if cutoff is None:
        return True
    raw = rec.get("investigated_at")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        when = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when >= cutoff


def build_tuning_report(
    store: AlertHistoryStore,
    days: int | None = None,
    now: datetime | None = None,
) -> TuningReport:
    """Group the desk's record by the detection that produced it.

    Latest record per alert (an alert investigated three times is one
    firing, judged on the verdict that stood). Suppressed near-duplicates
    count as FIRINGS — they are real alerts the rule raised, and volume
    is what noise means — but never as false-positive evidence, because
    their verdict was borrowed from an anchor rather than formed about
    them.

    Two rules make this loop harder to read than a single pass would be,
    and both are load-bearing. The adversarial review found each one by
    reproducing the failure, and they are the same failure twice:
    something that was supposed to remove EVIDENCE removed the
    COUNTER-evidence with it.

    1. **Nothing suppresses a true positive.** The exclusions —
       suppressed duplicate, injection-flagged, out of window — say a
       record cannot argue that a rule is noisy. None of them says the
       rule never caught anything, so every record still contributes its
       true-positive evidence: to the blockers, to the under-ranked
       list, and above all to `tp_entities`, the set the exception
       safety gate is checked against. The first draft `continue`d
       before the verdict was read, and the consequence was the exact
       inversion of this module's stated purpose: an injection flag
       comes from attacker-influenced content, so PLANTING injection
       text in the alert that would otherwise block the exception was
       what earned the exception. Five review lenses found it
       independently.

    2. **The window scopes the noise, never the safety.** `days` answers
       "what is costing us lately", so it bounds firings, the rate and
       the recommendation. It must not bound "has this rule ever caught
       something real": an exception is a permanent change to a sensor,
       and the review reproduced the same store flipping from NO SAFE
       EXCEPTION to a clean recommendation purely by passing the
       documented DAYS argument. Blockers, true-positive entities, the
       alias map and the confirmed-technique table therefore read the
       WHOLE store, and only the volume side is windowed.
    """
    cutoff = None
    if days is not None:
        cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)

    # Latest record per alert over the WHOLE store — the window is applied
    # per alert below, so an alert is judged on its genuinely latest
    # record rather than on the last one that happened to fall inside the
    # window.
    latest: dict[str, dict] = {}
    aliases = _AliasMap()
    for rec in store._iter_records():
        # rec["alert_id"], not rec.get(): every other reader of this store
        # does the same, so a malformed line fails the same loud way here
        # as in the scorecard and the digest rather than being quietly
        # dropped from exactly the report an operator opens to look at
        # their own data.
        latest[rec["alert_id"]] = rec  # file order: last line wins
        # Every record, not just the surviving latest one and not just
        # the in-window ones: that an IP belongs to a host is a fact
        # about the environment, and a superseded record can be the only
        # place the inventory recorded it.
        _learn_aliases(rec, aliases)

    rulings = store.dispositions()
    # Autonomous closures that still STAND, by alert id. Reused from the
    # scorecard rather than re-derived, exactly as the digest does: it
    # already decides which closures were overtaken by later human work.
    # These are the alerts that cost the desk model spend and no analyst
    # attention at all, which is the distinction this report's ranking
    # claims to make.
    unattended = build_scorecard(store).auto_closed_ids

    groups: dict[str, Detection] = {}
    # Entity sets per detection, kept beside the group so the exception
    # search never has to re-walk the store. True positives carry their
    # alert id and whether a human confirmed them: the refusal message
    # has to name the alert an exception would have hidden.
    fp_entities: dict[str, list[set[str]]] = {}
    tp_entities: dict[str, list[tuple[str, bool, set[str]]]] = {}
    roles: dict[str, dict[str, str]] = {}

    considered = 0
    undated = 0
    for alert_id, rec in latest.items():
        name, provenance = detection_of(rec)
        key = (name, provenance)
        det = groups.get(key)
        if det is None:
            det = groups[key] = Detection(name=name, provenance=provenance)
            fp_entities[key], tp_entities[key], roles[key] = [], [], {}

        ruling = rulings.get(alert_id)
        verdict = _effective_verdict(rec, ruling)

        # --- counter-evidence: unconditional, whatever else this record
        # --- is disqualified from saying.
        if verdict == "true_positive":
            tp_entities[key].append((alert_id, bool(ruling), _entities(rec)))
            if ruling:
                det.ruled_tp.append(alert_id)
                # A suppressed record's own verdict is the anchor's,
                # borrowed; an overturn of it indicts that anchor's
                # judgment on this rule, which is the thing the blocker
                # is about.
                if rec.get("verdict") == "false_positive":
                    det.overturned_fp.append(alert_id)
                if _severity(rec) in _ROUTINE_SEVERITIES:
                    det.under_ranked.append(alert_id)
                for technique in rec.get("attack_techniques") or ():
                    if isinstance(technique, str) and technique:
                        det.technique_alerts.setdefault(
                            technique, set()
                        ).add(alert_id)

        placed = _in_window(rec, cutoff)
        if placed is None:
            undated += 1
            continue
        if not placed:
            continue
        considered += 1

        # --- volume and rate: windowed, and subject to the exclusions.
        det.firings.append(alert_id)
        suppressed = bool(rec.get("duplicate_of"))
        if suppressed:
            det.suppressed.append(alert_id)
        # A TRUE POSITIVE IS NEVER EXCLUDED. Every exclusion here exists
        # to stop a record arguing that a rule is NOISY; a true positive
        # argues the opposite, so dropping it from the denominator makes
        # the rule look worse than it is. Getting this half wrong is how
        # the first version let attacker text manufacture a finding
        # outright: leaving the numerator and shrinking the denominator
        # took 7 false positives against 3 true positives from 70% (not
        # reported) to 88% (reported) with nothing changed but an
        # injection string planted in two of the true positives.
        if verdict != "true_positive":
            if suppressed:
                continue
            if _has_injection(rec) and not ruling:
                det.injection_excluded.append(alert_id)
                continue

        det.admissible.append(alert_id)
        if _escalated(rec):
            det.escalated.append(alert_id)
        if ruling:
            det.ruled.append(alert_id)

        if verdict == "false_positive":
            det.fp.append(alert_id)
            if ruling:
                det.analyst_backed_fp.append(alert_id)
            if alert_id in unattended:
                det.fp_auto_closed.append(alert_id)
            fp_entities[key].append(_entities(rec))
            roles[key].update(_inventory_roles(rec))
        elif verdict == "true_positive":
            det.tp.append(alert_id)
        else:
            det.inconclusive.append(alert_id)

    for key, det in groups.items():
        det.exception, det.refused = _exception_candidates(
            fp_entities[key], tp_entities[key], roles[key], aliases
        )

    return TuningReport(
        # A group with no in-window firings exists only to carry its
        # blockers into a sibling row; it is not itself a detection this
        # window saw, and listing it would report a rule as having fired
        # zero times.
        detections=sorted(
            (d for d in groups.values() if d.firings),
            key=lambda d: (d.name, d.provenance),
        ),
        window_days=days,
        records_considered=considered,
        undated_excluded=undated,
    )


def _exception_candidates(
    fp_sets: list[set[str]],
    tp_sets: list[tuple[str, bool, set[str]]],
    roles: dict[str, str],
    aliases: _AliasMap,
) -> tuple[ExceptionCandidate | None, list[ExceptionCandidate]]:
    """The entities shared by EVERY false positive, split into the safe
    recommendation and the refused ones.

    Present-in-all, not present-in-most: an entity missing from even one
    false positive does not explain the noise, and an exception written
    around it leaves the rest firing while opening a hole. When a
    detection has several unrelated benign causes there is no universal
    entity and the report says so — which is the true answer.

    The two halves use different notions of identity, on purpose.
    Finding candidates is a LITERAL intersection: an entity has to be
    written the same way in every false positive to be proposed, so a
    thin alias chain can only cost a recommendation that might have been
    made. Refusing them goes through the alias map: a candidate is
    disqualified when a true positive names the same asset ANY way at
    all. Aliasing must never cost a refusal.

    The check is scoped to THIS detection's own true positives, because
    that is where the exception would be written — but never to the
    reporting window, which bounds only what the report calls noisy. It
    is not a claim that the entity is harmless anywhere else.
    """
    if not fp_sets:
        return None, []
    shared = set.intersection(*fp_sets)
    if not shared:
        return None, []

    candidates: list[ExceptionCandidate] = []
    for entity in sorted(shared):
        # `aliases.names`, not `entity in ents`: an exception written for
        # a host silences the alerts that named its IP too.
        blinded = [
            aid for aid, _, ents in tp_sets if aliases.names(entity, ents)
        ]
        candidates.append(
            ExceptionCandidate(
                entity=entity,
                role=roles.get(entity),
                shared_by=len(fp_sets),
                blinded=sorted(blinded),
                blinded_confirmed=sorted(
                    aid for aid, ruled, ents in tp_sets
                    if ruled and aliases.names(entity, ents)
                ),
            )
        )
    # Inventory-known entities first (the operator already documented the
    # role, so the exception is defensible), then alphabetical so the
    # report is stable run to run.
    candidates.sort(key=lambda c: (c.role is None, c.entity))
    safe = next((c for c in candidates if c.safe), None)
    return safe, [c for c in candidates if not c.safe]


def _pct(value: float) -> str:
    return f"{value:.0%}"


def _short(name: str) -> str:
    return name if len(name) <= _MAX_NAME else name[: _MAX_NAME - 1] + "…"


def _sanitize(lines: list[str]) -> list[str]:
    """Apply one_line to every emitted line, preserving indentation.

    Done at the single point of emission rather than at each of the
    dozen interpolation sites: a field added to this report later cannot
    reopen the hole by forgetting to escape itself.
    """
    out = []
    for line in lines:
        indent = len(line) - len(line.lstrip(" "))
        out.append(" " * indent + one_line(line))
    return out


def render_tuning_report(report: TuningReport) -> str:
    """Human-readable tuning advice for the CLI."""
    window = (
        f"last {report.window_days} day(s)"
        if report.window_days is not None
        else "all recorded history"
    )
    lines = [
        "SOC copilot detection tuning report — what the sensors cost and caught",
        "",
        f"Scope: {window} — {report.records_considered} alert(s) across "
        f"{len(report.detections)} detection(s).",
    ]
    if report.window_days is not None:
        lines.append(
            "  (The window picks the detections and the volume figures. "
            "What a detection has CAUGHT — its blockers, the true "
            "positives an exception is checked against, the techniques — "
            "is read from the whole store.)"
        )
    if report.undated_excluded:
        lines.append(
            f"  ({report.undated_excluded} alert(s) carry no "
            f"investigated_at, so nothing places them in the window; they "
            f"still count against an exception.)"
        )
    derived = sum(1 for d in report.detections if d.provenance == "title")
    if derived:
        lines.append(
            f"  ({derived} detection(s) are keyed by ALERT TITLE — the "
            f"source did not name a rule. Title-keyed and rule-keyed "
            f"records never share a row, so a title cannot merge into a "
            f"named rule's numbers.)"
        )

    if not report.detections:
        lines.append("")
        lines.append("Nothing investigated yet — no detection has a record.")
        return "\n".join(_sanitize(lines))

    bar = (
        f"{_pct(NOISE_THRESHOLD)}+ false positive, over {MIN_FIRINGS}+ "
        f"firings and {MIN_EVIDENCE}+ judged alerts"
    )
    lines.append("")
    if report.noisy:
        lines.append(f"NOISY DETECTIONS ({len(report.noisy)}) — {bar}:")
        for det in report.noisy:
            lines.extend(_render_noisy(det))
    else:
        lines.append(f"No detection meets the noise bar ({bar}).")

    if report.watchlist:
        lines.append("")
        lines.append(
            f"WATCHLIST ({len(report.watchlist)}) — looks false on too "
            f"little to say so, so no recommendation:"
        )
        for det in report.watchlist:
            lines.append(
                f"  {_short(det.name)}: {len(det.fp)}/{len(det.admissible)} "
                f"false positive over {len(det.firings)} firing(s)"
            )

    if report.under_ranked:
        lines.append("")
        lines.append(
            "UNDER-RANKED — analyst-confirmed true positives that arrived "
            "as low/medium (no volume threshold: one is a finding):"
        )
        for det in report.under_ranked:
            lines.append(
                f"  {_short(det.name)}: {len(det.under_ranked)} confirmed "
                f"true positive(s) at routine severity — "
                f"{', '.join(sorted(det.under_ranked))}"
            )
            lines.append("    -> raise this detection's severity or risk score")

    techniques = report.confirmed_techniques
    if techniques:
        lines.append("")
        lines.append(
            "CONFIRMED TECHNIQUES — what the detections above actually "
            "caught, analyst-ruled, over the whole store. A record of what "
            "fired, NOT a coverage map: this cannot see an attack no rule "
            "detected."
        )
        for technique, count, sources in techniques:
            lines.append(
                f"  {technique}: {count} confirmed via "
                f"{', '.join(_short(s) for s in sources)}"
            )

    return "\n".join(_sanitize(lines))


def _render_noisy(det: Detection) -> list[str]:
    rate = det.fp_rate
    unruled = len(det.fp) - len(det.analyst_backed_fp)
    basis = (
        f"{len(det.analyst_backed_fp)} confirmed by an analyst, "
        f"{unruled} the copilot's own call"
    )
    lines = [
        "",
        f"  {_short(det.name)}"
        + ("" if det.provenance == "rule" else "   [key derived from title]"),
        f"    {len(det.fp)}/{len(det.admissible)} false positive "
        f"({_pct(rate)}) over {len(det.firings)} firing(s) — {basis}",
    ]
    if det.fp_auto_closed:
        # The ranking is by analyst attention, so say when the two
        # numbers differ: a rule whose output the desk closes by itself
        # is a spend problem, not an alert-fatigue problem.
        lines.append(
            f"    {det.analyst_attention} of those false positives reached "
            f"an analyst; {len(det.fp_auto_closed)} were closed "
            f"autonomously (desk cost, not analyst time)"
        )
    if det.suppressed:
        lines.append(
            f"    {len(det.suppressed)} of those firings were near-duplicates "
            f"the desk suppressed without investigating"
        )
    if det.injection_excluded:
        lines.append(
            f"    {len(det.injection_excluded)} firing(s) excluded from the "
            f"false-positive evidence: the investigation flagged a "
            f"prompt-injection attempt in untrusted content and no human "
            f"has ruled on it"
        )
    for blocker in det.blockers:
        lines.append(f"    ! {blocker}")

    if det.exception:
        role = f" — inventory: {det.exception.role}" if det.exception.role else ""
        lines.append(
            f"    -> every one of those {det.exception.shared_by} false "
            f"positives involves {det.exception.entity}{role}"
        )
        lines.append(
            "       scope an exception to it rather than turning the rule "
            "down: no true positive on this detection has involved it"
        )
    elif not det.refused:
        lines.append(
            "    -> no single entity is present in every false positive: "
            "this rule's noise has more than one cause, so there is no one "
            "exception to write"
        )

    # Refusals print whether or not a safe candidate was found. When both
    # exist the safe one needs the caveat MORE, not less: the alias map
    # only links identifiers the operator's inventory put together, so a
    # host and its own address are unrelated strings to it, and "safe"
    # can mean "we could not tell it was the same box" (review catch —
    # the first version hid every refusal behind `elif`).
    if det.refused:
        headline = "ALSO CONSIDERED AND REFUSED" if det.exception else (
            "NO SAFE EXCEPTION"
        )
        lines.append(f"    -> {headline}:")
        for candidate in det.refused:
            confirmed = (
                f", analyst-confirmed: {', '.join(candidate.blinded_confirmed)}"
                if candidate.blinded_confirmed else ""
            )
            lines.append(
                f"       {candidate.entity} — shared by all "
                f"{candidate.shared_by} false positives, but this detection "
                f"returned a true positive on "
                f"{', '.join(candidate.blinded)}{confirmed}"
            )
        if det.exception:
            lines.append(
                f"       Confirm {det.exception.entity} is not another name "
                f"for one of those before writing the exception."
            )
    return lines

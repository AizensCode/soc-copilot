"""From a verdict to a to-do list: typed containment actions.

Every other output of this copilot is something to READ. This one is
shaped like a command — `block_ip 185.220.101.47` — and that changes
what it has to prove before it says anything.

So the same rule as everywhere, applied harder: **the model does not
author actions.** It supplies a verdict and an ATT&CK mapping; a pure
function here turns those, plus the enrichment payloads the tools
returned, into a typed action with a named target and a rationale that
carries its own identifier. There is no path by which a sentence in an
alert becomes an instruction to block an address.

Nothing in this module executes anything, and nothing in this repo
does. These are proposals for a human. The roadmap's policy-gated
execution slice is deliberately NOT here: the gates below are written
as if it were, because that is the only way to find out whether they
hold, but the boundary is stated rather than blurred.

**The failure that matters is not a missed action; it is a confident
wrong one.** An analyst who does not get a suggestion loses a few
minutes. An analyst who blocks the address of their own patch mirror,
or disables the service account that runs backups, has caused the
outage themselves — with the copilot's name on it. Every gate below is
sized by that asymmetry:

- **Only a true positive proposes anything.** Not inconclusive: "I am
  not sure" is a reason to look, never a reason to act. And not at
  `low` confidence, which is the same sentence said differently.

- **An injection-flagged investigation proposes nothing at all.** This
  is the sharpest version of the attack this project keeps closing. An
  attacker who can talk the triager into `block_ip` on a CDN edge, a
  DNS resolver, or a payment gateway has a denial-of-service primitive
  aimed at the defender, executed by the defender. Content that tries
  to steer the desk is disqualified from producing anything actionable,
  exactly as it is in `closure.py` and `routing.py`.

- **The operator's inventory can stop an action, never start one.** A
  target the inventory knows is not thereby innocent — the scanner box
  is exactly the machine an attacker wants — so an inventoried target
  does not silence the action. It moves it to `needs_approval` with the
  owner's name attached, which is the difference between a list an
  analyst can work through and a list they can execute in bulk.

- **Refusals are printed.** A withheld action says why. An operator who
  cannot see that the desk considered blocking 10.0.0.5 and declined
  will consider it themselves, without the reason.

The grounding is deliberately uneven, and says so per action via
`basis`, because an operator reading a list of commands deserves to know
which is which:

- `reputation` — `block_ip`, `block_domain`, `block_hash`. External
  ground truth about the target itself, which holds whatever this alert
  turns out to be.
- `technique` — `isolate_host`, `disable_account`, `reset_credentials`,
  `revoke_oauth_grant`. The investigation's ATT&CK mapping, which is a
  model judgment: the same ground `history.correlate` stands on for its
  `shared_technique` signal, but weaker than reputation, and it says
  what this investigation CONCLUDED rather than what is true of the
  target.
- `analysis` — `quarantine_email`. A deterministic analyzer's own
  finding (`phishing.py`), which is neither of the other two.

The inventory gate below works through the `AssetMatch` entries attached
to this investigation, which `assets.match_assets` produces for IPs,
hosts, service accounts and SaaS apps. It is the reach of that matcher,
not of the inventory file: a target the matcher never matched cannot be
gated by it, and `mail_senders` in particular is read by `phishing.py`
and not by the asset matcher — which is why `quarantine_email` consults
the phishing analysis for that record instead.
"""
import ipaddress
from dataclasses import dataclass

from .history import alert_host
from .models import (
    Alert,
    AssetMatch,
    Evidence,
    Investigation,
    ResponseAction,
)
from .textsafe import sanitize_lines

# Confidence levels at which the desk will propose containment at all.
# `low` is excluded deliberately: a low-confidence true positive is an
# alert that still needs a human to look, and a to-do list is not that.
_ACTIONABLE_CONFIDENCE = ("high", "medium")

# --- reputation bars -------------------------------------------------
#
# These are read from the tool payload (`Evidence.raw_data`), NOT from
# `Evidence.confidence`, and the reason is worth recording: the agentic
# path converts every tool result through one generic converter that
# hardcodes `confidence="medium"` (copilot.py `_tool_result_to_evidence`).
# Gating on the graded confidence would therefore have made containment
# structurally impossible in agentic mode while working in phase one —
# the asymmetric-wiring hole this project has been bitten by before.
# The payload is identical on both paths, so the payload is the ground.
#
# The numbers match what the phase-one converters already grade as
# `high`, and `test_the_action_bar_agrees_with_the_desks_own_high_grade`
# holds them to that rather than trusting this comment.
ABUSE_CONFIDENCE_BAR = 75          # copilot._ip_result_to_evidence: high
VT_MALICIOUS_RATIO_BAR = 0.5       # copilot._hash_result_to_evidence: high

# The domain bar is deliberately STRICTER than the converter's `high`,
# which is any non-zero `malicious_scan_count`. That grade is a fine
# thing to show an analyst and a bad thing to aim a block with: the
# count is taken over at most the twenty most recent scans URLScan
# returns, so "1 of 20 pages someone scanned under this domain was
# flagged" is a statement about a page, not about the domain. This
# repo's own recorded cassette is the argument — `bit.ly` and
# `lucidchart.com` both sit at 10,000 total scans, and lucidchart is the
# SANCTIONED app in the benign OAuth fixture.
URLSCAN_MALICIOUS_RATIO_BAR = 0.5  # of the scans actually returned

# ...and above this much scan history a domain is shared infrastructure
# whatever its ratio says, so a human decides. The same role
# `isWhitelisted` plays for addresses, from a weaker signal — hence
# needs_approval rather than a refusal. Grounded in the corpus: every
# attacker domain in the cassette records 0 scans, sqlmap.org 138,
# bit.ly and lucidchart.com 10,000.
POPULAR_DOMAIN_SCANS = 100

# Principals that cannot be disabled in the sense the action means: the
# local system authorities, and machine accounts (a trailing `$`).
# Proposing to disable one is either a no-op or an outage, and it is the
# ordinary content of a Windows alert — `user.name` on a scheduled-task
# or service event is routinely SYSTEM.
_UNDISABLEABLE_ACCOUNTS = frozenset({
    "system", "local service", "network service", "anonymous logon",
    "local system", "nt authority\\system", "nt authority\\local service",
    "nt authority\\network service", "nt authority\\anonymous logon",
})

# Above this many accounts, an account action is a mass action. A
# password spray names every username it tried, and disabling all of
# them is precisely the outage the spray was hoping for — so the desk
# says which accounts it saw and refuses to aim at all of them at once.
MAX_ACCOUNT_TARGETS = 3

# Actions whose target is a user principal, and which therefore go
# through the two guards above.
_ACCOUNT_ACTIONS = ("disable_account", "reset_credentials")

# Technique families that justify each non-reputation action. Matched on
# the parent technique, so T1059.001 counts as T1059 — the same
# convention `history._parent_tcodes` uses for correlation.
_TECHNIQUE_ACTIONS: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    (
        "isolate_host", "host",
        ("T1486", "T1059", "T1053", "T1547", "T1543", "T1055", "T1490"),
        "code ran, persisted, or destroyed data on this host",
    ),
    (
        "disable_account", "users",
        ("T1078", "T1098", "T1136"),
        "the account itself was the vehicle",
    ),
    (
        "reset_credentials", "users",
        ("T1110", "T1003", "T1555", "T1552", "T1621"),
        "the credential was attacked or exposed",
    ),
    (
        "revoke_oauth_grant", "apps",
        ("T1528", "T1550"),
        "a delegated authorization is the standing access",
    ),
)

# raw_data key naming the entity each tool's payload is ABOUT. Binding an
# Evidence entry to a target through the payload's own subject field —
# never by looking for the string inside the prose `claim` — is what
# keeps "this reputation belongs to that address" a fact rather than a
# match.
_SUBJECT_KEYS = ("ipAddress", "hash", "domain")


@dataclass(frozen=True)
class _Reputation:
    """One tool payload, bound to its subject."""

    subject: str
    tool: str
    data: dict


def _parents(techniques: list[str]) -> set[str]:
    """Technique ids reduced to their parent ('T1059.001' -> 'T1059')."""
    out: set[str] = set()
    for tech in techniques or ():
        if isinstance(tech, str) and tech:
            out.add(tech.split(".")[0].strip().upper())
    return out


def _reputations(evidence: list[Evidence]) -> list[_Reputation]:
    """Every successful enrichment payload that names what it is about.

    A failed lookup contributes nothing: it is the absence of a fact, and
    `Evidence.success` exists precisely so the autonomous paths can tell
    the two apart (see models.Evidence).
    """
    out: list[_Reputation] = []
    for item in evidence or ():
        if not item.success:
            continue
        for key in _SUBJECT_KEYS:
            subject = item.raw_data.get(key)
            if isinstance(subject, str) and subject:
                out.append(
                    _Reputation(
                        subject=subject, tool=item.source_tool, data=item.raw_data
                    )
                )
                break
    return out


def _blockable_ip(rep: _Reputation) -> tuple[bool, str | None]:
    """(does the reputation justify blocking, reason it does not).

    Two refusals matter more than the score. A non-globally-routable
    address is not something a perimeter can block — an RFC1918 entry in
    a blocklist either does nothing or takes out an internal range. And
    AbuseIPDB's own whitelist marks the infrastructure that gets reported
    constantly and must never be blocked: public resolvers, major CDNs.
    A high score on a whitelisted address is the shape of exactly the
    self-inflicted outage this module exists to avoid.
    """
    score = rep.data.get("abuseConfidenceScore")
    if not isinstance(score, (int, float)) or score < ABUSE_CONFIDENCE_BAR:
        return False, None
    try:
        parsed = ipaddress.ip_address(rep.subject)
    except ValueError:
        return False, f"{rep.subject} is not an address this can act on"
    if not parsed.is_global:
        return False, (
            f"{rep.subject} scores {score:g}/100 but is not globally "
            f"routable — a perimeter block would not reach it; contain the "
            f"host instead"
        )
    if rep.data.get("isWhitelisted"):
        return False, (
            f"{rep.subject} scores {score:g}/100 but is on AbuseIPDB's "
            f"whitelist (shared infrastructure such as a public resolver "
            f"or CDN edge) — blocking it would be an outage of your own"
        )
    return True, None


def _inventory_index(matches: list[AssetMatch]) -> dict[str, AssetMatch]:
    """entity/name -> the inventory entry, for stopping an action on
    operator-owned infrastructure."""
    index: dict[str, AssetMatch] = {}
    for match in matches or ():
        if not isinstance(match, AssetMatch):
            continue
        for value in (match.entity, match.name):
            if isinstance(value, str) and value:
                index.setdefault(value, match)
    return index


def _targets(alert: Alert, kind: str) -> list[str]:
    """The entities of one kind this alert names, in a stable order."""
    if kind == "host":
        host = alert_host(alert)
        return [host] if host else []
    values = alert.indicators.get(kind)
    # `indicators` is a free-form dict, so guard the container as well as
    # the elements — `history.alert_iocs` guards the same shape, and a
    # scalar string here would iterate one action per character.
    if not isinstance(values, list):
        return []
    return [v for v in values if isinstance(v, str) and v]


def _undisableable(target: str) -> str | None:
    """Why this principal cannot be the subject of an account action, or
    None if it can."""
    name = target.strip().lower()
    if name in _UNDISABLEABLE_ACCOUNTS:
        return (
            f"{target} is a local system authority, not an account that "
            f"can be disabled — the alert names it because that is who the "
            f"activity ran as"
        )
    if target.strip().endswith("$"):
        return (
            f"{target} is a machine account; disabling it removes the "
            f"computer from the domain rather than containing a user"
        )
    return None


def propose_actions(
    alert: Alert, investigation: Investigation
) -> list[ResponseAction]:
    """The containment steps this investigation justifies, plus the ones
    it considered and refused.

    Pure: no network, no store, no model. Deterministic in the alert and
    the investigation, so the same inputs always produce the same list in
    the same order — a to-do list that reshuffles between runs is one an
    analyst stops trusting.
    """
    if investigation.verdict != "true_positive":
        return []
    if investigation.confidence not in _ACTIONABLE_CONFIDENCE:
        return []
    inventory = _inventory_index(investigation.asset_matches)
    reputations = _reputations(investigation.evidence)
    actions: list[ResponseAction] = []

    def add(
        action: str, target: str, basis: str, rationale: str,
        evidence: list[str] | None = None, withheld: str | None = None,
        caution: str | None = None,
    ) -> None:
        if withheld:
            actions.append(
                ResponseAction(
                    action=action, target=target, status="withheld",
                    basis=basis, rationale=withheld,
                    evidence=evidence or [],
                )
            )
            return
        asset = inventory.get(target)
        if asset:
            # An inventoried target is not innocent — it is exactly what
            # an attacker wants to be standing on — so this slows the
            # action down instead of dropping it.
            rationale = f"{rationale}. Operator inventory: {asset.role}"
        if caution:
            rationale = f"{rationale}. {caution}"
        actions.append(
            ResponseAction(
                action=action,
                target=target,
                status="needs_approval" if (asset or caution) else "proposed",
                basis=basis,
                rationale=rationale,
                evidence=evidence or [],
                owner=asset.owner if asset else None,
                inventory_role=asset.role if asset else None,
            )
        )

    # --- reputation-grounded: true about the target, not just this alert.
    # The target must still be something the ALERT named. On the agentic
    # path the model chooses what to look up, and it can reach an entity
    # it found inside a tool response — untrusted content picking the
    # target of a command. Evidence about such an entity is still
    # reported; it just does not become an aimed action without a human
    # noticing that the target came from outside the alert.
    named = set(_targets(alert, "ips") + _targets(alert, "hashes")
                + _targets(alert, "domains"))
    for rep in reputations:
        if rep.subject not in named:
            continue
        if "abuseConfidenceScore" in rep.data:
            ok, refusal = _blockable_ip(rep)
            score = rep.data.get("abuseConfidenceScore")
            if ok:
                add("block_ip", rep.subject, "reputation",
                    f"{rep.subject} has abuse confidence {score:g}/100 "
                    f"({rep.data.get('totalReports', 0)} reports)",
                    [rep.tool])
            elif refusal:
                add("block_ip", rep.subject, "reputation", "", [rep.tool],
                    withheld=refusal)
        elif "hash" in rep.data and rep.data.get("found"):
            mal = rep.data.get("malicious_count") or 0
            total = rep.data.get("total_engines") or 0
            if total and mal / total >= VT_MALICIOUS_RATIO_BAR:
                add("block_hash", rep.subject, "reputation",
                    f"{rep.subject} is flagged malicious by {mal}/{total} "
                    f"engines", [rep.tool])
        elif "domain" in rep.data and rep.data.get("found"):
            mal = rep.data.get("malicious_scan_count") or 0
            sampled = rep.data.get("scans_returned") or 0
            total = rep.data.get("total_scans") or 0
            if not sampled or mal / sampled < URLSCAN_MALICIOUS_RATIO_BAR:
                continue
            add("block_domain", rep.subject, "reputation",
                f"{rep.subject} had {mal} of the {sampled} most recent "
                f"URLScan scans flagged malicious", [rep.tool],
                caution=(
                    f"This domain carries {total} scans on record — that is "
                    f"shared infrastructure, and a block reaches everyone "
                    f"who uses it, not just this alert"
                    if total >= POPULAR_DOMAIN_SCANS else None
                ))

    # --- technique-grounded: true about this investigation's reading
    parents = _parents(investigation.attack_techniques)
    for action, kind, families, why in _TECHNIQUE_ACTIONS:
        hit = sorted(parents & set(families))
        if not hit:
            continue
        targets = _targets(alert, kind)
        why = f"{why} — this investigation mapped {', '.join(hit)}"
        if action in _ACCOUNT_ACTIONS and len(targets) > MAX_ACCOUNT_TARGETS:
            # A spray names every username it tried. Acting on all of them
            # is the outage the spray was after, and the desk does not
            # know which one actually authenticated — so it says what it
            # saw and refuses to aim (review catch).
            for target in targets:
                add(action, target, "technique", "", withheld=(
                    f"{action} not aimed: this alert names {len(targets)} "
                    f"accounts, which is a spray rather than a compromised "
                    f"identity. Establish which one authenticated first — "
                    f"acting on all of them is the outage the spray wanted"
                ))
            continue
        for target in targets:
            if action in _ACCOUNT_ACTIONS:
                blocked = _undisableable(target)
                if blocked:
                    add(action, target, "technique", "", withheld=blocked)
                    continue
            add(action, target, "technique", why)

    # --- analysis-grounded: a deterministic analyzer's own finding
    phishing = investigation.phishing
    if phishing and any(s.strength == "strong" for s in phishing.signals):
        _add_quarantine(phishing, add)

    if investigation.injection_flags:
        # Computed first, then withheld — rather than returning early —
        # so the operator sees WHAT was suppressed, not just that
        # something was. This is the sharpest form of the attack the
        # project keeps closing: content that tries to steer the triager
        # does not get to aim it. An empty list stays empty; nothing here
        # invents an action in order to refuse it.
        where = investigation.injection_flags[0].location
        count = len(investigation.injection_flags)
        return [
            # An action the gates ALREADY refused keeps its own reason.
            # Rewriting it said "it would otherwise have been proposed
            # because <the refusal>", which reads the desk's own veto back
            # as an endorsement — a whitelisted CDN reported as something
            # only injection stopped us blocking. Four lenses found that
            # inversion; it was introduced by the fix that added this
            # branch in the first place.
            action if action.status == "withheld" else action.model_copy(update={
                "status": "withheld",
                "rationale": (
                    f"Withheld: this investigation carries {count} "
                    f"prompt-injection attempt(s) in untrusted content "
                    f"(first at {where}). It would otherwise have been "
                    f"proposed because {action.rationale}"
                ),
            })
            for action in _dedupe(actions)
        ]

    return _dedupe(actions)


def _add_quarantine(phishing, add) -> None:
    """Aim a quarantine at the sender — but only when there IS one.

    This is the trap the adversarial review found, and it is a good one:
    the strong signals that justify the action are, in the ordinary case,
    exactly the signals establishing that the From: address was NOT
    authenticated. `dmarc_fail` and `no_aligned_authentication` are
    statements that nothing vouched for the domain the recipient saw. So
    the first version aimed the action at the impersonated party — spoof
    the finance director and the desk proposes quarantining the finance
    director's own address.

    The envelope address is no better as a fallback: it is chosen by the
    sending client, it is a bare DOMAIN rather than an address (see
    models.PhishingAnalysis), and it is a *different* entity from the one
    the cited signals are about — so the rationale would describe a
    target it was not about. Naming a high-volume sanctioned relay there
    costs the attacker one SMTP command.

    So the action is aimed only at an address an authenticated identifier
    ALIGNS with, which is the same discipline `phishing.py` applies
    before matching the operator's `mail_senders` record: "only
    authenticated identifiers may be matched." When nothing authenticated
    the From:, the action is withheld and says so — which is a more
    useful sentence than a confident wrong target.
    """
    strong = sorted(s.name for s in phishing.signals if s.strength == "strong")
    why = (
        f"the header analysis graded {len(strong)} signal(s) strong "
        f"({', '.join(strong[:3])})"
    )
    sender = phishing.header_from
    aligned = (
        (phishing.spf_aligned and phishing.spf_result == "pass")
        or (phishing.dkim_aligned and phishing.dkim_result == "pass")
    )
    if not sender:
        return
    if not aligned:
        add("quarantine_email", sender, "analysis", "", withheld=(
            f"Not aimed at {sender}: {why}, and those signals say nothing "
            f"authenticated that address. Acting on it would act on the "
            f"impersonated party, not the sender — the envelope domain is "
            f"where attribution actually points"
        ))
        return
    # An authenticated, aligned sender the operator has on record as a
    # sanctioned bulk sender is a conversation, not a quarantine.
    sanctioned = next(
        (s for s in phishing.signals if s.name == "sanctioned_bulk_sender"),
        None,
    )
    add("quarantine_email", sender, "analysis", why, caution=(
        f"The operator's inventory records this sender: {sanctioned.fact}"
        if sanctioned else None
    ))


def _dedupe(actions: list[ResponseAction]) -> list[ResponseAction]:
    """One entry per (action, target), strongest status first, then a
    stable order.

    A withheld entry loses to a real one on the same target: if any
    grounding justifies the action, "we declined" is no longer the whole
    story and printing both would read as the desk contradicting itself.
    """
    rank = {"proposed": 0, "needs_approval": 1, "withheld": 2}
    best: dict[tuple[str, str], ResponseAction] = {}
    for item in actions:
        key = (item.action, item.target)
        current = best.get(key)
        if current is None or rank[item.status] < rank[current.status]:
            best[key] = item
    return sorted(
        best.values(),
        key=lambda a: (rank[a.status], a.action, a.target),
    )


def render_actions(actions: list[ResponseAction]) -> str:
    """The CLI view. Empty string when there is nothing to contain, so a
    false positive prints no heading at all.

    Every emitted line goes through `sanitize_lines`, because targets are
    alert content: a username carrying newlines could otherwise emit a
    `block_ip` line indistinguishable from one the desk recommended. That
    is the same bug the tuning report shipped with one increment earlier,
    which is why the helper now lives in `textsafe.py` instead of being
    written a third time.
    """
    live = [a for a in actions if a.status != "withheld"]
    withheld = [a for a in actions if a.status == "withheld"]
    if not actions:
        return ""
    lines = ["Response actions (proposals — nothing here is executed):"]
    for item in live:
        flag = "  [NEEDS OWNER APPROVAL]" if item.status == "needs_approval" else ""
        lines.append(f"  {item.action} {item.target}{flag}")
        lines.append(f"      why: {item.rationale} [{item.basis}]")
        if item.owner:
            lines.append(f"      owner: {item.owner}")
    if not live:
        lines.append("  (none proposed)")
    for item in withheld:
        lines.append(f"  WITHHELD {item.action} {item.target}")
        lines.append(f"      {item.rationale}")
    return "\n".join(sanitize_lines(lines))

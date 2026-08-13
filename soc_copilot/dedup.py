"""Near-duplicate suppression — not spending the LLM twice on the same thing.

SOC volume is not uniform: it is a handful of genuinely new situations
plus the same detections firing again and again — the nightly scanner
burst, the recurring brute-force from a blocked IP, the scheduled job
that trips the same rule every morning. Each repeat currently costs a
full LLM investigation. This module detects, deterministically and
before any model call, that an incoming alert is a near-duplicate of one
the copilot recently investigated, and reuses that conclusion at zero
marginal cost.

Suppression is an autonomous decision (choosing NOT to look), so it gets
the same treatment as autonomous closure: a pure, gate-heavy policy where
every gate is spelled out, opt-in at the CLI (`--watch --dedup`), and a
reason string recorded for the audit trail.

THE FINGERPRINT IS THE WHOLE SAFETY ARGUMENT. It must match a genuine
benign repeat while differing on any *materially* different event — and
"the auth finally SUCCEEDED" is the material difference that matters most
(it is the entire distance between "brute force attempted" and "brute
force succeeded"). So the fingerprint is content-aware: it hashes the
alert's stable identity (source, severity, title, host, sorted IOCs)
PLUS a signature of the raw log's SEMANTIC fields — every string/bool
leaf (outcome, username, process, command line, action) — while dropping
what genuinely varies between identical repeats: numeric leaves (counts,
byte totals, ports), timestamps, and the digits inside free-text message
fields. An outcome flip, a new process, a different user, an escalated
severity therefore all break the match; a changed attempt-count does not.
An early allowlist-only version of this fingerprint (identity fields but
no raw-log content) was cut in review: it let a successful-login alert
collide with the benign failed-login anchor and suppress the compromise
unexamined.

Further gates, each failing toward a fresh human-reachable investigation:

- A conclusion is borrowed only from an anchor the copilot could have
  acted on alone: high-confidence false positive, no escalation, no
  injection flags on the anchor — and never a fingerprint an analyst has
  overturned ANYWHERE in its history (not just on the chosen anchor).
- The NEW alert is injection-scanned FIRST: hostile content never
  suppresses, whatever it matches.
- Suppressed records never anchor, so the window is measured from the
  last REAL investigation — a repeat is re-investigated at full depth at
  least once per window.
- A hard suppression cap forces a real investigation after
  MAX_CONSECUTIVE_SUPPRESSIONS reuses of one fingerprint, independent of
  the alert's own (attacker-influenceable) timestamps — the deterministic
  backstop against an unbounded suppressed stream.
- An alert whose own id already has a real investigation on record is
  never suppressed: a retry after a push failure re-investigates rather
  than discarding the verdict it already paid for.
"""
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

from .history import AlertHistoryStore, alert_host, alert_iocs
from .injection import scan_for_injection
from .models import Alert, Investigation, Telemetry

DEFAULT_WINDOW_HOURS = 24
# After this many consecutive suppressions of one fingerprint (since its
# last real investigation), force a fresh look regardless of the window —
# a timestamp-independent bound on how long the copilot will keep reusing
# a conclusion without re-examining the environment.
MAX_CONSECUTIVE_SUPPRESSIONS = 25
HYPOTHESIS_EXCERPT = 600

# raw_log leaf keys that hold a human-readable rendering of fields also
# present structurally; their embedded digits (counts, ports, times) vary
# between identical repeats, so their digits are neutralized rather than
# the whole field dropped — the words ("Accepted"/"Failed") still count.
_FREETEXT_KEYS = {
    "message", "msg", "description", "note", "notes", "summary",
    "details", "detail", "raw", "log", "reason", "text",
}
_NUMERIC_RE = re.compile(r"^[+-]?\d+(?:[.,]\d+)?$")
_ISO_RE = re.compile(r"^\d{4}-\d\d-\d\d[t ]", re.IGNORECASE)
_DROP = object()  # sentinel: this leaf is volatile, leave it out


def _digits_out(text: str) -> str:
    return re.sub(r"\d+", "#", text)


def _signature(node: object, key: str | None = None) -> object:
    """A canonical structure of only the SEMANTIC (non-volatile) content of
    `node`. Numeric leaves, timestamps, and numeric-string leaves drop out;
    string/bool leaves survive; free-text leaves survive with digits
    neutralized; lists are order-normalized. Returns _DROP when nothing
    survives, so a subtree of pure volatility contributes nothing."""
    if isinstance(node, bool):
        return node
    if isinstance(node, (int, float)) or node is None:
        return _DROP
    if isinstance(node, str):
        if key is not None and key.lower() in _FREETEXT_KEYS:
            return _digits_out(node)
        stripped = node.strip()
        if _NUMERIC_RE.match(stripped) or _ISO_RE.match(stripped):
            return _DROP
        return node
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            r = _signature(v, k)
            if r is not _DROP:
                out[k] = r
        return out or _DROP
    if isinstance(node, list):
        items = [r for r in (_signature(v, key) for v in node) if r is not _DROP]
        if not items:
            return _DROP
        # Order-independent: two bursts that list the same usernames in a
        # different order are the same detection.
        return sorted(items, key=lambda x: json.dumps(x, sort_keys=True))
    return _DROP


def fingerprint(alert: Alert) -> str:
    """A stable identity for 'this same detection, these same entities,
    describing the same kind of event'. Built from flattened identity
    fields plus a semantic signature of the raw log (see _signature).
    The raw_log 'host' key is left to alert_host so the native and ECS
    host shapes agree on that field; the rest of raw_log is shape-specific
    and only ever compared within one source pipeline."""
    raw = alert.raw_log if isinstance(alert.raw_log, dict) else {}
    content = _signature({k: v for k, v in raw.items() if k != "host"})
    identity = {
        "source": alert.source,
        "severity": alert.severity,
        "title": alert.title,
        "host": alert_host(alert),
        "iocs": sorted(alert_iocs(alert)),
        "content": None if content is _DROP else content,
    }
    canonical = json.dumps(identity, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _alert_from_record(rec: dict) -> Alert | None:
    """Reconstruct the Alert a history record was written for, so the SAME
    fingerprint() runs over it — no second implementation to drift. Returns
    None for records that predate full-alert storage or won't parse."""
    raw = rec.get("alert")
    if not isinstance(raw, dict):
        return None
    try:
        return Alert(**raw)
    except Exception:
        return None


def _record_fingerprint(rec: dict) -> str | None:
    alert = _alert_from_record(rec)
    return fingerprint(alert) if alert is not None else None


def _has_real_record(store: AlertHistoryStore, alert_id: str) -> bool:
    """True if this alert_id already has a non-suppressed investigation on
    record — it was really worked, so a re-arrival (e.g. a retry after a
    failed push) must not be suppressed and have that verdict discarded."""
    for rec in store._iter_records():
        if rec["alert_id"] == alert_id and not rec.get("duplicate_of"):
            return True
    return False


def _fingerprint_overturned(
    store: AlertHistoryStore, fp: str
) -> str | None:
    """The alert_id of any record sharing this fingerprint whose analyst
    ruling is NOT a false positive — a documented correction on exactly
    this detection, wherever in its history it landed (on the original
    anchor OR on a suppressed duplicate the analyst happened to work).
    Blocks suppression from either direction."""
    rulings = store.dispositions()
    if not rulings:
        return None
    for rec in store._iter_records():
        ruling = rulings.get(rec["alert_id"])
        if not ruling:
            continue
        if ruling.get("human_verdict") == "false_positive":
            continue
        if _record_fingerprint(rec) == fp:
            return rec["alert_id"]
    return None


def find_anchor(
    store: AlertHistoryStore,
    alert: Alert,
    window_hours: int = DEFAULT_WINDOW_HOURS,
    now: datetime | None = None,
) -> tuple[dict | None, int]:
    """The most recent REAL (non-suppressed) investigation of this same
    fingerprint within the window, plus the number of suppressions charged
    against it since. Returns (anchor, suppressions_since) — anchor is None
    when there is no in-window real investigation to borrow from.

    Windowed on investigated_at ('we recently spent money on exactly
    this'), never the alert's own timestamp. Suppressed records are never
    anchors, so copies cannot extend the window the original earned."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=window_hours)
    fp = fingerprint(alert)

    anchor: dict | None = None
    anchor_at: datetime | None = None
    for rec in store._iter_records():
        if rec["alert_id"] == alert.alert_id:
            continue
        if rec.get("duplicate_of"):
            continue
        investigated_at = rec.get("investigated_at")
        if not investigated_at:
            continue
        when = datetime.fromisoformat(investigated_at)
        if when < cutoff:
            continue
        if _record_fingerprint(rec) != fp:
            continue
        anchor, anchor_at = rec, when  # file order: latest matching wins

    if anchor is None:
        return None, 0

    # Count suppressions of this fingerprint charged since the anchor was
    # investigated — the cap is measured from the last real look.
    suppressions = 0
    for rec in store._iter_records():
        if not rec.get("duplicate_of"):
            continue
        investigated_at = rec.get("investigated_at")
        if not investigated_at:
            continue
        if datetime.fromisoformat(investigated_at) < anchor_at:
            continue
        if _record_fingerprint(rec) == fp:
            suppressions += 1
    return anchor, suppressions


def should_suppress(anchor: dict, ruling: dict | None) -> tuple[bool, str]:
    """May this anchor's conclusion be reused without a fresh look?

    The bar is the closure policy's, applied to the ANCHOR: only a
    conclusion the copilot could have acted on alone is safe to borrow.
    Campaign correlation is deliberately NOT a gate here — a same-
    fingerprint 'campaign' is a recurring benign family (a real campaign
    spans DIFFERENT alerts, which never share this fingerprint and are
    never suppressed); the volume backstop is the suppression cap, not the
    correlator. Returns (decision, reason) either way, for the audit
    trail."""
    inv = anchor.get("investigation", {})

    if ruling and ruling.get("human_verdict") != "false_positive":
        return False, (
            f"analyst ruled the anchor {anchor['alert_id']} "
            f"'{ruling.get('human_verdict')}' — a documented correction on "
            f"exactly this detection; every repeat gets a fresh look"
        )
    if anchor.get("verdict") != "false_positive":
        return False, (
            f"anchor verdict is {anchor.get('verdict')}; only a "
            f"false-positive conclusion may be reused without a fresh look"
        )
    if anchor.get("confidence") != "high":
        return False, (
            f"anchor confidence is {anchor.get('confidence')}; reuse "
            f"requires high"
        )
    if inv.get("escalation_recommended"):
        return False, "anchor recommended escalation"
    if inv.get("injection_flags"):
        return False, "anchor carried injection flags"
    # The anchor's blind spots are inherited by anything that borrows its
    # conclusion. Without this the closure gate is VACUOUS on the whole
    # dedup path: the suppressed copy carries no evidence of its own (it
    # looked nothing up, and says so), so an anchor the policy REFUSED to
    # close for failed lookups would be closed by its own duplicate half an
    # hour later — under a reason string asserting the clean investigation
    # that never happened (review catch, two lenses).
    blind = sorted({
        e.get("source_tool", "?")
        for e in inv.get("evidence") or []
        if e.get("success") is False   # absent on pre-field records: answered
    })
    if blind:
        return False, (
            f"anchor's investigation had {len(blind)} failed enrichment "
            f"lookup(s) ({', '.join(blind)}); a conclusion reached without "
            f"the evidence it asked for is not one to reuse unexamined"
        )

    ruled = " (analyst-confirmed)" if ruling else ""
    return True, (
        f"near-duplicate of {anchor['alert_id']} investigated "
        f"{anchor.get('investigated_at', '?')}: high-confidence false "
        f"positive{ruled} with no escalation or injection signals"
    )


def build_suppressed_investigation(
    alert: Alert,
    anchor: dict,
    reason: str,
    store: AlertHistoryStore,
) -> Investigation:
    """The zero-cost record of a suppressed repeat.

    Borrows the anchor's conclusion (verdict, confidence, techniques) and
    says so plainly, carrying duplicate_of so nothing downstream mistakes
    it for fresh analysis. It records prior_sightings (cheap, honest,
    useful context) but NOT a fresh campaign correlation: a suppressed
    copy is not an investigation, so attaching a campaign verdict to it —
    one derived partly from the alert's own attacker-influenceable
    timestamp — would be dishonest and was the wrong volume backstop. The
    suppression cap is the backstop; this stays a faithful 'we reused
    anchor X' marker."""
    inv = anchor.get("investigation", {})
    hypothesis = (
        f"Suppressed as a near-duplicate: {reason}. "
        f"No new model investigation was run; the anchor's hypothesis: "
        f"{inv.get('hypothesis', '')[:HYPOTHESIS_EXCERPT]}"
    )
    tel = inv.get("telemetry") or {}
    return Investigation(
        alert_id=alert.alert_id,
        verdict=anchor["verdict"],
        confidence=anchor["confidence"],
        hypothesis=hypothesis,
        attack_techniques=list(anchor.get("attack_techniques", [])),
        escalation_recommended=False,
        duplicate_of=anchor["alert_id"],
        prior_sightings=store.prior_sightings(alert),
        correlation=None,
        injection_flags=[],
        telemetry=Telemetry(
            model=tel.get("model", ""),
            cost_usd=0.0,
            duration_seconds=0.0,
        ),
    )


def try_suppress(
    store: AlertHistoryStore,
    alert: Alert,
    window_hours: int,
    now: datetime | None = None,
) -> tuple[Investigation, str] | None:
    """The whole pipeline: scan, guard, match, gate, build. Returns the
    recorded suppressed Investigation and the reason, or None when the
    alert deserves (or requires) a real investigation.

    Order matters and is part of the safety argument:
    1. Injection scan on the NEW alert — hostile content never suppresses.
    2. Already-investigated guard — never discard a verdict already paid
       for (retry after a failed push re-investigates).
    3. Anchor + suppression-cap lookup.
    4. Fingerprint-wide analyst-overturn block.
    5. The anchor reuse gates.
    """
    if scan_for_injection(alert):
        return None
    if _has_real_record(store, alert.alert_id):
        return None
    anchor, suppressions = find_anchor(store, alert, window_hours, now=now)
    if anchor is None:
        return None
    if suppressions >= MAX_CONSECUTIVE_SUPPRESSIONS:
        return None
    overturned_id = _fingerprint_overturned(store, fingerprint(alert))
    if overturned_id is not None:
        return None
    ruling = store.dispositions().get(anchor["alert_id"])
    suppress, reason = should_suppress(anchor, ruling)
    if not suppress:
        return None
    investigation = build_suppressed_investigation(alert, anchor, reason, store)
    store.record(alert, investigation)
    return investigation, reason

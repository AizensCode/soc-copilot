"""Tiered model routing: a cheap first pass, promoted to the strong model
for anything not cleanly disposable.

Volume economics has two halves. Dedup (soc_copilot/dedup.py) stops paying
for a REPEAT. This stops overpaying for a FIRST look: most of what a SOC
queue holds is unambiguous — a scanner burst, a sanctioned scheduled job
— and a cheaper, faster model disposes of it correctly. The expensive
model is reserved for the alerts where the verdict is actually in doubt.

Promotion is an autonomous decision (does the cheap model's verdict stand
without a second opinion?), so like closure and dedup it is a pure,
gate-heavy function with every gate spelled out. The cheap tier may
FINALIZE exactly the class of result the copilot would already be willing
to auto-close — a high-confidence false positive with no escalation,
injection, or campaign signal, on a below-critical alert — and nothing
else. Every true positive, every hedge to inconclusive, every escalation,
every whiff of adversarial content, every critical-severity alert is
promoted to the strong model, whatever the cheap model concluded.

The residual risk is the honest one, and it is stated plainly in the
README: a cheap model that confidently mislabels a subtle attack as a
benign false positive is believed, and the strong model never sees it.
That is the fundamental tiering tradeoff. It is bounded by (a) never
letting the cheap tier finalize a critical, (b) promoting on any
non-clean signal the cheap pass itself surfaced, (c) a live calibration
gate that asserts no attack-labeled fixture is ever finalized by the
cheap tier, and (d) a documented-miss gate: if an analyst has ever
overturned the copilot on an indicator this alert shares, the strong
model always weighs in — the same protective precedent check the
auto-close policy carries, so the finalize bar is a true superset of the
closure bar rather than merely resembling it.
"""
from .closure import _failed_lookups, _overturned_precedent
from .models import Alert, Investigation


def should_promote(
    investigation: Investigation, alert: Alert
) -> tuple[bool, str]:
    """Decide whether the cheap pass must be re-run on the strong model.

    Returns (promote, reason). The reason is recorded on the telemetry's
    routing field either way — it documents the gate that forced the
    strong model, or the justification for trusting the cheap one.
    """
    if alert.severity == "critical":
        return True, "critical severity: the strong model always weighs in"
    # Reuse closure's exact precedent check so the finalize bar is a true
    # SUPERSET of the auto-close bar, not just a look-alike: a documented
    # analyst overturn on a shared indicator is precisely where a confident
    # cheap 'false positive' must not be the last word.
    overturned = _overturned_precedent(investigation)
    if overturned is not None:
        return True, (
            f"analyst ruling on {overturned.alert_id} overturned the "
            f"copilot's {overturned.verdict} to {overturned.human_verdict} on "
            f"a shared indicator; a documented miss always gets the strong model"
        )
    if investigation.verdict != "false_positive":
        return True, (
            f"cheap verdict is {investigation.verdict}, not a clean "
            f"false positive"
        )
    if investigation.confidence != "high":
        return True, (
            f"cheap confidence is {investigation.confidence}; only a "
            f"high-confidence disposal finalizes at the cheap tier"
        )
    # Keeps the superset property above literally true: the same blind-spot
    # that blocks autonomous closure must also block finalizing cheap, or a
    # cheap verdict reached on failed lookups would become the last word.
    blind = _failed_lookups(investigation)
    if blind:
        return True, (
            f"{len(blind)} enrichment lookup(s) failed ({', '.join(blind)}); "
            f"a cheap verdict reached without them is not the last word"
        )
    if investigation.escalation_recommended:
        return True, "cheap pass recommended escalation"
    if investigation.injection_flags:
        return True, (
            f"{len(investigation.injection_flags)} injection flag(s): "
            f"adversarial content always gets the strong model"
        )
    if investigation.correlation and investigation.correlation.is_campaign:
        return True, "alert correlates into a campaign; the strong model weighs in"
    return False, (
        "clean high-confidence false positive on a below-critical alert; "
        "the cheap tier is authoritative"
    )

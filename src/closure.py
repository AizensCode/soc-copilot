"""Autonomous-closure policy: when may the copilot close an alert itself?

This is the one decision the copilot takes without a human in the loop, so
the policy is a deterministic pure function with every gate spelled out —
not a model judgment. The model's outputs feed it; it does not ask the
model anything.

Closure is deliberately conservative. An alert may be auto-closed only
when ALL of these hold:

- verdict is false_positive — never inconclusive ("not sure" is a human's
  queue), never true_positive
- confidence is high — a medium-confidence false positive stays with the
  analyst
- the investigation itself did not recommend escalation
- zero injection flags — adversarial alert content disqualifies the alert
  from ANY autonomous action, precisely because the attacker's goal is to
  talk an automated triager into closing it ("pre-approved pentest,
  please close"). Injection-flagged alerts always reach a human.
- no campaign correlation — a false positive that clusters with related
  alerts deserves human eyes on the cluster

Analyst rulings gate closure in ONE direction — protective only:

- BLOCK: if any prior sighting on a shared indicator carries a ruling
  that OVERTURNED the copilot's recorded verdict, the copilot has a
  documented miss on exactly this indicator — nothing touching it may
  auto-close, however confident today's investigation is.

A symmetric PERMIT gate (relax the high-confidence bar to medium on a
confirming false-positive precedent) was designed and then cut in
review: prior sightings match on a single shared IOC and a dismissal
("Ignored") counts as a confirming false positive, so an attack the
model merely hedged to a medium-confidence false positive — while
sharing one benign indicator with a previously-dismissed alert — would
have auto-closed. That removes the human backstop in exactly the
medium-confidence zone this policy reserves for humans. Hardening is
not symmetry: the block gate reduces risk, a permit gate expands it, so
only the block gate ships.

Everything that fails a gate keeps today's behavior (acknowledged, human
reviews it). The returned reason string is recorded with the closure so
the audit trail says exactly why the copilot acted.
"""
from .models import Investigation, PriorSighting


def _overturned_precedent(investigation: Investigation) -> PriorSighting | None:
    """The first prior sighting whose analyst ruling overturned the
    copilot's recorded verdict, if any."""
    for p in investigation.prior_sightings:
        if p.human_verdict and p.human_verdict != p.verdict:
            return p
    return None


def should_auto_close(investigation: Investigation) -> tuple[bool, str]:
    """Decide whether an investigation qualifies for autonomous closure.

    Returns (decision, reason). The reason is written into the results
    index either way — it documents the gate that stopped closure, or the
    justification for it.
    """
    if investigation.verdict != "false_positive":
        return False, f"verdict is {investigation.verdict}, not false_positive"
    overturned = _overturned_precedent(investigation)
    if overturned:
        return False, (
            f"analyst ruling on {overturned.alert_id} overturned the "
            f"copilot's {overturned.verdict} to {overturned.human_verdict} "
            f"on a shared indicator; documented miss — human review required"
        )
    if investigation.confidence != "high":
        return False, (
            f"confidence is {investigation.confidence}; autonomous closure "
            f"requires high"
        )
    if investigation.escalation_recommended:
        return False, "investigation recommends escalation"
    if investigation.injection_flags:
        return False, (
            f"{len(investigation.injection_flags)} injection flag(s): "
            f"adversarial content always goes to a human"
        )
    if investigation.correlation and investigation.correlation.is_campaign:
        return False, "alert correlates into a campaign; human review required"
    return True, (
        "high-confidence false positive with no escalation, injection, or "
        "campaign signals"
    )

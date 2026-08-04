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

Everything that fails a gate keeps today's behavior (acknowledged, human
reviews it). The returned reason string is recorded with the closure so
the audit trail says exactly why the copilot acted.
"""
from .models import Investigation


def should_auto_close(investigation: Investigation) -> tuple[bool, str]:
    """Decide whether an investigation qualifies for autonomous closure.

    Returns (decision, reason). The reason is written into the results
    index either way — it documents the gate that stopped closure, or the
    justification for it.
    """
    if investigation.verdict != "false_positive":
        return False, f"verdict is {investigation.verdict}, not false_positive"
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

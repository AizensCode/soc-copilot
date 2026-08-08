"""Deterministic triage ordering for the watch queue.

Watch mode fetches up to N open alerts per cycle and, until now, worked
them in whatever order Elastic returned — so during a backlog (exactly
when ordering matters most) a critical, campaign-linked alert could wait
behind low-severity noise. Every signal needed to order them the way a
human lead would exists deterministically BEFORE any LLM call: the
alert's own severity, whether it shares an indicator with a past TRUE
positive, and a pre-investigation correlation pass.

Pure functions over already-computed inputs — the caller passes the
prior sightings and correlation in, so there is no store access, no API,
and no network here, and the ordering is fully testable without a live
copilot.
"""
from .models import Alert, Correlation, PriorSighting

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Weights. Severity is the base (10..40); the two memory signals are
# additive on top, sized so a coordinated campaign outranks everything
# and a recurring true positive outranks raw severity alone.
_CAMPAIGN_BONUS = 100
_RELATED_BONUS = 25
_RECURRING_TP_BONUS = 50


def _effective_verdict(sighting: PriorSighting) -> str:
    """An analyst ruling is ground truth; absent one, the copilot's own
    recorded verdict stands. So an OVERTURNED prior (copilot said
    true_positive, a human ruled false_positive) correctly does not count
    as a recurring true positive — and a CONFIRMED one (human ruled
    true_positive) counts even if the copilot had hedged."""
    return sighting.human_verdict or sighting.verdict


def priority_score(
    alert: Alert,
    priors: list[PriorSighting],
    correlation: Correlation | None,
) -> tuple[int, str]:
    """Score an open alert for investigation order; higher goes first.

    Returns (score, reason). The reason is logged in the watch heartbeat
    so an operator can see why the queue reordered — the ordering is
    never a black box, exactly like the closure and escalation policies.
    """
    reasons: list[str] = []
    score = _SEVERITY_RANK.get(alert.severity, 2) * 10
    reasons.append(f"severity={alert.severity}")

    if correlation and correlation.is_campaign:
        score += _CAMPAIGN_BONUS
        reasons.append("campaign-correlated")
    elif correlation and correlation.related_alerts:
        score += _RELATED_BONUS
        reasons.append(f"{len(correlation.related_alerts)} related prior(s)")

    recurring = [p for p in priors if _effective_verdict(p) == "true_positive"]
    if recurring:
        score += _RECURRING_TP_BONUS
        reasons.append(f"recurs a true positive ({recurring[0].alert_id})")

    return score, ", ".join(reasons)

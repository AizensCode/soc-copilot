"""Expected investigation outcomes for each labeled alert.

Each entry maps an alert filename to the assertions we expect the
copilot's investigation to satisfy. These are the ground truth labels —
changing them is changing what "correct" means, so do so deliberately.

Matching semantics:
- expected_verdict: exact string match on Investigation.verdict
- allowed_verdicts: list of acceptable verdicts (any-of match) for
  cases where multiple verdicts are defensible
- min_confidence: ordered comparison (low < medium < high)
- required_techniques: each string must appear as substring in any
  attack_techniques entry (so "T1110.001" matches
  "T1110.001 - Brute Force: Password Guessing")
- forbidden_techniques: none of these may appear anywhere in
  attack_techniques (catches hallucinated T-codes)
- must_escalate: exact bool match on escalation_recommended
- pivots_must_include: each string must appear (case-insensitive) in
  the concatenated action+rationale text of at least one pivot
- min_evidence_count: investigation must contain at least this many
  Evidence entries (catches silently-failed enrichment)
"""
from typing import TypedDict


class AlertExpectation(TypedDict, total=False):
    expected_verdict: str              # exact match
    allowed_verdicts: list[str]        # any-of match for ambiguous cases
    min_confidence: str
    required_techniques: list[str]
    forbidden_techniques: list[str]
    must_escalate: bool
    pivots_must_include: list[str]
    min_evidence_count: int


EXPECTATIONS: dict[str, AlertExpectation] = {
    "brute_force_ssh.json": {
        "expected_verdict": "true_positive",
        "min_confidence": "high",
        # T1110 family (any sub-technique) is what matters — 
        # the specific sub-technique choice is an analyst judgment call
        # between .001 guessing / .003 spraying / .004 stuffing
        "required_techniques": ["T1110"],  # was ["T1110.001", "T1110.003"]
        "forbidden_techniques": ["T1566", "T1204"],
        "must_escalate": True,
        "pivots_must_include": [
          "successful", # the one truly non-negotiable pivot —
                        # did any authentication actually succeed?
        ],
        "min_evidence_count": 1,
    },
    "phishing_attachment.json": {
        # Allow either true_positive or inconclusive — the EICAR
        # ambiguity (real attack vs sanctioned test) is a genuine
        # analyst judgment call, and both verdicts are defensible
        # as long as attack TTPs are still mapped and escalation
        # still fires.
        "allowed_verdicts": ["true_positive", "inconclusive"],
        "min_confidence": "medium",
        "required_techniques": ["T1566.001", "T1204.002"],
        "forbidden_techniques": [
            "T1110",       # brute force shouldn't appear
            "T1566.002",   # spearphishing-link doesn't apply (no link in alert)
            "T1566.003",   # spearphishing-service doesn't apply either
            "T1598",       # phishing-for-information family doesn't apply (T1598.002 was hallucinated last run)        
        ],
        "must_escalate": True,
        "pivots_must_include": [
            "suppliersi-nvoices",  # any pivot addressing the typosquat
        ],
        "min_evidence_count": 1,
    },
}


CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


def confidence_meets_minimum(actual: str, minimum: str) -> bool:
    """Check if `actual` is at least as strong as `minimum`."""
    return CONFIDENCE_ORDER[actual] >= CONFIDENCE_ORDER[minimum]
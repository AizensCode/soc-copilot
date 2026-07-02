"""
Data models for the SOC copilot.

Every investigation flows through these shapes. Pydantic validates them
at runtime, which catches bad LLM outputs before they propagate.
"""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class Alert(BaseModel):
    """A security alert, typically from a SIEM or EDR."""

    alert_id: str
    timestamp: datetime
    source: str = Field(description="Where the alert came from, e.g. 'siem', 'edr', 'firewall'")
    severity: Literal["low", "medium", "high", "critical"]
    title: str
    raw_log: dict = Field(description="The original log payload, untouched")
    indicators: dict = Field(
        default_factory=dict,
        description="Extracted IOCs: {'ips': [...], 'hashes': [...], 'users': [...]}",
    )


class Evidence(BaseModel):
    """A single factual claim, always tied back to the tool that produced it.

    This is the anti-hallucination contract: if the LLM wants to state
    something as fact, it must attach an Evidence entry pointing at a
    real tool output.
    """

    source_tool: str
    claim: str
    raw_data: dict
    confidence: Literal["low", "medium", "high"]


class Pivot(BaseModel):
    """A suggested next investigation step for the human analyst."""

    action: str
    rationale: str
    priority: Literal["low", "medium", "high"]


class GroupMatch(BaseModel):
    """A MITRE ATT&CK threat group whose documented TTPs overlap with the
    investigation's observed techniques.

    Populated deterministically from the local MITRE group map (never by the
    LLM), so every group name traces back to the official ATT&CK data. Overlap
    is suggestive context, not attribution.
    """

    group: str
    aliases: list[str] = Field(default_factory=list)
    matched_techniques: list[str] = Field(
        description="Observed technique IDs this group is documented to use"
    )
    overlap_count: int


class PriorSighting(BaseModel):
    """A past investigation that shares one or more indicators with the
    current alert.

    Filled deterministically from the copilot's own case history (never by the
    LLM), so every sighting traces back to a real prior investigation. This is
    the cross-alert memory a human analyst keeps in their head.
    """

    alert_id: str
    timestamp: datetime
    verdict: str
    confidence: str
    title: str
    matched_iocs: list[str] = Field(
        description="Indicators shared between this alert and the prior one"
    )


class Investigation(BaseModel):
    """The final report produced for an alert."""

    alert_id: str
    verdict: Literal["true_positive", "false_positive", "inconclusive"]
    confidence: Literal["low", "medium", "high"]
    hypothesis: str
    attack_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs, e.g. ['T1110.003', 'T1078']",
    )
    evidence: list[Evidence] = Field(default_factory=list)
    suggested_pivots: list[Pivot] = Field(default_factory=list)
    associated_groups: list[GroupMatch] = Field(
        default_factory=list,
        description=(
            "MITRE ATT&CK groups whose TTPs overlap the mapped techniques. "
            "Filled deterministically from the local group map, not the LLM."
        ),
    )
    prior_sightings: list[PriorSighting] = Field(
        default_factory=list,
        description=(
            "Past investigations sharing an indicator with this alert. "
            "Filled deterministically from the case history, not the LLM."
        ),
    )
    escalation_recommended: bool
    escalation_draft: str | None = None
    reasoning_transcript: str = ""
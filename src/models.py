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
    escalation_recommended: bool
    escalation_draft: str | None = None
    reasoning_transcript: str = ""
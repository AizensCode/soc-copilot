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


class SigmaMatch(BaseModel):
    """A community Sigma detection rule whose logic matches the alert's raw
    log.

    Populated deterministically by the curated-rule matcher (never by the
    LLM), so every rule title and ATT&CK tag traces back to a committed
    SigmaHQ rule file. Explains WHY detection logic recognizes this behavior;
    the rule's tags suggest technique families but do not override the
    observed-vs-anticipated mapping discipline.
    """

    rule_id: str
    title: str
    level: str = "medium"
    tags: list[str] = Field(default_factory=list)


class AssetMatch(BaseModel):
    """An alert identifier found in the operator-maintained asset inventory
    (data/asset_context.json).

    Filled deterministically by the asset matcher (never by the LLM), so
    every entry traces to a committed inventory record. The inventory is
    trusted by provenance — the operator wrote it, unlike alert content,
    which is attacker-influenced. That makes it the one legitimate source
    for "this is sanctioned infrastructure" claims: a prose assertion of
    legitimacy inside an alert is untrusted; the same claim in the
    inventory is verified. A match describes an entity's SANCTIONED role;
    whether the observed activity actually fits that role is still the
    analyst's call.
    """

    entity: str = Field(description="The identifier as it appeared in the alert")
    entity_type: Literal["ip", "host", "service_account"]
    name: str | None = Field(
        default=None,
        description="Canonical inventory name, e.g. the host behind an IP",
    )
    role: str
    owner: str | None = None
    notes: str | None = None
    expected_activity: list[str] = Field(
        default_factory=list,
        description="Sanctioned usage: expected sources, schedule windows",
    )


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
    human_verdict: str | None = Field(
        default=None,
        description=(
            "The analyst's ruling on that prior investigation, synced back "
            "from case management (--sync-feedback). When present it "
            "outranks the copilot's own recorded verdict: memory must not "
            "keep citing an opinion a human has overturned."
        ),
    )
    human_summary: str | None = Field(
        default=None,
        description="The analyst's closing note, when they wrote one",
    )


class RelatedAlert(BaseModel):
    """A prior alert that correlates with the current one via shared
    infrastructure, target, or (corroborating) technique within a time window.
    """

    alert_id: str
    timestamp: datetime
    verdict: str
    signals: list[str] = Field(
        description=(
            "Why these alerts correlate, e.g. 'shared_ioc:1.2.3.4', "
            "'related_ip:5.6.7.8/24', 'shared_host:web-02', "
            "'shared_technique:T1110'"
        )
    )


class Correlation(BaseModel):
    """Campaign assessment: does this alert cluster with recent prior alerts?

    Computed deterministically from the case history (never the LLM). A single
    alert in isolation yields is_campaign=False with no related alerts.
    """

    is_campaign: bool
    window_hours: int
    related_alerts: list[RelatedAlert] = Field(default_factory=list)
    summary: str


class InjectionFlag(BaseModel):
    """A suspected prompt-injection attempt found in untrusted alert content.

    Detected deterministically by scanning alert fields, so it can't be talked
    out of firing by the content it inspects. An injection attempt is itself a
    hostile signal, not just something to defend against.
    """

    location: str = Field(description="Where it was found, e.g. 'raw_log.notes'")
    pattern: str = Field(description="Which injection pattern matched")
    excerpt: str = Field(description="The surrounding text")


class PhishingSignal(BaseModel):
    """One deterministic observation from the email deep-dive.

    Every signal carries the FACT with its identifier attached (never
    "SPF failed", always "SPF fail for smtp.mailfrom=<domain>") and, where
    one exists, the legitimate traffic pattern that produces the same
    observation. That second field is what stops a weak signal from being
    read as a verdict: a Return-Path on a different domain is how every
    email service provider works.

    Computed by soc_copilot/phishing.py, never by the LLM.
    """

    name: str = Field(description="Stable signal id, e.g. 'dmarc_fail'")
    strength: Literal["strong", "moderate", "weak"]
    fact: str = Field(description="What was observed, with its identifier")
    benign_cause: str | None = Field(
        default=None,
        description="Legitimate pattern that also produces this observation",
    )


class PhishingAnalysis(BaseModel):
    """Email authentication and URL analysis for an alert carrying mail.

    Filled deterministically by soc_copilot/phishing.py, never by the LLM.
    None on the Investigation when the alert carries no email material to
    analyze — which is different from "analyzed and clean".

    Alignment is the load-bearing field, not the pass/fail results: SPF
    authenticates the envelope and DKIM authenticates a signing domain,
    and neither looks at the From: header the recipient actually sees.
    Only alignment ties an authenticated identifier to that domain.
    """

    header_from: str | None = None
    envelope_from: str | None = Field(
        default=None, description="smtp.mailfrom domain (what SPF authenticated)"
    )
    dkim_domain: str | None = Field(
        default=None, description="d= of a validated signature"
    )
    spf_result: str | None = None
    dkim_result: str | None = None
    dmarc_result: str | None = Field(
        default=None,
        description="pass/fail/none/bestguesspass — 'none' means no policy "
        "published, which is NOT an authentication failure",
    )
    spf_aligned: bool | None = Field(
        default=None,
        description="Envelope domain shares an organizational domain with "
        "header.from. None when not computable.",
    )
    dkim_aligned: bool | None = None
    arc_present: bool = Field(
        default=False,
        description="An ARC chain exists — the ordinary signature of "
        "forwarding, and the usual benign explanation of a DMARC failure",
    )
    urls_examined: list[str] = Field(default_factory=list)
    signals: list[PhishingSignal] = Field(default_factory=list)
    summary: str = ""


class Telemetry(BaseModel):
    """Cost and performance of PRODUCING an investigation — distinct from
    its content.

    Filled deterministically by the copilot from the API `usage` blocks
    and a wall clock, never by the LLM. Cost is a list-price estimate
    (see soc_copilot/pricing.py): it does not account for prompt-cache discounts
    or negotiated rates, so treat it as an upper bound for budgeting, not
    a bill. This is what turns the README's hand-waved "≈$0.05 per
    investigation" into a measured per-run number, and the basis a
    future cheap-tier triage would have to beat.
    """

    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    api_calls: int = Field(default=0, description="messages.create round-trips")
    tool_calls: int = Field(default=0, description="tools dispatched (agentic)")
    retries: int = Field(
        default=0,
        description="phase-1 report resamples or agentic JSON corrections",
    )
    duration_seconds: float = 0.0
    cost_usd: float = 0.0
    routing: str | None = Field(
        default=None,
        description=(
            "Tiered-routing path, when --tiered ran: whether the cheap "
            "model finalized the verdict or it was promoted to the strong "
            "model, and why. None for a single-model investigation. Cost "
            "and token counts here are the SUM across tiers when promoted."
        ),
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
    sigma_matches: list[SigmaMatch] = Field(
        default_factory=list,
        description="Community detection rules matching the raw log; "
        "filled deterministically by the Sigma matcher, never by the LLM",
    )
    asset_matches: list[AssetMatch] = Field(
        default_factory=list,
        description=(
            "Alert identifiers found in the operator-maintained asset "
            "inventory. Filled deterministically by the asset matcher, "
            "never by the LLM."
        ),
    )
    phishing: PhishingAnalysis | None = Field(
        default=None,
        description=(
            "Email authentication and URL analysis when the alert carries "
            "mail headers. Filled deterministically by the phishing "
            "analyzer, never by the LLM. None means there was no email "
            "material to analyze — not that the mail was clean."
        ),
    )
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
    correlation: Correlation | None = Field(
        default=None,
        description=(
            "Campaign assessment: whether this alert clusters with recent "
            "prior alerts. Filled deterministically from the case history."
        ),
    )
    injection_flags: list[InjectionFlag] = Field(
        default_factory=list,
        description=(
            "Suspected prompt-injection attempts in the alert content. "
            "Detected deterministically by scanning, not by the LLM."
        ),
    )
    escalation_recommended: bool
    escalation_draft: str | None = None
    duplicate_of: str | None = Field(
        default=None,
        description=(
            "Set when this record was produced by near-duplicate "
            "suppression instead of a fresh investigation: the alert_id "
            "of the anchor investigation whose conclusion was reused. "
            "Filled deterministically by the dedup policy, never by the "
            "LLM. None for every real investigation."
        ),
    )
    reasoning_transcript: str = ""
    telemetry: Telemetry | None = Field(
        default=None,
        description=(
            "Cost and performance of producing this investigation. Filled "
            "deterministically by the copilot, never by the LLM. Optional "
            "so records written before telemetry existed simply lack it."
        ),
    )

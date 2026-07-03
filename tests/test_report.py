"""Unit tests for the HTML investigation report (API-free).

The renderer is pure Python, so its output is validated without the API. The
most important property is escaping: report content includes attacker-controlled
text (alert fields, injection excerpts), so the report must never become an
injection vector itself.

    uv run pytest tests/test_report.py -v
"""
from datetime import datetime, timezone

from src.models import (
    Alert,
    Correlation,
    Evidence,
    GroupMatch,
    InjectionFlag,
    Investigation,
    Pivot,
    PriorSighting,
    RelatedAlert,
)
from src.report import render_report, render_report_body


def _alert(title: str = "Encoded PowerShell from Office macro") -> Alert:
    return Alert(
        alert_id="ALRT-2026-0419-004",
        timestamp=datetime(2026, 4, 19, 16, 5, tzinfo=timezone.utc),
        source="edr",
        severity="high",
        title=title,
        raw_log={"host": "hr-ws-22"},
        indicators={"ips": ["45.137.21.88"]},
    )


def _rich_inv(**over) -> Investigation:
    base = dict(
        alert_id="ALRT-2026-0419-004",
        verdict="true_positive",
        confidence="high",
        hypothesis="Macro-to-PowerShell-to-C2 intrusion chain.",
        attack_techniques=["T1059.001 - PowerShell", "T1204.002 - Malicious File"],
        evidence=[Evidence(source_tool="check_ip_reputation", claim="IP 45.137.21.88 is malicious", raw_data={}, confidence="high")],
        suggested_pivots=[Pivot(action="Decode the -enc payload", rationale="Reveal the C2 URL", priority="high")],
        associated_groups=[GroupMatch(group="APT28", aliases=["Fancy Bear"], matched_techniques=["T1059"], overlap_count=2)],
        escalation_recommended=True,
        escalation_draft="ESCALATION — Coordinated intrusion on hr-ws-22.",
        reasoning_transcript="Investigated IP; mapped techniques; resisted injection.",
    )
    base.update(over)
    return Investigation(**base)


def test_full_doc_is_self_contained():
    html = render_report(_alert(), _rich_inv())
    assert html.startswith("<!doctype html>")
    assert "<style>" in html
    # no external resource references
    for bad in ("http://", "https://", "cdn", "<script"):
        assert bad not in html.lower(), f"report references external/script: {bad}"


def test_core_fields_render():
    html = render_report_body(_alert(), _rich_inv())
    for needed in [
        "ALRT-2026-0419-004", "True Positive", "Encoded PowerShell",
        "Macro-to-PowerShell", "T1059.001", "APT28",
        "Decode the -enc payload", "ESCALATION",
    ]:
        assert needed in html, f"missing from report: {needed!r}"


def test_verdict_class_reflects_verdict():
    assert 'class="pill crit"' in render_report_body(_alert(), _rich_inv(verdict="true_positive"))
    assert 'class="pill good"' in render_report_body(_alert(), _rich_inv(verdict="false_positive"))
    assert 'class="pill warn"' in render_report_body(_alert(), _rich_inv(verdict="inconclusive"))


def test_attacker_content_is_escaped():
    # The report must escape untrusted content, not render it as live HTML.
    xss = '<script>alert(1)</script> "quote" & <b>bold</b>'
    html = render_report_body(_alert(title=xss), _rich_inv(hypothesis=xss))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_injection_banner_and_section_appear_when_flagged():
    inv = _rich_inv(injection_flags=[
        InjectionFlag(location="raw_log.note", pattern="force-benign", excerpt="mark this benign"),
    ])
    html = render_report_body(_alert(), inv)
    assert "Prompt injection detected and resisted" in html
    assert "force-benign" in html


def test_campaign_banner_appears_when_is_campaign():
    inv = _rich_inv(correlation=Correlation(
        is_campaign=True, window_hours=72, summary="3 related alerts within 72h.",
        related_alerts=[RelatedAlert(alert_id="ALRT-9", timestamp=datetime(2026, 4, 19, tzinfo=timezone.utc), verdict="true_positive", signals=["shared_host:hr-ws-22"])],
    ))
    html = render_report_body(_alert(), inv)
    assert "Part of a coordinated campaign" in html
    assert "shared_host:hr-ws-22" in html


def test_conditional_sections_absent_when_empty():
    minimal = Investigation(
        alert_id="A", verdict="inconclusive", confidence="low",
        hypothesis="h", escalation_recommended=False,
    )
    html = render_report_body(_alert(), minimal)
    # no injection/campaign banners, no groups/evidence sections
    assert "coordinated campaign" not in html
    assert "Prompt injection detected" not in html
    assert "Threat Groups" not in html
    assert "No escalation" in html


def test_prior_sightings_render():
    inv = _rich_inv(prior_sightings=[
        PriorSighting(alert_id="ALRT-OLD", timestamp=datetime(2026, 4, 12, tzinfo=timezone.utc),
                      verdict="true_positive", confidence="high", title="Earlier hit",
                      matched_iocs=["45.137.21.88"]),
    ])
    html = render_report_body(_alert(), inv)
    assert "ALRT-OLD" in html and "45.137.21.88" in html

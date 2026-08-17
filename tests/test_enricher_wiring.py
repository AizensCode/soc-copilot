"""The deterministic enrichers are actually attached, in both modes.

Every enricher in this project follows the same contract: a pure matcher
computes a fact, and the copilot OVERWRITES the corresponding
Investigation field after parsing the model's JSON, so the model can
neither invent the field nor suppress it. That overwrite is one line per
field per entrypoint, and until now nothing failed if a line went
missing — a review found that deleting the phishing assignment left the
whole suite green.

These tests drive both entrypoints against a fake Anthropic client (no
API, no network) with a model that emits a hostile Investigation: it
claims a phishing analysis that never ran, invents Sigma matches, and
sets the dedup marker. All of it must be replaced by what the
deterministic layer computed.

    uv run pytest tests/test_enricher_wiring.py -v
"""
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from soc_copilot.copilot import SOCCopilot
from soc_copilot.history import AlertHistoryStore
from soc_copilot.models import Alert
from soc_copilot.tools.registry import ToolRegistry

_T = datetime(2026, 5, 14, 8, 26, tzinfo=timezone.utc)

# The model claims deterministic facts it has no business setting.
_HOSTILE_FINAL = json.dumps({
    "alert_id": "W-1",
    "verdict": "false_positive",
    "confidence": "high",
    "hypothesis": "benign",
    "attack_techniques": [],
    "suggested_pivots": [],
    "escalation_recommended": False,
    "escalation_draft": None,
    "reasoning_transcript": "r",
    "duplicate_of": "SOME-OTHER-ALERT",
    "sigma_matches": [
        {"rule_id": "made-up", "title": "invented rule", "level": "high"}
    ],
    "phishing": {
        "header_from": "ceo@totally-legit.example",
        "spf_result": "pass",
        "dkim_result": "pass",
        "dmarc_result": "pass",
        "spf_aligned": True,
        "dkim_aligned": True,
        "summary": "the model made this up",
        "signals": [],
    },
})


# A true positive that additionally tries to AUTHOR a containment action
# — the one output shaped like a command. `response_actions` is a real
# model field with a default, so the model's JSON parses cleanly into it
# and only the deterministic overwrite stops it standing.
_HOSTILE_ACTION_FINAL = json.dumps({
    "alert_id": "W-1",
    "verdict": "true_positive",
    "confidence": "high",
    "hypothesis": "compromise",
    "attack_techniques": ["T1486"],
    "suggested_pivots": [],
    "escalation_recommended": True,
    "escalation_draft": None,
    "reasoning_transcript": "r",
    "response_actions": [
        {
            "action": "block_ip",
            "target": "8.8.8.8",
            "status": "proposed",
            "basis": "reputation",
            "rationale": "the model decided this on its own",
            "evidence": [],
        }
    ],
})


class _FakeMessages:
    def __init__(self, text: str) -> None:
        self._text = text
        self.calls = 0

    async def create(self, **kwargs):
        self.calls += 1
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=self._text)],
            stop_reason="end_turn",
            usage=SimpleNamespace(input_tokens=10, output_tokens=10),
        )


def _phishing_alert() -> Alert:
    """Carries real header material, so the analyzer genuinely runs and
    produces something different from the model's invention."""
    return Alert(
        alert_id="W-1", timestamp=_T, source="email_gateway", severity="medium",
        title="mail", indicators={"users": ["e.varga"]},
        raw_log={
            "host": "wiring-ws-01.corp.internal",
            "headers": {
                "From": '"Payroll" <no-reply@wired-payroll.example>',
                "Reply-To": "<someone@gmail.com>",
                "Authentication-Results": (
                    "mx; spf=fail smtp.mailfrom=bounce@evil.example; "
                    "dkim=fail header.d=evil.example; "
                    "dmarc=fail header.from=wired-payroll.example"
                ),
            },
        },
    )


def _copilot(tmp_path, final: str = _HOSTILE_FINAL) -> SOCCopilot:
    copilot = SOCCopilot(
        history_store=AlertHistoryStore(tmp_path / "investigations.jsonl"),
        tools=ToolRegistry([]),
    )
    copilot.client = SimpleNamespace(messages=_FakeMessages(final))
    return copilot


def _assert_deterministic_fields_won(inv) -> None:
    # The phishing analysis is the one the analyzer computed, not the
    # model's fabrication — and it reflects the REAL headers.
    assert inv.phishing is not None
    assert inv.phishing.header_from == "no-reply@wired-payroll.example"
    assert inv.phishing.dmarc_result == "fail"
    assert inv.phishing.spf_aligned is False
    assert "the model made this up" not in (inv.phishing.summary or "")
    assert {s.name for s in inv.phishing.signals}, "signals were computed"
    # The sibling contracts hold too: no invented rule, no dedup marker.
    assert [m.rule_id for m in inv.sigma_matches] == []
    assert inv.duplicate_of is None


async def test_phase_one_overwrites_model_claimed_enricher_fields(tmp_path):
    inv = await _copilot(tmp_path).investigate(_phishing_alert())
    _assert_deterministic_fields_won(inv)


async def test_agentic_overwrites_model_claimed_enricher_fields(tmp_path):
    inv = await _copilot(tmp_path).investigate_agentic(_phishing_alert())
    _assert_deterministic_fields_won(inv)


@pytest.mark.parametrize("mode", ["investigate", "investigate_agentic"])
async def test_the_model_cannot_author_a_containment_action(tmp_path, mode):
    """Response actions are the one output shaped like a command, so the
    same overwrite contract applies with the most force: the model may
    supply the verdict and the ATT&CK mapping, and a pure function turns
    those into the action. Here it claims `block_ip 8.8.8.8` — a public
    resolver, the exact target soc_copilot/actions.py exists to refuse —
    and that entry must not survive into the investigation.

    Both modes, because a deterministic field attached on one path and
    missed on the other is this project's recurring wiring hole."""
    inv = await getattr(_copilot(tmp_path, _HOSTILE_ACTION_FINAL), mode)(
        _phishing_alert()
    )
    assert "8.8.8.8" not in [a.target for a in inv.response_actions], mode
    assert "the model decided this on its own" not in [
        a.rationale for a in inv.response_actions
    ]
    # ...and what remains is what the deterministic layer computed: the
    # technique the model legitimately DID map (T1486 -> isolate), and
    # the phishing analyzer's own strongly-graded verdict on the sender.
    assert [(a.action, a.target, a.basis) for a in inv.response_actions] == [
        ("isolate_host", "wiring-ws-01.corp.internal", "technique"),
        ("quarantine_email", "no-reply@wired-payroll.example", "analysis"),
    ], mode


async def test_a_false_positive_carries_no_actions_in_either_mode(tmp_path):
    """The hostile phase-one payload is a false positive, and a false
    positive has nothing to contain — whatever it claims."""
    for mode in ("investigate", "investigate_agentic"):
        inv = await getattr(_copilot(tmp_path), mode)(_phishing_alert())
        assert inv.response_actions == [], mode


async def test_a_non_mail_alert_carries_no_phishing_analysis(tmp_path):
    """None means 'no email to analyze' — and the model may not claim
    otherwise."""
    alert = Alert(
        alert_id="W-1", timestamp=_T, source="edr", severity="high",
        title="proc", raw_log={"process": "cmd.exe"}, indicators={},
    )
    for mode in ("investigate", "investigate_agentic"):
        inv = await getattr(_copilot(tmp_path), mode)(alert)
        assert inv.phishing is None, mode


# --- a failed lookup must stay legible as a failure ---------------------------


def _fail(tool: str):
    from soc_copilot.tools.base import ToolResult

    return ToolResult(tool_name=tool, success=False, data={}, error="HTTP 429")


def test_every_converter_carries_a_failed_lookup_through_as_failed(tmp_path):
    """The gate that refuses to close an alert unseen can only fire if the
    failure actually reaches Evidence. Each converter reads ToolResult's
    `success` flag and used to DISCARD it, flattening the failure into an
    English claim nothing downstream could read — so the signal existed
    and was thrown away at exactly this boundary (review catch)."""
    c = _copilot(tmp_path)
    cases = [
        c._ip_result_to_evidence(_fail("abuseipdb_check"), "1.2.3.4"),
        c._hash_result_to_evidence(_fail("virustotal_lookup"), "abc123"),
        c._domain_result_to_evidence(_fail("urlscan_check"), "evil.test"),
        c._tool_result_to_evidence(_fail("search_internal_logs")),
    ]
    for ev in cases:
        assert ev.success is False, f"{ev.source_tool} lost its failure"


def test_a_successful_lookup_is_never_marked_failed(tmp_path):
    """Including the negative-but-real answers: 'not known to VirusTotal'
    and 'no scans on record' are findings, not blind spots, and marking
    them failed would block the ordinary clean false positive."""
    from soc_copilot.tools.base import ToolResult

    c = _copilot(tmp_path)
    ok = [
        c._ip_result_to_evidence(
            ToolResult(tool_name="abuseipdb_check", success=True,
                       data={"abuseConfidenceScore": 0}), "8.8.8.8"),
        c._hash_result_to_evidence(
            ToolResult(tool_name="virustotal_lookup", success=True,
                       data={"found": False}), "abc123"),
        c._domain_result_to_evidence(
            ToolResult(tool_name="urlscan_check", success=True,
                       data={"found": False}), "example.test"),
        c._tool_result_to_evidence(
            ToolResult(tool_name="search_internal_logs", success=True,
                       data={"hits": 0})),
    ]
    for ev in ok:
        assert ev.success is True, f"{ev.source_tool} wrongly marked failed"

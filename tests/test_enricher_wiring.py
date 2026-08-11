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


def _copilot(tmp_path) -> SOCCopilot:
    copilot = SOCCopilot(
        history_store=AlertHistoryStore(tmp_path / "investigations.jsonl"),
        tools=ToolRegistry([]),
    )
    copilot.client = SimpleNamespace(messages=_FakeMessages(_HOSTILE_FINAL))
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

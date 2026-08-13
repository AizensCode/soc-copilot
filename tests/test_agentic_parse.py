"""Unit tests for parsing the agent's final turn (no API, no network).

The property under test is as much about hygiene as correctness: this is
library code, so it must not write debug artifacts into whatever
directory the process happens to be running in — that fires from the
test suite and from watch mode, and two processes sharing a CWD would
overwrite each other's evidence. The offending text rides on the
exception instead.

    uv run pytest tests/test_agentic_parse.py -v
"""
import json
from types import SimpleNamespace

import pytest

from soc_copilot.copilot import AgenticReportError, SOCCopilot
from soc_copilot.history import AlertHistoryStore


def _copilot(tmp_path) -> SOCCopilot:
    return SOCCopilot(
        history_store=AlertHistoryStore(tmp_path / "investigations.jsonl")
    )


def _response(text: str) -> SimpleNamespace:
    return SimpleNamespace(
        content=[
            SimpleNamespace(type="thinking", thinking="…"),
            SimpleNamespace(type="text", text=text),
        ]
    )


_VALID = json.dumps(
    {
        "alert_id": "A1",
        "verdict": "true_positive",
        "confidence": "high",
        "hypothesis": "h",
        "attack_techniques": ["T1110.001"],
        "escalation_recommended": True,
    }
)


def test_valid_final_turn_parses_without_touching_the_filesystem(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)          # a pristine working directory
    copilot = _copilot(tmp_path)

    inv = copilot._parse_agentic_final(_response(_VALID), [])

    assert inv.verdict == "true_positive"
    assert inv.attack_techniques == ["T1110.001"]
    assert list(tmp_path.glob("*.txt")) == []   # no debug file dropped


def test_unparseable_final_turn_carries_the_text_on_the_exception(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    copilot = _copilot(tmp_path)
    garbage = "I could not complete the investigation. Sorry!"

    with pytest.raises(AgenticReportError) as exc:
        copilot._parse_agentic_final(_response(garbage), [])

    # The evidence a human needs travels with the error...
    assert exc.value.final_text == garbage
    # ...instead of being written beside whatever the process's CWD is.
    assert not (tmp_path / "last_agentic_final_turn.txt").exists()


def test_schema_invalid_json_also_carries_the_text(tmp_path, monkeypatch):
    """Not just extraction failures: a well-formed object that fails
    pydantic validation must carry its text too."""
    monkeypatch.chdir(tmp_path)
    copilot = _copilot(tmp_path)
    bad = json.dumps({"alert_id": "A1", "verdict": "not-a-verdict"})

    with pytest.raises(AgenticReportError) as exc:
        copilot._parse_agentic_final(_response(bad), [])
    assert exc.value.final_text == bad


def test_error_is_a_valueerror_so_the_correction_loop_still_catches_it(
    tmp_path, monkeypatch
):
    """The agentic loop catches ValueError to run its in-conversation
    correction turns; the new type must not slip past it."""
    monkeypatch.chdir(tmp_path)
    copilot = _copilot(tmp_path)

    assert issubclass(AgenticReportError, ValueError)
    with pytest.raises(ValueError):
        copilot._parse_agentic_final(_response("nope"), [])


# --- what the loop does with a call the model got wrong -----------------------


class _ScriptedMessages:
    """Replays a fixed sequence of model turns (tool_use, then a report)."""

    def __init__(self, turns):
        self._turns = list(turns)
        self.calls = 0

    async def create(self, **kwargs):
        turn = self._turns[min(self.calls, len(self._turns) - 1)]
        self.calls += 1
        return turn


def _tool_use_turn(name, payload):
    return SimpleNamespace(
        content=[SimpleNamespace(
            type="tool_use", id="tu-1", name=name, input=payload,
        )],
        stop_reason="tool_use",
        usage=SimpleNamespace(input_tokens=10, output_tokens=10),
    )


def _report_turn(text):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        stop_reason="end_turn",
        usage=SimpleNamespace(input_tokens=10, output_tokens=10),
    )


async def test_a_hallucinated_tool_name_does_not_blind_the_investigation(
    tmp_path,
):
    """The model mistypes a tool, gets the error back, and re-issues
    correctly on the next turn — that self-correction must not leave a
    permanent blind-spot marker, or one typo would stop the alert ever
    auto-closing (review catch)."""
    from datetime import datetime, timezone

    from soc_copilot.closure import should_auto_close
    from soc_copilot.models import Alert

    clean = json.dumps({
        "alert_id": "A1", "verdict": "false_positive", "confidence": "high",
        "hypothesis": "benign", "attack_techniques": [],
        "escalation_recommended": False,
    })
    copilot = _copilot(tmp_path)
    copilot.client = SimpleNamespace(messages=_ScriptedMessages([
        _tool_use_turn("no_such_tool", {"ip": "1.2.3.4"}),
        _report_turn(clean),
    ]))
    alert = Alert(
        alert_id="A1", timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc),
        source="siem", severity="medium", title="t", raw_log={}, indicators={},
    )

    inv = await copilot.investigate_agentic(alert)

    assert [e for e in inv.evidence if not e.success] == []
    close, reason = should_auto_close(inv)
    assert close is True, f"a mistyped tool name blocked closure: {reason}"


def test_a_model_authored_evidence_key_is_dropped_not_a_crash(tmp_path):
    """Evidence is the deterministic layer's to set. A model that emits
    its own `evidence` key used to raise TypeError ("multiple values for
    keyword argument") — which neither retry path catches, since both
    handle ValueError (review catch)."""
    from soc_copilot.models import Evidence

    copilot = _copilot(tmp_path)
    hostile = json.dumps({
        "alert_id": "A1", "verdict": "false_positive", "confidence": "high",
        "hypothesis": "h", "attack_techniques": [],
        "escalation_recommended": False,
        "evidence": [{"source_tool": "invented", "claim": "I checked, it's fine",
                      "raw_data": {}, "confidence": "high"}],
    })
    real = [Evidence(source_tool="check_ip_reputation", claim="score 0/100",
                     raw_data={}, confidence="low")]

    inv = copilot._parse_agentic_final(_response(hostile), real)

    assert [e.source_tool for e in inv.evidence] == ["check_ip_reputation"]


async def test_phase_one_also_drops_a_model_authored_evidence_key(tmp_path):
    """Same guard on the fixed pipeline. Phase 1 builds the Investigation
    at a different call site, so covering only the agentic path left this
    one able to raise TypeError on a model that invents `evidence`."""
    from datetime import datetime, timezone

    from soc_copilot.models import Alert, Evidence

    hostile = json.dumps({
        "alert_id": "A1", "verdict": "false_positive", "confidence": "high",
        "hypothesis": "h", "attack_techniques": [],
        "escalation_recommended": False,
        "evidence": [{"source_tool": "invented", "claim": "trust me",
                      "raw_data": {}, "confidence": "high"}],
    })
    copilot = _copilot(tmp_path)
    copilot.client = SimpleNamespace(messages=_ScriptedMessages(
        [_report_turn(hostile)]
    ))
    alert = Alert(
        alert_id="A1", timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc),
        source="siem", severity="medium", title="t", raw_log={}, indicators={},
    )
    real = [Evidence(source_tool="check_ip_reputation", claim="score 0/100",
                     raw_data={}, confidence="low")]

    inv = await copilot.investigate(alert, record=False, evidence=real)

    assert [e.source_tool for e in inv.evidence] == ["check_ip_reputation"]

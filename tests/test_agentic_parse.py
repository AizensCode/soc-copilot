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

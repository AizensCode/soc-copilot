"""Unit tests for the Sigma matcher (API-free, network-free).

The matcher is a pure function from an alert's raw_log to a list of
matched curated rules, so both the matching semantics and the concrete
sample-alert coverage are exact, deterministic assertions.

    uv run pytest tests/test_sigma.py -v
"""
import json
from pathlib import Path

import pytest

from src.models import Alert
from src.sigma import (
    _ConditionParser,
    _match_value,
    load_rules,
    match_sigma_rules,
    tags_to_techniques,
)

SAMPLE_ALERTS_DIR = Path("data/sample_alerts")

ENCODE_RULE = "fb843269-508c-4b76-8b8d-88679db22ce7"  # powershell -enc
OFFICE_CHILD_RULE = "438025f9-5856-4663-83f7-52f878a70a50"
OUTLOOK_TEMP_RULE = "a018fdc3-46a3-44e5-9afb-2cd4af1d4b39"


def _alert(filename: str) -> Alert:
    with (SAMPLE_ALERTS_DIR / filename).open() as f:
        return Alert(**json.load(f))


def _alert_from_raw(raw_log: dict) -> Alert:
    return Alert(
        alert_id="t-1",
        timestamp="2026-01-01T00:00:00Z",
        source="test",
        severity="high",
        title="test",
        raw_log=raw_log,
        indicators={},
    )


# --- rule loading ------------------------------------------------------------


def test_curated_rules_load_with_ids_and_tags():
    rules = load_rules()
    assert len(rules) >= 3
    by_id = {r["id"] for r in rules}
    assert {ENCODE_RULE, OFFICE_CHILD_RULE, OUTLOOK_TEMP_RULE} <= by_id
    for r in rules:
        assert r["title"] and r["level"]
        assert "condition" in r["detection"]


# --- matching semantics ------------------------------------------------------


def test_match_value_case_insensitive_contains():
    assert _match_value("PowerShell.exe -ENC abc", " -enc ", "contains")
    assert not _match_value("powershell.exe -Encoding utf8", " -enc ", "contains")


def test_endswith_matches_bare_basename():
    # rule pattern '\powershell.exe' vs an alert carrying just the basename
    assert _match_value("powershell.exe", "\\powershell.exe", "endswith")
    assert _match_value(r"C:\Windows\powershell.exe", "\\powershell.exe", "endswith")
    assert not _match_value("notpowershell.exe", "\\powershell.exe", "endswith")


def test_unmodified_value_honors_wildcards():
    assert _match_value("C:\\Users\\x\\evil.exe", "*\\evil.exe", None)
    assert _match_value("Cmd.Exe", "cmd.exe", None)  # case-insensitive equality
    assert not _match_value("cmd.exe.bak", "cmd.exe", None)


def test_condition_parser_forms():
    results = {"selection": True, "filter_a": False, "filter_b": True}
    assert _ConditionParser("selection and not filter_a", results).parse()
    assert not _ConditionParser("selection and not 1 of filter_*", results).parse()
    assert _ConditionParser("all of them", {"a": True, "b": True}).parse()
    assert not _ConditionParser("all of them", {"a": True, "b": False}).parse()
    assert _ConditionParser("1 of them", {"a": False, "b": True}).parse()
    with pytest.raises(ValueError):
        _ConditionParser("unknown_selection", results).parse()


def test_filter_suppresses_match():
    # ' -Encoding ' is the encode rule's false-positive filter
    matches = match_sigma_rules(_alert_from_raw({
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc dGVzdA== -Encoding utf8",
    }))
    assert ENCODE_RULE not in [m.rule_id for m in matches]


def test_nested_ecs_raw_log_matches():
    # Elastic-normalized alerts nest process fields; FIELD_MAP dotted paths
    # must reach them.
    matches = match_sigma_rules(_alert_from_raw({
        "process": {
            "name": "powershell.exe",
            "command_line": "powershell.exe -w hidden -enc dGVzdA==",
        },
    }))
    assert ENCODE_RULE in [m.rule_id for m in matches]


def test_tags_to_techniques_extracts_tcodes():
    tags = ["attack.execution", "attack.t1059.001", "attack.t1204", "cve.2021"]
    assert tags_to_techniques(tags) == ["T1059.001", "T1204"]


# --- sample-alert coverage (exact, deterministic) ----------------------------


def test_prompt_injection_alert_matches_encode_and_office_child():
    ids = {m.rule_id for m in match_sigma_rules(_alert("prompt_injection.json"))}
    assert ids == {ENCODE_RULE, OFFICE_CHILD_RULE}


def test_phishing_attachment_matches_outlook_temp():
    ids = {m.rule_id for m in match_sigma_rules(_alert("phishing_attachment.json"))}
    assert ids == {OUTLOOK_TEMP_RULE}


@pytest.mark.parametrize("filename", [
    "brute_force_ssh.json",
    "dns_tunneling_beacon.json",
    "impossible_travel_login.json",
    "suspicious_url_click.json",
])
def test_uncovered_families_match_nothing(filename):
    assert match_sigma_rules(_alert(filename)) == []

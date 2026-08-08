"""Unit tests for CLI argument parsing (no API, no network).

The CLI keeps its historical `--command` shape (so every documented
invocation still works), but each command now parses its own args with
argparse instead of scanning sys.argv. Two properties matter and are
locked here: an unknown or misspelled flag is REJECTED (a typo'd
--auto-close in a systemd unit silently changed autonomous behavior
before), and a bad numeric value is refused loudly rather than silently
defaulted (the original `--digest -1` catch).

    uv run pytest tests/test_cli.py -v
"""
import argparse

import pytest

from src.main import _parse_args, positive_int

# --- positive_int type -------------------------------------------------------


def test_positive_int_parses_a_valid_value():
    assert positive_int("window hours")("48") == 48


@pytest.mark.parametrize("bad", ["-1", "0", "abc", "1.5"])
def test_positive_int_rejects_non_positive_and_non_integer(bad):
    with pytest.raises(argparse.ArgumentTypeError, match="positive integer"):
        positive_int("window hours")(bad)


# --- command parsing ---------------------------------------------------------


def test_default_command_investigates_a_file():
    command, args = _parse_args(["alert.json", "--agentic", "--case"])
    assert command == "file"
    assert args.file == "alert.json"
    assert args.agentic is True and args.case is True
    assert args.report is None


def test_debug_dump_is_opt_in_with_an_optional_path():
    """A run must not drop a debug file into the operator's CWD unasked."""
    _, default = _parse_args(["alert.json"])
    assert default.debug is None                      # off unless requested
    _, bare = _parse_args(["alert.json", "--debug"])
    assert bare.debug == "last_run_debug.json"
    _, named = _parse_args(["alert.json", "--debug", "out.json"])
    assert named.debug == "out.json"


def test_report_takes_an_optional_value():
    _, bare = _parse_args(["alert.json", "--report"])
    assert bare.report == "investigation_report.html"
    _, named = _parse_args(["alert.json", "--report", "out.html"])
    assert named.report == "out.html"


def test_watch_optional_interval_and_flags():
    command, args = _parse_args(["--watch", "30", "--auto-close", "--notify"])
    assert command == "watch"
    assert args.interval == 30
    assert args.auto_close is True and args.notify is True
    assert args.case is False
    # A following flag is not swallowed as the interval.
    _, defaulted = _parse_args(["--watch", "--agentic"])
    assert defaulted.interval == 60 and defaulted.agentic is True


def test_digest_negative_value_is_rejected_not_defaulted(capsys):
    """The original live bug, now enforced by argparse's own validation."""
    with pytest.raises(SystemExit) as exc:
        _parse_args(["--digest", "-1"])
    assert exc.value.code == 2
    assert "positive integer" in capsys.readouterr().err


def test_ask_requires_an_alert_id_but_question_is_optional():
    command, args = _parse_args(["--ask", "ALRT-1"])
    assert command == "ask" and args.alert_id == "ALRT-1"
    assert args.question is None
    _, with_q = _parse_args(["--ask", "ALRT-1", "why true positive?"])
    assert with_q.question == "why true positive?"
    with pytest.raises(SystemExit):        # missing required alert_id
        _parse_args(["--ask"])


def test_ask_question_may_begin_with_a_dash():
    """The question is free text, not an argparse token: a dash-prefixed
    question must be taken verbatim, not rejected as an unknown option."""
    _, args = _parse_args(["--ask", "ALRT-1", "--why did you escalate?"])
    assert args.question == "--why did you escalate?"


@pytest.mark.parametrize("truncated", ["--au", "--not", "--c"])
def test_truncated_flag_prefixes_are_rejected_not_silently_applied(
    truncated, capsys
):
    """allow_abbrev=False: `--au` must NOT silently enable --auto-close.
    Accepting prefixes would re-open the silent-autonomous-behavior hole
    this whole change closes."""
    with pytest.raises(SystemExit) as exc:
        _parse_args(["--watch", "60", truncated])
    assert exc.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_unknown_flag_on_a_command_is_rejected(capsys):
    """The safety fix: a misspelled --auto-close must error, not vanish."""
    with pytest.raises(SystemExit) as exc:
        _parse_args(["--watch", "60", "--auto-clsoe"])
    assert exc.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_unknown_command_is_rejected_not_treated_as_a_file(capsys):
    with pytest.raises(SystemExit) as exc:
        _parse_args(["--waaatch"])
    assert exc.value.code == 2
    assert "Unknown command" in capsys.readouterr().err


def test_flagless_commands_reject_stray_arguments(capsys):
    command, _ = _parse_args(["--scorecard"])
    assert command == "scorecard"
    with pytest.raises(SystemExit):
        _parse_args(["--scorecard", "extra"])

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

from soc_copilot.main import _parse_args, positive_int

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


def test_tiered_flag_parses_on_every_investigation_entrypoint():
    """--tiered is opt-in on the file, from-elastic, and watch commands."""
    _, f = _parse_args(["alert.json", "--tiered"])
    assert f.tiered is True
    _, e = _parse_args(["--from-elastic", "2", "--tiered"])
    assert e.tiered is True
    _, w = _parse_args(["--watch", "30", "--tiered", "--dedup"])
    assert w.tiered is True and w.dedup == 24
    # Off unless asked.
    _, bare = _parse_args(["alert.json"])
    assert bare.tiered is False


def test_watch_dedup_flag_off_by_default_with_bounded_window():
    """--dedup is opt-in (suppression is an autonomous decision); bare
    --dedup gets the default window, an explicit window is honored, and a
    negative window is rejected like every other count."""
    _, off = _parse_args(["--watch"])
    assert off.dedup is None
    _, bare = _parse_args(["--watch", "--dedup"])
    assert bare.dedup == 24
    _, windowed = _parse_args(["--watch", "--dedup", "6"])
    assert windowed.dedup == 6
    with pytest.raises(SystemExit):
        _parse_args(["--watch", "--dedup", "-3"])


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


# --- the logging bootstrap in cli() ------------------------------------------
#
# cli() is the only place logging is configured; if the call is dropped,
# every INFO line in production falls into the stdlib's lastResort
# handler and vanishes — with the whole suite green, because nothing
# else exercises cli() (review catch).


def test_python_dash_m_keeps_the_narration(tmp_path):
    """Under `python -m soc_copilot.main` the module runs as "__main__";
    a getLogger(__name__) narrator would sit outside the configured
    "soc_copilot" hierarchy and every INFO line would silently vanish
    into the stdlib's lastResort handler (review catch). Only a real
    child process can pin this: under pytest the module is IMPORTED as
    soc_copilot.main, so __name__ equals the pinned name and an
    in-process assertion cannot tell them apart (mutation catch — the
    name-equality version of this test survived the revert)."""
    import os
    import subprocess
    import sys

    env = dict(
        os.environ,
        HISTORY_PATH=str(tmp_path / "investigations.jsonl"),
        LOG_FORMAT="text",
        LOG_LEVEL="INFO",
    )
    r = subprocess.run(
        [sys.executable, "-m", "soc_copilot.main", "--export-case"],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode == 0, r.stderr
    assert "Nothing to export" in r.stderr        # INFO narration survived


def test_cli_configures_logging_before_dispatching(monkeypatch):
    import soc_copilot.main as main

    order: list[tuple] = []

    def fake_configure(fmt, level):
        order.append(("configure", fmt, level))

    async def fake_dispatch(command, args):
        order.append(("dispatch", command))

    monkeypatch.setattr(main, "configure_logging", fake_configure)
    monkeypatch.setattr(main, "_dispatch", fake_dispatch)
    monkeypatch.setattr(main.sys, "argv", ["soc-copilot", "--scorecard"])

    main.cli()

    assert [step[0] for step in order] == ["configure", "dispatch"]
    from soc_copilot.config import settings

    assert order[0][1:] == (settings.LOG_FORMAT, settings.LOG_LEVEL)


def test_a_broken_logging_config_is_reported_on_bare_stderr(
    monkeypatch, capsys
):
    """When the logging config ITSELF is the broken thing, there is no
    logger to speak through — the error must still reach stderr as one
    plain line, exit 1."""
    import soc_copilot.main as main

    def broken_configure(fmt, level):
        raise RuntimeError("LOG_FORMAT must be one of text, json, got 'yaml'")

    monkeypatch.setattr(main, "configure_logging", broken_configure)
    monkeypatch.setattr(main.sys, "argv", ["soc-copilot", "--scorecard"])

    with pytest.raises(SystemExit) as exc:
        main.cli()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "Configuration error" in err and "LOG_FORMAT" in err


def test_config_errors_after_the_bootstrap_speak_through_the_logger(
    monkeypatch, caplog
):
    """Once logging IS configured, a missing-key RuntimeError from
    dispatch must go through the logger (so LOG_FORMAT=json stays JSON
    to the last line), still exit 1."""
    import logging

    import soc_copilot.main as main

    logger = logging.getLogger("soc_copilot")
    saved_handlers, saved_level = list(logger.handlers), logger.level

    async def failing_dispatch(command, args):
        raise RuntimeError("Missing required environment variable(s): X")

    monkeypatch.setattr(main, "_dispatch", failing_dispatch)
    monkeypatch.setattr(main.sys, "argv", ["soc-copilot", "--scorecard"])
    try:
        with pytest.raises(SystemExit) as exc:
            main.cli()
    finally:
        logger.handlers = saved_handlers
        logger.setLevel(saved_level)

    assert exc.value.code == 1
    [rec] = [r for r in caplog.records if "Configuration error" in r.getMessage()]
    assert rec.levelno == logging.ERROR
    assert "Missing required" in rec.getMessage()


def test_rotate_history_parses_its_days_and_flags():
    from soc_copilot.rotate import DEFAULT_RETENTION_DAYS

    command, args = _parse_args(["--rotate-history"])
    assert command == "rotate-history"
    assert args.days == DEFAULT_RETENTION_DAYS
    assert args.dry_run is False and args.include_human_records is False

    _, explicit = _parse_args(
        ["--rotate-history", "30", "--dry-run", "--include-human-records"]
    )
    assert explicit.days == 30
    assert explicit.dry_run and explicit.include_human_records


def test_rotate_history_rejects_a_nonpositive_retention(capsys):
    """A retention of 0 or -1 would archive the entire store, including
    records written seconds ago. argparse's own validation, same as the
    other windowed commands."""
    for bad in ("0", "-1"):
        with pytest.raises(SystemExit) as exc:
            _parse_args(["--rotate-history", bad])
        assert exc.value.code == 2
    assert "positive integer" in capsys.readouterr().err


def test_rotate_history_rejects_an_abbreviated_flag():
    """allow_abbrev=False is load-bearing across every command: `--dry`
    silently expanding to `--dry-run` would make the difference between a
    report and a data move a typo away."""
    with pytest.raises(SystemExit):
        _parse_args(["--rotate-history", "--dry"])
    with pytest.raises(SystemExit):
        _parse_args(["--rotate-history", "--include-human"])


def test_rotate_history_is_in_the_usage_text():
    """Every command this CLI accepts is listed, or an operator cannot
    discover the one that applies their retention policy."""
    from soc_copilot.main import USAGE

    assert "--rotate-history" in USAGE


def test_tuning_report_parses_its_optional_window():
    command, args = _parse_args(["--tuning-report"])
    assert command == "tuning-report"
    assert args.days is None            # all recorded history by default

    _, windowed = _parse_args(["--tuning-report", "30"])
    assert windowed.days == 30


def test_tuning_report_rejects_a_nonpositive_window(capsys):
    for bad in ("0", "-1"):
        with pytest.raises(SystemExit) as exc:
            _parse_args(["--tuning-report", bad])
        assert exc.value.code == 2
    assert "positive integer" in capsys.readouterr().err


def test_tuning_report_is_in_the_usage_text():
    from soc_copilot.main import USAGE

    assert "--tuning-report" in USAGE

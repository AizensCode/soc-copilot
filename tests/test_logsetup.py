"""The desk's voice (soc_copilot/logsetup.py): no API, no network.

What these pin: JSON mode emits one parseable object per line no matter
what the message contains; the correlation id rides the context and only
the context; configuration is idempotent and loudly rejects bad values;
and the handler writes to whatever sys.stderr IS at emit time, so
redirection (and pytest's own capture) keeps working.

    uv run pytest tests/test_logsetup.py -v
"""
import json
import logging

import pytest

from soc_copilot.logsetup import alert_context, configure_logging

log = logging.getLogger("soc_copilot.test_logsetup")


@pytest.fixture(autouse=True)
def _restore_logger_state():
    """configure_logging mutates the shared 'soc_copilot' logger; put it
    back so these tests never change how OTHER tests' records flow."""
    logger = logging.getLogger("soc_copilot")
    saved_handlers = list(logger.handlers)
    saved_level = logger.level
    yield
    logger.handlers = saved_handlers
    logger.setLevel(saved_level)


def _err_lines(capsys) -> list[str]:
    return [ln for ln in capsys.readouterr().err.splitlines() if ln]


# --- the JSON contract -------------------------------------------------------


def test_json_mode_emits_one_parseable_object_per_line(capsys):
    configure_logging("json", "INFO")
    log.info("first line\n  second line of the SAME message")
    [line] = _err_lines(capsys)                    # newline escaped, not torn
    doc = json.loads(line)
    assert doc["level"] == "INFO"
    assert "second line" in doc["msg"]
    assert "\n" in doc["msg"]


def test_json_ts_is_utc_iso8601_from_the_records_own_clock(capsys):
    from datetime import datetime

    configure_logging("json", "INFO")
    log.info("tick")
    [line] = _err_lines(capsys)
    ts = json.loads(line)["ts"]
    parsed = datetime.fromisoformat(ts)
    assert parsed.utcoffset() is not None and not parsed.utcoffset()


def test_alert_id_rides_the_context_and_only_the_context(capsys):
    configure_logging("json", "INFO")
    with alert_context("ALRT-42"):
        log.info("inside")
    log.info("outside")
    inside, outside = (json.loads(ln) for ln in _err_lines(capsys))
    assert inside["alert_id"] == "ALRT-42"
    assert "alert_id" not in outside


def test_nested_alert_context_restores_the_outer_id(capsys):
    configure_logging("json", "INFO")
    with alert_context("OUTER"):
        with alert_context("INNER"):
            log.info("deep")
        log.info("back")
    deep, back = (json.loads(ln) for ln in _err_lines(capsys))
    assert deep["alert_id"] == "INNER"
    assert back["alert_id"] == "OUTER"


def test_exception_info_lands_in_the_json_doc(capsys):
    configure_logging("json", "INFO")
    try:
        raise ValueError("boom")
    except ValueError:
        log.error("it broke", exc_info=True)
    [line] = _err_lines(capsys)
    doc = json.loads(line)
    assert "ValueError: boom" in doc["exc"]


# --- the text contract -------------------------------------------------------


def test_text_mode_is_exactly_the_message(capsys):
    """What print() said before is what text mode says now — no
    timestamp prefix (journald/docker stamp every line already)."""
    configure_logging("text", "INFO")
    log.info("hello %s", "operator")
    assert capsys.readouterr().err == "hello operator\n"


# --- configuration -----------------------------------------------------------


def test_configure_is_idempotent_never_stacking_handlers(capsys):
    configure_logging("text", "INFO")
    configure_logging("text", "INFO")
    log.info("once")
    assert _err_lines(capsys) == ["once"]
    assert len(logging.getLogger("soc_copilot").handlers) == 1


def test_reconfigure_switches_format_in_place(capsys):
    configure_logging("text", "INFO")
    configure_logging("json", "INFO")
    log.info("now json")
    [line] = _err_lines(capsys)
    assert json.loads(line)["msg"] == "now json"


def test_level_filters_below_the_configured_floor(capsys):
    configure_logging("text", "WARNING")
    log.info("dropped")
    log.warning("kept")
    assert _err_lines(capsys) == ["kept"]


def test_values_are_case_insensitive(capsys):
    configure_logging("JSON", "info")
    log.info("ok")
    assert json.loads(_err_lines(capsys)[0])["msg"] == "ok"


def test_invalid_format_raises_a_config_error_naming_the_valid_ones():
    with pytest.raises(RuntimeError, match="LOG_FORMAT.*text.*json"):
        configure_logging("yaml", "INFO")


def test_invalid_level_raises_a_config_error_naming_the_valid_ones():
    with pytest.raises(RuntimeError, match="LOG_LEVEL.*DEBUG.*ERROR"):
        configure_logging("text", "CHATTY")


def test_the_handler_writes_to_the_current_stderr(capsys):
    """StreamHandler binds its stream at construction; ours must not —
    a handler pinned to a replaced stderr would narrate into a dead
    buffer under redirection (and under pytest's capture, which is how
    every OTHER test in this file works at all). Configure ONCE, then
    emit under two different stderr objects: capsys gives each test a
    fresh capture, so the second emission only lands if the handler
    late-binds."""
    import sys

    configure_logging("text", "INFO")
    log.info("first stderr")
    assert capsys.readouterr().err == "first stderr\n"
    from io import StringIO

    replacement = StringIO()
    original = sys.stderr
    sys.stderr = replacement
    try:
        log.info("second stderr")
    finally:
        sys.stderr = original
    assert replacement.getvalue() == "second stderr\n"


def test_records_still_propagate_to_the_root_logger(caplog):
    """Propagation stays ON (nothing configures the root in this
    process, so nothing double-prints) — anything capturing at the root
    keeps seeing the records. This is also what keeps caplog-based
    tests working after configure_logging has run."""
    configure_logging("text", "INFO")
    with caplog.at_level(logging.INFO, logger="soc_copilot"):
        log.info("visible at the root")
    assert "visible at the root" in caplog.text


# --- delivering the level to journald ---------------------------------------
#
# A Python log level is an in-process fact: journald stamps every
# captured stream line at the unit's default priority (info), so the
# documented `journalctl -p warning` view showed NOTHING until the level
# was made to travel (review catch). When stderr IS the journal socket,
# each line gets the sd-daemon `<N>` prefix journald strips and records.


def _record(level: int, msg: str) -> logging.LogRecord:
    return logging.LogRecord(
        "soc_copilot.x", level, __file__, 1, msg, None, None
    )


def test_sd_prefix_maps_levels_to_syslog_priorities():
    from soc_copilot.logsetup import _SdPriorityFormatter

    fmt = _SdPriorityFormatter(logging.Formatter("%(message)s"))
    assert fmt.format(_record(logging.WARNING, "w")) == "<4>w"
    assert fmt.format(_record(logging.ERROR, "e")) == "<3>e"
    assert fmt.format(_record(logging.INFO, "i")) == "<6>i"
    assert fmt.format(_record(logging.DEBUG, "d")) == "<7>d"


def test_sd_prefix_covers_every_line_of_a_multiline_message():
    """journald treats each line as its own record; an unprefixed
    continuation line would silently fall back to info."""
    from soc_copilot.logsetup import _SdPriorityFormatter

    fmt = _SdPriorityFormatter(logging.Formatter("%(message)s"))
    out = fmt.format(_record(logging.WARNING, "first\nsecond"))
    assert out == "<4>first\n<4>second"


def test_sd_prefix_wraps_json_mode_intact():
    """journald strips the token before storing, so the journal's
    MESSAGE field is the clean JSON object — pin that the prefix sits
    OUTSIDE the JSON, not inside it."""
    from soc_copilot.logsetup import _JsonFormatter, _SdPriorityFormatter

    fmt = _SdPriorityFormatter(_JsonFormatter())
    out = fmt.format(_record(logging.ERROR, "boom"))
    assert out.startswith("<3>{")
    assert json.loads(out[3:])["level"] == "ERROR"


def test_journal_detection_requires_the_exact_devinode_match(monkeypatch):
    from types import SimpleNamespace

    from soc_copilot import logsetup

    class _FakeStderr:
        def fileno(self):
            return 99

    monkeypatch.setattr(logsetup.sys, "stderr", _FakeStderr())
    monkeypatch.setattr(
        logsetup.os, "fstat",
        lambda fd: SimpleNamespace(st_dev=12, st_ino=34),
    )
    monkeypatch.setenv("JOURNAL_STREAM", "12:34")
    assert logsetup._stderr_is_journal() is True
    monkeypatch.setenv("JOURNAL_STREAM", "12:35")   # journal is a DIFFERENT fd
    assert logsetup._stderr_is_journal() is False
    monkeypatch.delenv("JOURNAL_STREAM")
    assert logsetup._stderr_is_journal() is False


def test_journal_detection_survives_a_filenoless_stderr(monkeypatch):
    """pytest capture and StringIO redirection have no usable fileno —
    that must mean 'not the journal', never a crash at configure time."""
    import io

    from soc_copilot import logsetup

    monkeypatch.setenv("JOURNAL_STREAM", "12:34")
    monkeypatch.setattr(logsetup.sys, "stderr", io.StringIO())
    assert logsetup._stderr_is_journal() is False


def test_configure_installs_the_prefix_only_under_the_journal(
    monkeypatch, capsys
):
    from soc_copilot import logsetup

    monkeypatch.setattr(logsetup, "_stderr_is_journal", lambda: True)
    configure_logging("text", "INFO")
    log.warning("under journald")
    assert capsys.readouterr().err == "<4>under journald\n"

    monkeypatch.setattr(logsetup, "_stderr_is_journal", lambda: False)
    configure_logging("text", "INFO")
    log.warning("on a terminal")
    assert capsys.readouterr().err == "on a terminal\n"

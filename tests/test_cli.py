"""Unit tests for CLI argument parsing (no API, no network).

Born from a live catch: `--digest -1` silently ran the default 24h
window, because _arg_after's leading-dash check (there so a following
flag isn't consumed as a value) also swallowed negative numbers. A
numeric token is always the user's intended value — parse it, validate
it, and refuse it loudly rather than guessing.

    uv run pytest tests/test_cli.py -v
"""
import pytest

from src.main import _positive_int_after


def _argv(monkeypatch, *args):
    monkeypatch.setattr("sys.argv", ["src.main", *args])


def test_valid_value_is_parsed(monkeypatch):
    _argv(monkeypatch, "--digest", "48")
    assert _positive_int_after("--digest", 24, "window hours") == 48


def test_absent_value_falls_back_to_default(monkeypatch):
    _argv(monkeypatch, "--digest")
    assert _positive_int_after("--digest", 24, "window hours") == 24


def test_following_flag_is_not_consumed_as_a_value(monkeypatch):
    _argv(monkeypatch, "--watch", "--agentic")
    assert _positive_int_after("--watch", 60, "poll interval seconds") == 60


@pytest.mark.parametrize("bad", ["-1", "0", "abc", "--5", "1.5"])
def test_invalid_values_exit_loudly_instead_of_guessing(monkeypatch, bad, capsys):
    """The live bug: `--digest -1` ran a 24h window without a word."""
    _argv(monkeypatch, "--digest", bad)
    with pytest.raises(SystemExit) as exc:
        _positive_int_after("--digest", 24, "window hours")
    assert exc.value.code == 2
    assert "must be a positive integer" in capsys.readouterr().out

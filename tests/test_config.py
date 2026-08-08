"""Unit tests for lazy configuration (no API, no network).

The contract these lock in: importing the package and running the free
suite must work with an empty environment (that is what lets CI run
without secrets), while a real command that needs a key fails fast and
names the exact variable to set. Plus the env-override bug fix — two
settings were documented as overridable but silently weren't.

    uv run pytest tests/test_config.py -v
"""
import pytest

from src.config import Settings

_KEY_VARS = [
    "ANTHROPIC_API_KEY", "ABUSEIPDB_API_KEY",
    "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY",
]
_OTHER_VARS = [
    "ELASTIC_URL", "ELASTIC_API_KEY", "ELASTIC_ALERTS_INDEX",
    "ELASTIC_RESULTS_INDEX", "THEHIVE_URL", "THEHIVE_API_KEY",
    "THEHIVE_ORGANISATION", "HISTORY_PATH", "MODEL",
    "CORRELATION_WINDOW_HOURS",
]


@pytest.fixture
def clean_env(monkeypatch):
    """An environment with every soc-copilot variable removed — the state
    CI runs in. .env values loaded at import are cleared here too."""
    for var in _KEY_VARS + _OTHER_VARS:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def test_from_env_never_raises_on_missing_keys(clean_env):
    """The whole point: no keys, no crash — imports and the free suite
    must work in a secretless CI environment."""
    s = Settings.from_env()
    assert s.ANTHROPIC_KEY is None
    assert s.ABUSEIPDB_KEY is None
    # Non-secret defaults still populate.
    assert s.CORRELATION_WINDOW_HOURS == 72
    assert s.HISTORY_PATH == "data/history/investigations.jsonl"


def test_require_names_the_missing_env_vars(clean_env):
    s = Settings.from_env()
    with pytest.raises(RuntimeError) as exc:
        s.require("ANTHROPIC_KEY", "ABUSEIPDB_KEY")
    msg = str(exc.value)
    # Reports the env-var names a human sets, not the attribute names.
    assert "ANTHROPIC_API_KEY" in msg
    assert "ABUSEIPDB_API_KEY" in msg
    assert "ANTHROPIC_KEY" not in msg


def test_require_passes_when_present(clean_env):
    clean_env.setenv("ANTHROPIC_API_KEY", "sk-test")
    Settings.from_env().require("ANTHROPIC_KEY")  # no raise


def test_require_reports_only_the_missing_ones(clean_env):
    clean_env.setenv("ANTHROPIC_API_KEY", "sk-test")
    s = Settings.from_env()
    with pytest.raises(RuntimeError) as exc:
        s.require("ANTHROPIC_KEY", "URLSCAN_KEY")
    msg = str(exc.value)
    assert "URLSCAN_API_KEY" in msg
    assert "ANTHROPIC_API_KEY" not in msg  # the present one isn't named


def test_history_path_and_window_are_env_overridable(clean_env):
    """The bug fix: both were documented as overridable but from_env
    never read them, so the env var was silently ignored."""
    clean_env.setenv("HISTORY_PATH", "/tmp/custom/history.jsonl")
    clean_env.setenv("CORRELATION_WINDOW_HOURS", "48")
    s = Settings.from_env()
    assert s.HISTORY_PATH == "/tmp/custom/history.jsonl"
    assert s.CORRELATION_WINDOW_HOURS == 48


def test_absent_overrides_keep_the_defaults(clean_env):
    s = Settings.from_env()
    assert s.HISTORY_PATH == "data/history/investigations.jsonl"
    assert s.MODEL == "claude-sonnet-5"
    assert s.ELASTIC_ALERTS_INDEX == ".alerts-security.alerts-default"


def test_non_integer_window_fails_loudly(clean_env):
    clean_env.setenv("CORRELATION_WINDOW_HOURS", "not-a-number")
    with pytest.raises(RuntimeError, match="must be an integer"):
        Settings.from_env()

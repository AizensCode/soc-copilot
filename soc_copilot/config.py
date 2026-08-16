"""
Centralized configuration. Loads secrets from .env via python-dotenv.
Never hardcode API keys; never commit .env.

Loading is deliberately lazy: `from_env()` never raises for a missing
key, so importing any module (and running the free, network-free test
suite) works with no .env at all — the CI that guards this repo has no
secrets. A key is validated at the moment a command that needs it runs,
via `require()`, which names the exact environment variable to set. The
old behavior — demand all four keys at import — meant the 190+ offline
tests couldn't even import without a fully populated .env.
"""
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()

# Settings attribute -> the environment variable a human actually sets,
# so require()'s error message names what to add to .env.
_ENV_NAMES = {
    "ANTHROPIC_KEY": "ANTHROPIC_API_KEY",
    "ABUSEIPDB_KEY": "ABUSEIPDB_API_KEY",
    "VIRUSTOTAL_KEY": "VIRUSTOTAL_API_KEY",
    "URLSCAN_KEY": "URLSCAN_API_KEY",
}


@dataclass(frozen=True)
class Settings:
    ANTHROPIC_KEY: str | None = None
    ABUSEIPDB_KEY: str | None = None
    VIRUSTOTAL_KEY: str | None = None
    URLSCAN_KEY: str | None = None
    MODEL: str = "claude-sonnet-5"
    # The cheap first-pass model for tiered routing (--tiered). A high-
    # confidence, unambiguous false positive is finalized here; anything
    # else is promoted to MODEL. See soc_copilot/routing.py.
    TIER_CHEAP_MODEL: str = "claude-haiku-4-5"
    # Case-history store (cross-alert memory). Not a secret; overridable per env.
    HISTORY_PATH: str = "data/history/investigations.jsonl"
    # Temporal window (hours) for clustering alerts into a campaign.
    CORRELATION_WINDOW_HOURS: int = 72
    # How long after an investigation the watch loop may still FINISH it
    # from the record on disk rather than re-running it, when a crash or
    # kill left the alert un-acknowledged in Elastic (soc_copilot/resume.py).
    # 0 disables resuming: every re-opened alert then gets a fresh look.
    RESUME_WINDOW_MINUTES: int = 30
    # Elastic SIEM integration — optional; the copilot runs fine without it.
    ELASTIC_URL: str | None = None
    ELASTIC_API_KEY: str | None = None
    ELASTIC_ALERTS_INDEX: str = ".alerts-security.alerts-default"
    ELASTIC_RESULTS_INDEX: str = "soc-copilot-investigations"
    # Raw event telemetry the agentic search_internal_logs tool queries to
    # answer "did this actually happen?" pivots. Optional; the tool
    # degrades gracefully when unset.
    ELASTIC_EVENTS_INDEX: str = "soc-events-demo"
    # TheHive case management — optional; the copilot runs fine without it.
    THEHIVE_URL: str | None = None
    THEHIVE_API_KEY: str | None = None
    THEHIVE_ORGANISATION: str | None = None
    # Escalation webhook (Slack/Mattermost/generic) — optional. When set and
    # --notify is passed in watch mode, escalations and campaigns POST here.
    WEBHOOK_URL: str | None = None
    # How the CLI narrates (soc_copilot/logsetup.py): "text" is exactly
    # the prose print() produced; "json" is one machine-parseable object
    # per line for a log shipper. Validated loudly at startup.
    LOG_FORMAT: str = "text"
    LOG_LEVEL: str = "INFO"

    def require(self, *attrs: str) -> None:
        """Assert the given settings are present, or raise naming the
        exact environment variables to set. Called at CLI entry points
        (not in the library) so imports and injected-client tests stay
        key-free while a real keyless run fails fast and legibly."""
        missing = [
            _ENV_NAMES.get(a, a) for a in attrs if not getattr(self, a)
        ]
        if missing:
            raise RuntimeError(
                f"Missing required environment variable(s): "
                f"{', '.join(missing)}. Add them to your .env file."
            )

    @classmethod
    def from_env(cls) -> "Settings":
        # Only override a default when the env var is actually set, so the
        # dataclass defaults stay the single source of truth (and a typo'd
        # HISTORY_PATH env var can't silently blank the path).
        overrides: dict[str, object] = {
            "ANTHROPIC_KEY": os.environ.get("ANTHROPIC_API_KEY"),
            "ABUSEIPDB_KEY": os.environ.get("ABUSEIPDB_API_KEY"),
            "VIRUSTOTAL_KEY": os.environ.get("VIRUSTOTAL_API_KEY"),
            "URLSCAN_KEY": os.environ.get("URLSCAN_API_KEY"),
            "ELASTIC_URL": os.environ.get("ELASTIC_URL"),
            "ELASTIC_API_KEY": os.environ.get("ELASTIC_API_KEY"),
            "THEHIVE_URL": os.environ.get("THEHIVE_URL"),
            "THEHIVE_API_KEY": os.environ.get("THEHIVE_API_KEY"),
            "THEHIVE_ORGANISATION": os.environ.get("THEHIVE_ORGANISATION"),
            "WEBHOOK_URL": os.environ.get("WEBHOOK_URL"),
        }
        # These two carry non-None defaults and were previously documented
        # as env-overridable but silently weren't — only override when set.
        for name in ("ELASTIC_ALERTS_INDEX", "ELASTIC_RESULTS_INDEX",
                     "ELASTIC_EVENTS_INDEX", "HISTORY_PATH", "MODEL",
                     "TIER_CHEAP_MODEL", "LOG_FORMAT", "LOG_LEVEL"):
            if (val := os.environ.get(name)) is not None:
                overrides[name] = val
        # Integer settings: a typo must fail loudly at startup rather than
        # silently falling back to the default (which for a WINDOW would
        # mean quietly using a different policy than the operator set).
        for name in ("CORRELATION_WINDOW_HOURS", "RESUME_WINDOW_MINUTES"):
            if (raw := os.environ.get(name)) is not None:
                try:
                    overrides[name] = int(raw)
                except ValueError:
                    raise RuntimeError(
                        f"{name} must be an integer, got {raw!r}"
                    )
        return cls(**overrides)


settings = Settings.from_env()

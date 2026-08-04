"""
Centralized configuration. Loads secrets from .env via python-dotenv.
Never hardcode API keys; never commit .env.
"""
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    ANTHROPIC_KEY: str
    ABUSEIPDB_KEY: str
    VIRUSTOTAL_KEY: str
    URLSCAN_KEY: str
    MODEL: str = "claude-sonnet-5"
    # Case-history store (cross-alert memory). Not a secret; overridable per env.
    HISTORY_PATH: str = "data/history/investigations.jsonl"
    # Temporal window (hours) for clustering alerts into a campaign.
    CORRELATION_WINDOW_HOURS: int = 72
    # Elastic SIEM integration — optional; the copilot runs fine without it.
    ELASTIC_URL: str | None = None
    ELASTIC_API_KEY: str | None = None
    ELASTIC_ALERTS_INDEX: str = ".alerts-security.alerts-default"
    ELASTIC_RESULTS_INDEX: str = "soc-copilot-investigations"
    # TheHive case management — optional; the copilot runs fine without it.
    THEHIVE_URL: str | None = None
    THEHIVE_API_KEY: str | None = None
    THEHIVE_ORGANISATION: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
        abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY")
        virustotal_key = os.environ.get("VIRUSTOTAL_API_KEY")
        urlscan_key = os.environ.get("URLSCAN_API_KEY")

        missing = []
        if not anthropic_key:
            missing.append("ANTHROPIC_API_KEY")
        if not abuseipdb_key:
            missing.append("ABUSEIPDB_API_KEY")
        if not virustotal_key:
            missing.append("VIRUSTOTAL_API_KEY")
        if not urlscan_key:
            missing.append("URLSCAN_API_KEY")

        if missing:
            raise RuntimeError(
                f"Missing required environment variables: {', '.join(missing)}. "
                f"Add them to your .env file."
            )

        return cls(
            ANTHROPIC_KEY=anthropic_key,
            ABUSEIPDB_KEY=abuseipdb_key,
            VIRUSTOTAL_KEY=virustotal_key,
            URLSCAN_KEY=urlscan_key,
            ELASTIC_URL=os.environ.get("ELASTIC_URL"),
            ELASTIC_API_KEY=os.environ.get("ELASTIC_API_KEY"),
            ELASTIC_ALERTS_INDEX=os.environ.get(
                "ELASTIC_ALERTS_INDEX", ".alerts-security.alerts-default"
            ),
            ELASTIC_RESULTS_INDEX=os.environ.get(
                "ELASTIC_RESULTS_INDEX", "soc-copilot-investigations"
            ),
            THEHIVE_URL=os.environ.get("THEHIVE_URL"),
            THEHIVE_API_KEY=os.environ.get("THEHIVE_API_KEY"),
            THEHIVE_ORGANISATION=os.environ.get("THEHIVE_ORGANISATION"),
        )


settings = Settings.from_env()
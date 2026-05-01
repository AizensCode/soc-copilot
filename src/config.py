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
    MODEL: str = "claude-sonnet-4-6" # upgrade to claude-sonnet-4-6 for agentic phase; use claude-opus-4-7 only for final eval runs

    @classmethod
    def from_env(cls) -> "Settings":
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
        abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY")
        virustotal_key = os.environ.get("VIRUSTOTAL_API_KEY")

        missing = []
        if not anthropic_key:
            missing.append("ANTHROPIC_API_KEY")
        if not abuseipdb_key:
            missing.append("ABUSEIPDB_API_KEY")
        if not virustotal_key:
            missing.append("VIRUSTOTAL_API_KEY")

        if missing:
            raise RuntimeError(
                f"Missing required environment variables: {', '.join(missing)}. "
                f"Add them to your .env file."
            )

        return cls(ANTHROPIC_KEY=anthropic_key, ABUSEIPDB_KEY=abuseipdb_key, VIRUSTOTAL_KEY=virustotal_key)


settings = Settings.from_env()
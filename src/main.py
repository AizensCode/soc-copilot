"""CLI entry point. Run with: uv run python -m src.main <alert.json>"""
import asyncio
import json
import sys
from pathlib import Path

from .copilot import SOCCopilot
from .models import Alert


async def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m src.main <path/to/alert.json> [--agentic]")
        sys.exit(1)

    alert_path = Path(sys.argv[1])
    agentic_mode = "--agentic" in sys.argv

    with alert_path.open() as f:
        alert = Alert(**json.load(f))

    copilot = SOCCopilot()

    if agentic_mode:
        print(f"[mode: agentic — model decides tool calls]")
        investigation = await copilot.investigate_agentic(alert)
    else:
        print(f"[mode: phase one — fixed enrichment pipeline]")
        investigation = await copilot.investigate(alert)

    debug_path = Path("last_run_debug.json")
    with debug_path.open("w") as f:
        json.dump(
            {
                "mode": "agentic" if agentic_mode else "phase_one",
                "alert": alert.model_dump(mode="json"),
                "evidence_raw": [
                    e.model_dump(mode="json") for e in investigation.evidence
                ],
                "investigation": investigation.model_dump(mode="json"),
            },
            f,
            indent=2,
            default=str,
        )
    print(f"Full debug written to {debug_path}")
    print(investigation.model_dump_json(indent=2))


if __name__ == "__main__":
    asyncio.run(main())
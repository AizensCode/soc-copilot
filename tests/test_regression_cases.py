"""Replay analyst-ruled cases against the live copilot (API-backed).

Every file under data/evals/cases/ is an investigation a human ruled
on, exported by --export-case. The copilot re-investigates the same
alert (isolated store — no memory leakage from the operator's real
history) and its verdict is checked against the ANALYST's ruling, the
one label in this project that is ground truth rather than taste.

Cases where the copilot already agreed at export time are hard
regression gates. Cases exported as disagreements are declared
improvement targets: xfail, so a known-wrong verdict doesn't break the
suite, and an XPASS is the visible moment the copilot earned the case.

    uv run pytest tests/test_regression_cases.py -v
"""
import json
from pathlib import Path

import pytest

from soc_copilot.copilot import SOCCopilot
from soc_copilot.history import AlertHistoryStore
from soc_copilot.models import Alert

CASES_DIR = Path("data/evals/cases")
CASES = sorted(CASES_DIR.glob("*.json")) if CASES_DIR.is_dir() else []

pytestmark = pytest.mark.live


@pytest.mark.parametrize("case_path", CASES, ids=lambda p: p.stem)
async def test_verdict_matches_the_analyst_ruling(case_path, tmp_path, request):
    case = json.loads(case_path.read_text())
    if not case["agreed_at_export"]:
        request.applymarker(
            pytest.mark.xfail(
                reason=(
                    f"declared improvement target: copilot said "
                    f"{case['copilot_verdict_at_export']}, analyst ruled "
                    f"{case['label']['human_verdict']}"
                ),
                strict=False,
            )
        )

    copilot = SOCCopilot(
        history_store=AlertHistoryStore(tmp_path / "isolated.jsonl")
    )
    investigation = await copilot.investigate(Alert(**case["alert"]))
    assert investigation.verdict == case["label"]["human_verdict"], (
        f"analyst ruled {case['label']['human_verdict']} "
        f"({case['label']['source']}"
        + (f', note: "{case["label"]["summary"]}"' if case["label"]["summary"] else "")
        + f"), copilot now says {investigation.verdict}"
    )

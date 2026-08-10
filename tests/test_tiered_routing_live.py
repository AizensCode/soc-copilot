"""Live safety eval for tiered routing (makes real cheap-model API calls).

The one property that makes tiering safe to run unattended: the CHEAP
tier may never be the last word on an attack. This runs every
attack-labeled fixture through a phase-one investigation on the cheap
model and asserts the promotion gate sends it to the strong model —
whatever the cheap model concluded. It is the tiering analogue of the
auto-close safety gate (no attack fixture ever qualifies for autonomous
closure), and it reuses the harness's own labels as ground truth.

Calibration behind the pin (see the increment's write-up): across 3 runs
of each attack fixture, the cheap model (Haiku) called every one
true_positive/high — so promotion here is driven by the cheap model's
own verdict, not only by the gate's severity backstop. The economics
side (benign twins finalize on the cheap tier, 8/8 in calibration) is
deliberately NOT pinned hard: a benign twin that gets promoted is safe,
merely less economical, and pinning it would fail the suite on a
safe drift.

    uv run pytest tests/test_tiered_routing_live.py -v
"""
import pytest

from soc_copilot.config import settings
from soc_copilot.copilot import SOCCopilot
from soc_copilot.routing import should_promote

from .alert_loading import SAMPLE_ALERTS_DIR, load_alert_fixture
from .expectations import EXPECTATIONS

pytestmark = pytest.mark.live


def _attack_fixtures() -> list[str]:
    """Fixtures whose expectations do NOT permit false_positive — the
    harness's own labels, reused as 'this is an attack'."""
    out = []
    for fixture, exp in EXPECTATIONS.items():
        permitted = exp.get("allowed_verdicts") or [exp.get("expected_verdict")]
        if "false_positive" not in permitted:
            out.append(fixture)
    return out


@pytest.mark.parametrize("fixture", _attack_fixtures())
async def test_no_attack_is_finalized_by_the_cheap_tier(
    copilot: SOCCopilot, fixture: str
):
    alert = load_alert_fixture(SAMPLE_ALERTS_DIR / fixture)
    inv = await copilot.investigate(
        alert, model=settings.TIER_CHEAP_MODEL, record=False
    )
    promote, reason = should_promote(inv, alert)
    assert promote, (
        f"{fixture}: the cheap tier FINALIZED an attack-labeled alert "
        f"(verdict={inv.verdict}, confidence={inv.confidence}) — it must be "
        f"promoted to the strong model. Reason returned: {reason!r}"
    )

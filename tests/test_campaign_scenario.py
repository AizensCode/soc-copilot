"""The campaign scenario — the one deliberately memory-COUPLED eval.

The labeled set under `data/sample_alerts/` is memory-DEcoupled on
purpose: shared indicators make results depend on execution order, so
`tests/test_fixtures.py` forbids them. The cost of that rule is that the
most interesting behavior in the copilot's memory — what it does when
alerts really are related — cannot be measured there.

This module is the counterpart. It runs
`data/scenarios/campaign_ci_compromise/` (three stages of one intrusion,
see that directory's README) in chronological order through a PRIVATE
history store per mode, and asserts two different kinds of claim:

* the deterministic correlation curve — isolated, then related-but-below
  threshold, then campaign — including the fact that it holds ACROSS
  ingestion shapes (stage 1 is an ECS hit, stages 2-3 are native EDR
  fixtures), which is what `history.alert_host` exists for;
* what the model does with that context once it has it.

Live API calls (marked `live`), 3 investigations per mode.

    uv run pytest tests/test_campaign_scenario.py -v
"""
from pathlib import Path

import pytest
import pytest_asyncio

from src.copilot import SOCCopilot
from src.history import CAMPAIGN_MIN_RELATED, AlertHistoryStore
from src.models import Alert, Investigation

from .alert_loading import load_alert_fixture

pytestmark = pytest.mark.live

CAMPAIGN_DIR = Path("data/scenarios/campaign_ci_compromise")
MODES = ["phase_one", "agentic"]

STAGE_1 = "ALRT-2026-0610-101"   # external SSH auth  (ECS-shaped)
STAGE_2 = "ALRT-2026-0611-102"   # LSASS credential access (native)
STAGE_3 = "ALRT-2026-0611-103"   # staging + exfiltration  (native)

SHARED_IP = "107.189.31.187"
SHARED_HOST = "bld-ci-04.corp.internal"


def _stage_files() -> list[Path]:
    files = sorted(CAMPAIGN_DIR.glob("*.json"))
    assert len(files) == 3, f"expected 3 scenario stages, found {len(files)}"
    return files


@pytest_asyncio.fixture(scope="module")
async def campaign(tmp_path_factory) -> dict[str, list[tuple[Alert, Investigation]]]:
    """Run the scenario once per mode, in order, each in its own store.

    A private store per mode is the whole point: these alerts SHARE
    indicators, so they must never see the labeled set's history (or each
    other's mode).
    """
    runs: dict[str, list[tuple[Alert, Investigation]]] = {}
    for mode in MODES:
        store = AlertHistoryStore(
            tmp_path_factory.mktemp(f"campaign_{mode}") / "investigations.jsonl"
        )
        copilot = SOCCopilot(history_store=store)
        sequence: list[tuple[Alert, Investigation]] = []
        for path in _stage_files():
            alert = load_alert_fixture(path)
            investigation = (
                await copilot.investigate_agentic(alert)
                if mode == "agentic"
                else await copilot.investigate(alert)
            )
            sequence.append((alert, investigation))
        runs[mode] = sequence
    return runs


# --- the deterministic correlation curve -------------------------------------


@pytest.mark.parametrize("mode", MODES)
def test_first_stage_stands_alone(campaign, mode):
    """Nothing precedes stage 1, so memory must be empty — no phantom
    priors conjured from an alert's own content."""
    _, inv = campaign[mode][0]
    assert inv.prior_sightings == []
    assert inv.correlation is not None
    assert inv.correlation.is_campaign is False
    assert inv.correlation.related_alerts == []


@pytest.mark.parametrize("mode", MODES)
def test_second_stage_recalls_the_first(campaign, mode):
    """One related prior is related activity, not yet a campaign —
    the threshold has to mean something."""
    _, inv = campaign[mode][1]
    assert [s.alert_id for s in inv.prior_sightings] == [STAGE_1]
    assert SHARED_IP in inv.prior_sightings[0].matched_iocs
    assert inv.correlation is not None
    assert [r.alert_id for r in inv.correlation.related_alerts] == [STAGE_1]
    assert inv.correlation.is_campaign is False, (
        f"{CAMPAIGN_MIN_RELATED} related priors are required for a campaign; "
        f"one must not be enough"
    )


@pytest.mark.parametrize("mode", MODES)
def test_third_stage_is_recognized_as_a_campaign(campaign, mode):
    """Two related priors cross the threshold: the copilot must see one
    intrusion, not three unrelated alerts."""
    _, inv = campaign[mode][2]
    assert inv.correlation is not None
    assert inv.correlation.is_campaign is True
    assert sorted(r.alert_id for r in inv.correlation.related_alerts) == [
        STAGE_1,
        STAGE_2,
    ]
    assert sorted(s.alert_id for s in inv.prior_sightings) == [STAGE_1, STAGE_2]
    assert "campaign" in inv.correlation.summary.lower()


@pytest.mark.parametrize("mode", MODES)
def test_campaign_survives_crossing_ingestion_shapes(campaign, mode):
    """Stage 1 arrives ECS-shaped (host as {"name": ...}), stages 2-3
    native (host as a string). If memory compared those literally, the
    campaign would silently break into unrelated alerts — which is why
    history.alert_host normalizes both. Assert the host link explicitly.
    """
    _, inv = campaign[mode][2]
    signals_by_alert = {
        r.alert_id: r.signals for r in inv.correlation.related_alerts
    }
    assert f"shared_host:{SHARED_HOST}" in signals_by_alert[STAGE_1], (
        "the ECS-shaped first stage did not link by host — cross-shape "
        "host normalization regressed"
    )
    assert f"shared_host:{SHARED_HOST}" in signals_by_alert[STAGE_2]


# --- what the model does with the context ------------------------------------


@pytest.mark.parametrize("mode", MODES)
def test_no_stage_of_a_real_intrusion_is_dismissed(campaign, mode):
    """Every stage is genuinely malicious. A false_positive anywhere in
    this sequence is the failure this scenario exists to catch."""
    for (alert, inv), stage in zip(campaign[mode], ("1", "2", "3")):
        assert inv.verdict != "false_positive", (
            f"stage {stage} ({alert.alert_id}) dismissed as false_positive: "
            f"{inv.hypothesis[:200]}"
        )


@pytest.mark.parametrize("mode", MODES)
def test_every_stage_escalates(campaign, mode):
    """External auth to build infrastructure, LSASS access, and 2.4 GB
    of egress each warrant a human on their own (18/18 in calibration).
    This is also the closure policy's safety net under load: nothing in
    an active intrusion may drift into auto-close territory."""
    for (alert, inv), stage in zip(campaign[mode], ("1", "2", "3")):
        assert inv.escalation_recommended is True, (
            f"stage {stage} ({alert.alert_id}) did not escalate"
        )


@pytest.mark.parametrize("mode", MODES)
def test_campaign_stage_is_a_confident_true_positive(campaign, mode):
    """By stage 3 the copilot holds enrichment evidence AND two related
    priors on the same host. Hedging with that much corroboration is the
    regression to catch — calibration: 6/6 true_positive at high
    confidence."""
    _, inv = campaign[mode][2]
    assert inv.verdict == "true_positive"
    assert inv.confidence == "high"


@pytest.mark.parametrize("mode", MODES)
def test_campaign_stage_maps_collection_and_exfiltration(campaign, mode):
    """A 2.4 GB archive staged from the repo mirror and pushed to a
    bulletproof host is collection THEN exfiltration. T1560 (archive
    collected data) was mapped 6/6; the exfil family is left as an
    any-of because channel choice — over-C2 (T1041), alternative
    protocol (T1048), web service (T1567) — is a defensible analyst
    judgment and pinning one would punish the others."""
    _, inv = campaign[mode][2]
    blob = " ".join(inv.attack_techniques)
    assert "T1560" in blob, (
        f"staging a 7z archive of the repo mirror is T1560: "
        f"{inv.attack_techniques}"
    )
    assert any(code in blob for code in ("T1041", "T1048", "T1567", "T1030")), (
        f"no exfiltration technique mapped on the exfil stage: "
        f"{inv.attack_techniques}"
    )


# Per-stage technique discipline, calibrated 6/6 in both directions:
# what the evidence shows must be mapped, and the neighbouring families
# an over-eager mapper would reach for must not be.
_STAGE_TECHNIQUES = [
    # stage 1: publickey auth SUCCEEDED, so valid-account use is OBSERVED
    # (the required side of the T1078 triangulation). Nothing was guessed
    # and nothing was delivered.
    (0, ["T1078"], ["T1110", "T1566"]),
    # stage 2: a handle into LSASS is credential dumping, full stop.
    (1, ["T1003"], ["T1566"]),
    # stage 3: nothing was ever brute-forced, so T1110 stays out. T1078 is
    # deliberately NOT required here even though 5/6 runs mapped it: the
    # behavior THIS alert shows is staging and exfiltration, and an analyst
    # who maps only that — leaving valid-account use to the stages where it
    # was the observed event — is exercising the same discipline, not
    # missing something. (I pinned T1078 here on a first pass without
    # measuring it, having measured only stage 1; the sixth calibration
    # sequence and then this test disagreed. Requiring the un-calibrated
    # is how expectations quietly become taste.)
    (2, [], ["T1110"]),
]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("index,required,forbidden", _STAGE_TECHNIQUES)
def test_stage_techniques_track_observed_behavior(
    campaign, mode, index, required, forbidden
):
    alert, inv = campaign[mode][index]
    blob = " ".join(inv.attack_techniques)
    missing = [t for t in required if t not in blob]
    leaked = [t for t in forbidden if t in blob]
    assert not missing, (
        f"{alert.alert_id} [{mode}]: missing {missing} from "
        f"{inv.attack_techniques}"
    )
    assert not leaked, (
        f"{alert.alert_id} [{mode}]: mapped {leaked} without evidence — "
        f"{inv.attack_techniques}"
    )


@pytest.mark.parametrize("mode", MODES)
def test_prior_sighting_reaches_the_writeup_before_the_campaign_does(
    campaign, mode
):
    """Stage 2 is below the campaign threshold, so nothing flags it as a
    campaign — but the copilot has one prior sighting, and memory is only
    worth having if it reaches the human. Calibration: 6/6 named the
    prior alert by ID *and* cited the shared source IP.
    """
    _, inv = campaign[mode][1]
    assert inv.correlation is not None and not inv.correlation.is_campaign
    text = " ".join(
        [inv.hypothesis, inv.escalation_draft or ""]
        + [f"{p.action} {p.rationale}" for p in inv.suggested_pivots]
    ).lower()
    assert STAGE_1.lower() in text or SHARED_IP in text, (
        f"stage 2 write-up never mentions the related prior alert: "
        f"{text[:400]}"
    )


@pytest.mark.parametrize("mode", MODES)
def test_campaign_is_named_in_the_analyst_writeup(campaign, mode):
    """The correlation is only useful if it reaches the human. The
    write-up for stage 3 must connect this alert to the earlier activity
    — by campaign language, by a prior alert id, or by the shared
    infrastructure that links them."""
    _, inv = campaign[mode][2]
    text = " ".join(
        [inv.hypothesis, inv.escalation_draft or ""]
        + [f"{p.action} {p.rationale}" for p in inv.suggested_pivots]
    ).lower()
    assert any(
        marker in text
        for marker in (
            "campaign",
            "earlier alert",
            "prior alert",
            "related alert",
            STAGE_1.lower(),
            STAGE_2.lower(),
            SHARED_IP,
            "credential",       # the stage-2 activity, referenced by name
        )
    ), f"stage 3 write-up never connects to the earlier stages: {text[:400]}"

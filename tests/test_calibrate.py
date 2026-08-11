"""The calibration runner's arithmetic and report shape, proven API-free.

The runner's value is that its pass-rates are trustworthy, so the two
things that must be exactly right — the k/n counting and the marginal-pin
call-out — are tested against a SCRIPTED model that returns known verdicts,
with no network. `run_calibration` takes its investigate function as an
argument precisely so this test can drive it deterministically.

    uv run pytest tests/test_calibrate.py -v
"""
from soc_copilot.models import Investigation

from .calibrate import format_report, run_calibration, tally

_EXP = {
    "fix.json": {"expected_verdict": "true_positive", "min_confidence": "high"},
}


def _inv(verdict="true_positive", confidence="high", escalate=True) -> Investigation:
    return Investigation(
        alert_id="A", verdict=verdict, confidence=confidence,
        hypothesis="h", escalation_recommended=escalate,
    )


def test_tally_counts_pass_rate_per_property():
    # 4 clean runs + 2 that miss confidence (medium < high) in one cell.
    results = (
        [("fix.json", "phase_one", _inv())] * 4
        + [("fix.json", "phase_one", _inv(confidence="medium"))] * 2
    )
    report = tally(results, _EXP)
    cell = report["fixtures"]["fix.json"]["phase_one"]
    assert cell["runs"] == 6
    assert cell["properties"]["verdict"] == {"pass": 6, "n": 6}
    assert cell["properties"]["confidence"] == {"pass": 4, "n": 6}
    assert cell["confidences"] == {"high": 4, "medium": 2}


def test_marginal_pins_are_called_out_but_clean_ones_are_not():
    # 6 clean runs + 1 that misses confidence: verdict stays 7/7 (clean),
    # confidence is 6/7 (marginal).
    results = (
        [("fix.json", "phase_one", _inv())] * 6
        + [("fix.json", "phase_one", _inv(confidence="low"))]
    )
    report = tally(results, _EXP)
    marginal = {(m["property"], m["pass"], m["n"]) for m in report["marginal"]}
    assert ("confidence", 6, 7) in marginal   # 6 of 7 passed -> marginal
    assert not any(m["property"] == "verdict" for m in report["marginal"])  # 7/7 clean


def test_autoclose_safety_is_tracked_as_a_calibration_property():
    # An attack fixture where one sample is misread as a closeable FP.
    results = (
        [("fix.json", "phase_one", _inv())] * 5
        # a high-confidence FP with no escalation is what would auto-close
        + [("fix.json", "phase_one", _inv(verdict="false_positive", escalate=False))]
    )
    report = tally(results, _EXP)
    props = report["fixtures"]["fix.json"]["phase_one"]["properties"]
    assert "autoclose_safe" in props
    assert props["autoclose_safe"] == {"pass": 5, "n": 6}
    assert any(m["property"] == "autoclose_safe" for m in report["marginal"])


async def test_run_calibration_drives_the_grid_with_an_injected_function():
    """The runner executes fixture × mode × n and hands each sample to the
    injected investigate fn — no copilot, no API."""
    calls = []

    async def fake_investigate(alert, mode):
        calls.append((alert.alert_id, mode))
        return _inv()

    successes, failures = await run_calibration(
        ["brute_force_ssh.json"], ("phase_one", "agentic"), n=3,
        investigate=fake_investigate,
    )
    assert len(successes) == 6 and not failures  # 1 fixture × 2 modes × 3 runs
    assert len(calls) == 6
    assert {m for _, m in calls} == {"phase_one", "agentic"}


async def test_a_crashing_run_is_recorded_as_a_failure_not_an_aborted_batch():
    """One flaky live run (the copilot raising RuntimeError on max_iterations)
    must not throw away every completed run of an expensive sweep — it is
    caught and reported, and never folded into the pass count (review catch)."""
    seen = 0

    async def flaky(alert, mode):
        nonlocal seen
        seen += 1
        if seen == 2:
            raise RuntimeError("exceeded max_iterations")
        return _inv()

    successes, failures = await run_calibration(
        ["brute_force_ssh.json"], ("phase_one",), n=3, investigate=flaky,
    )
    assert len(successes) == 2 and len(failures) == 1
    assert "max_iterations" in failures[0][2]
    # the failed run is NOT counted as a pass: n reflects only successes.
    # (brute_force_ssh pins verdict=true_positive, which both _inv() match.)
    cell = tally(successes)["fixtures"]["brute_force_ssh.json"]["phase_one"]
    assert cell["properties"]["verdict"] == {"pass": 2, "n": 2}


async def test_cassette_miss_still_aborts_rather_than_being_recorded():
    """A CassetteMiss is a correctness problem (an unrecorded indicator),
    not a flaky run, so it must propagate — never be caught as a failure."""
    from .cassette import CassetteMiss

    async def missing(alert, mode):
        raise CassetteMiss("no recorded abuseipdb response for 9.9.9.9")

    import pytest
    with pytest.raises(CassetteMiss):
        await run_calibration(["brute_force_ssh.json"], ("phase_one",), n=1,
                              investigate=missing)


async def test_make_default_investigate_threads_the_model_through(monkeypatch):
    """The A/B harness's entire premise is that each side runs ITS model.
    Pin the pass-through hermetically: the investigate fn built with
    model="m-x" must call the copilot with model="m-x" (and record=False)
    in both modes — a dropped `model=model` would silently A/B the default
    model against itself while labeled baseline-vs-candidate."""
    from .alert_loading import SAMPLE_ALERTS_DIR, load_alert_fixture
    from .calibrate import make_default_investigate

    seen = []

    class _Stub:
        async def investigate(self, alert, model=None, record=True):
            seen.append(("phase_one", model, record))
            return _inv()

        async def investigate_agentic(self, alert, model=None, record=True):
            seen.append(("agentic", model, record))
            return _inv()

    monkeypatch.setattr("tests.calibrate.make_copilot", lambda **kw: _Stub())
    alert = load_alert_fixture(SAMPLE_ALERTS_DIR / "brute_force_ssh.json")
    investigate = make_default_investigate(cassette=None, model="m-x")
    await investigate(alert, "agentic")
    await investigate(alert, "phase_one")
    assert seen == [("agentic", "m-x", False), ("phase_one", "m-x", False)]


def test_format_report_flags_marginal_pins_visibly():
    results = [("fix.json", "phase_one", _inv())] * 5 + [
        ("fix.json", "phase_one", _inv(confidence="low"))
    ]
    text = format_report(tally(results, _EXP), {"n": 6, "model": "default"})
    assert "confidence=5/6*" in text        # the star marks the marginal one
    assert "MARGINAL PINS" in text


def test_format_report_says_so_when_everything_is_clean():
    results = [("fix.json", "phase_one", _inv())] * 6
    text = format_report(tally(results, _EXP), {"n": 6, "model": "default"})
    assert "passed every run" in text
    assert "MARGINAL" not in text

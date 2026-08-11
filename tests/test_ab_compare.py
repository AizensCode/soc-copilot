"""The A/B diff's arithmetic and report shape, proven API-free.

Same philosophy as test_calibrate.py: the harness's value is that its
diff is trustworthy, so classification (regression / improvement /
unchanged / incomparable), the k/k boundary flags, the proportion-based
distribution-shift rule, and both CLI paths are tested against reports
built by the REAL tally() from scripted Investigations — never
hand-forged shapes that could drift from what tally actually emits. The
live _main path runs here too, against an injected fake sweep, so the
diff's direction (candidate-worse == regression) and the candidate-first
spend order are pinned rather than assumed.

    uv run pytest tests/test_ab_compare.py -v
"""
import json

import pytest

from soc_copilot.models import Investigation

from . import ab_compare
from .ab_compare import _main, diff_reports, format_diff
from .calibrate import tally, write_report

_EXP = {
    "fix.json": {"expected_verdict": "true_positive", "min_confidence": "high"},
}
_EXP_SPLIT = {
    "fix.json": {"allowed_verdicts": ["true_positive", "inconclusive"]},
}


def _inv(verdict="true_positive", confidence="high") -> Investigation:
    return Investigation(
        alert_id="A", verdict=verdict, confidence=confidence,
        hypothesis="h", escalation_recommended=True,
    )


def _report(invs, expectations=_EXP, mode="phase_one"):
    return tally([("fix.json", mode, inv) for inv in invs], expectations)


def _no_live(monkeypatch):
    """Backstop for CLI tests that must die at argparse: if the gate under
    test regresses, fail HERE — loudly and offline — rather than letting
    _main proceed into a real double sweep of live API calls (review
    catch: the gate's SystemExit was the only barrier)."""
    def boom():
        raise AssertionError("cost gate breached — a live sweep was attempted")
    monkeypatch.setattr(ab_compare.ReputationCassette, "load", staticmethod(boom))


def test_diff_classifies_regression_improvement_and_unchanged():
    # baseline: verdict 6/6, confidence 4/6. candidate: verdict 5/6 (worse),
    # confidence 6/6 (better). Everything else identical.
    base = _report([_inv()] * 4 + [_inv(confidence="medium")] * 2)
    cand = _report([_inv()] * 5 + [_inv(verdict="inconclusive")])
    diff = diff_reports(base, cand)

    assert [e["property"] for e in diff["regressions"]] == ["verdict"]
    assert diff["regressions"][0]["baseline"] == {"pass": 6, "n": 6}
    assert diff["regressions"][0]["candidate"] == {"pass": 5, "n": 6}
    assert [e["property"] for e in diff["improvements"]] == ["confidence"]
    assert "autoclose_safe" in [e["property"] for e in diff["unchanged"]]


def test_the_kk_boundary_is_flagged_both_ways():
    # verdict was solid (6/6) and regressed -> newly_marginal; confidence
    # was marginal and became solid -> newly_solid.
    base = _report([_inv()] * 4 + [_inv(confidence="medium")] * 2)
    cand = _report([_inv()] * 5 + [_inv(verdict="inconclusive")])
    diff = diff_reports(base, cand)

    assert diff["regressions"][0]["newly_marginal"] is True
    assert diff["improvements"][0]["newly_solid"] is True


def test_rates_not_counts_are_compared_when_n_differs():
    # baseline 6/6; candidate 3/3 (half its runs failed and were excluded).
    # 100% == 100%: unchanged, not a phantom regression from 6 > 3.
    base = _report([_inv()] * 6)
    cand = _report([_inv()] * 3)
    diff = diff_reports(base, cand)

    assert not diff["regressions"] and not diff["improvements"]
    verdict = next(e for e in diff["unchanged"] if e["property"] == "verdict")
    assert verdict["baseline"]["n"] == 6 and verdict["candidate"]["n"] == 3


def test_identical_answers_at_different_n_are_not_a_distribution_shift():
    """Review catch: raw-Counter comparison read {tp: 6} vs {tp: 3} as
    'different answers' when the only difference was excluded failed runs.
    Distributions compare as proportions, like everything else here."""
    base = _report([_inv()] * 6)
    cand = _report([_inv()] * 3)
    assert diff_reports(base, cand)["distribution_shifts"] == []


def test_a_rate_change_is_not_double_reported_as_a_distribution_shift():
    """Review catch: a verdict regression necessarily changes the verdict
    Counter, and used to ALSO appear under the 'same pass-rate, different
    answers' banner — false on its face for a cell whose rate moved."""
    base = _report([_inv()] * 6)
    cand = _report([_inv()] * 5 + [_inv(verdict="inconclusive")])
    diff = diff_reports(base, cand)

    assert [e["property"] for e in diff["regressions"]] == ["verdict"]
    assert diff["distribution_shifts"] == []


def test_a_cell_with_no_runs_on_one_side_is_incomparable_not_crashed_on():
    base = tally(
        [("fix.json", "phase_one", _inv()), ("fix.json", "agentic", _inv())],
        _EXP,
    )
    cand = _report([_inv()])  # phase_one only
    diff = diff_reports(base, cand)

    # The reason is deliberately neutral: an absent cell can mean all its
    # runs failed OR that the sweep never included it (different grids).
    assert diff["incomparable"] == [{
        "fixture": "fix.json", "mode": "agentic",
        "reason": "cell absent on the candidate side "
                  "(not in that sweep, or all its runs failed)",
    }]
    text = format_diff(diff, {"baseline": "a", "candidate": "b"})
    assert "INCOMPARABLE (1)" in text
    assert "cell absent on the candidate side" in text


def test_a_property_pinned_on_only_one_side_is_incomparable():
    # Two saved reports from different eras: the newer one pins
    # min_confidence, the older one didn't.
    old = _report([_inv()] * 3, {"fix.json": {"expected_verdict": "true_positive"}})
    new = _report([_inv()] * 3, _EXP)
    diff = diff_reports(old, new)

    props = {i["property"] for i in diff["incomparable"] if "property" in i}
    assert props == {"confidence"}
    assert "baseline side" in diff["incomparable"][0]["reason"]


def test_same_rate_distribution_shift_is_surfaced():
    # Both sides pass allowed_verdicts 6/6, but the candidate answers
    # 'inconclusive' half the time — invisible to pass-rates, visible here.
    base = _report([_inv()] * 6, _EXP_SPLIT)
    cand = _report(
        [_inv()] * 3 + [_inv(verdict="inconclusive")] * 3, _EXP_SPLIT
    )
    diff = diff_reports(base, cand)

    assert not diff["regressions"]
    verdict_shift = next(s for s in diff["distribution_shifts"] if s["which"] == "verdicts")
    assert verdict_shift["candidate"] == {"true_positive": 3, "inconclusive": 3}
    text = format_diff(diff, {"baseline": "a", "candidate": "b"})
    assert "DISTRIBUTION SHIFTS (1)" in text
    assert "'inconclusive': 3" in text


def test_failed_run_counts_ride_along():
    base, cand = _report([_inv()] * 6), _report([_inv()] * 4)
    cand["failures"] = [
        {"fixture": "fix.json", "mode": "phase_one", "error": "RuntimeError: x"}
    ] * 2
    diff = diff_reports(base, cand)
    assert diff["failures"] == {"baseline": 0, "candidate": 2}
    assert "baseline 0, candidate 2" in format_diff(
        diff, {"baseline": "a", "candidate": "b"}
    )


def test_format_diff_banners_regressions_and_the_clean_case():
    base = _report([_inv()] * 6)
    worse = _report([_inv()] * 4 + [_inv(verdict="inconclusive")] * 2)
    text = format_diff(diff_reports(base, worse), {"baseline": "m-a", "candidate": "m-b"})
    assert "REGRESSIONS" in text
    assert "verdict: 6/6 -> 4/6" in text
    assert "(was solid, now marginal)" in text
    # The regressed report must NOT carry the approval line (review catch:
    # an or-assert here let the banner's guard be inverted undetected).
    assert "No regressions" not in text

    clean = format_diff(diff_reports(base, base), {"baseline": "m-a", "candidate": "m-a"})
    assert "No regressions" in clean
    assert "REGRESSIONS" not in clean


def test_an_empty_comparison_never_reads_as_a_clean_pass():
    """Review catch: diffing two wrong-shaped inputs produced 'No
    regressions — the candidate matches or beats the baseline', the exact
    sentence that green-lights an upgrade, over zero compared pins."""
    text = format_diff(diff_reports(tally([]), tally([])),
                       {"baseline": "a", "candidate": "b"})
    assert "No regressions" not in text
    assert "NOTHING COMPARED" in text


# --- The CLI, both paths, hermetically -------------------------------------


async def test_from_reports_diffs_two_saved_calibration_files_offline(
    tmp_path, capsys, monkeypatch
):
    """The offline path reads files written by calibrate's OWN writer
    (write_report — not a hand-built copy of its shape) and never touches
    the network."""
    a, b = tmp_path / "old.json", tmp_path / "new.json"
    write_report(a, _report([_inv()] * 6), {"model": "model-old"})
    write_report(b, _report([_inv()] * 5 + [_inv(confidence="low")]),
                 {"model": "model-new"})

    monkeypatch.setattr(
        "sys.argv", ["ab_compare", "--from-reports", str(a), str(b)]
    )
    assert await _main() == 0
    out = capsys.readouterr().out
    assert "baseline=model-old vs candidate=model-new" in out
    assert "confidence: 6/6 -> 5/6" in out
    # The offline mode owns up to what it cannot verify.
    assert "not verifiable from the reports" in out


async def test_from_reports_rejects_a_file_that_is_not_a_calibration_report(
    tmp_path, capsys, monkeypatch
):
    """Review catch: an A/B report (no 'fixtures' table) passed as input
    degraded to an empty diff and a confident clean verdict, exit 0."""
    good = tmp_path / "good.json"
    write_report(good, _report([_inv()]), {"model": "m"})
    bad = tmp_path / "ab_latest.json"  # the natural wrong file
    bad.write_text(json.dumps({"meta": {}, "baseline": {}, "diff": {}}))

    monkeypatch.setattr(
        "sys.argv", ["ab_compare", "--from-reports", str(bad), str(good)]
    )
    with pytest.raises(SystemExit):
        await _main()
    assert "not a calibration report" in capsys.readouterr().err


async def test_from_reports_missing_and_malformed_files_fail_cleanly(
    tmp_path, capsys, monkeypatch
):
    """A wrong path or bad JSON is a one-line parser error naming the
    file, not a multi-frame traceback (review catch)."""
    ok = tmp_path / "ok.json"
    write_report(ok, _report([_inv()]), {"model": "m"})

    monkeypatch.setattr("sys.argv", [
        "ab_compare", "--from-reports", str(tmp_path / "nope.json"), str(ok)
    ])
    with pytest.raises(SystemExit):
        await _main()
    assert "cannot read" in capsys.readouterr().err

    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    monkeypatch.setattr(
        "sys.argv", ["ab_compare", "--from-reports", str(broken), str(ok)]
    )
    with pytest.raises(SystemExit):
        await _main()
    assert "not valid JSON" in capsys.readouterr().err


@pytest.mark.parametrize("extra", [
    ["--candidate", "m"],
    ["--baseline", "other-model"],
    ["--n", "3"],
    ["--modes", "phase_one"],
    ["--out", "somewhere.json"],
    ["--fixtures", "brute_force_ssh.json"],
])
async def test_from_reports_refuses_every_live_sweep_argument(
    extra, tmp_path, monkeypatch
):
    """Review catch: the guard covered --candidate/--fixtures/--all but
    silently ignored --baseline, --out, --n, --modes, --concurrency."""
    a = tmp_path / "a.json"
    a.write_text("{}")
    monkeypatch.setattr("sys.argv", [
        "ab_compare", "--from-reports", str(a), str(a), *extra,
    ])
    with pytest.raises(SystemExit):
        await _main()


async def test_live_mode_requires_candidate_and_the_cost_gate(monkeypatch):
    _no_live(monkeypatch)
    # No --candidate at all.
    monkeypatch.setattr("sys.argv", ["ab_compare"])
    with pytest.raises(SystemExit):
        await _main()
    # --candidate but neither --fixtures nor --all: the shared cost gate
    # (calibrate.resolve_fixtures) must refuse a default double sweep.
    monkeypatch.setattr("sys.argv", ["ab_compare", "--candidate", "m"])
    with pytest.raises(SystemExit):
        await _main()


async def test_unknown_fixture_names_are_refused_by_the_shared_gate(
    monkeypatch, capsys
):
    _no_live(monkeypatch)
    monkeypatch.setattr("sys.argv", [
        "ab_compare", "--candidate", "m", "--fixtures", "not_a_fixture.json",
    ])
    with pytest.raises(SystemExit):
        await _main()
    assert "not pinned" in capsys.readouterr().err


def _fake_sweep(monkeypatch, results_by_model):
    """Wire _main's live path to an injected sweep: the fake
    make_default_investigate returns the MODEL STRING as the 'investigate
    fn', and the fake run_calibration uses it to look up scripted results.
    Records the order models were swept in."""
    order = []

    def fake_factory(cassette, model=None):
        return model

    async def fake_run(fixtures, modes, n, investigate, concurrency=4):
        order.append(investigate)
        return results_by_model[investigate]

    monkeypatch.setattr(ab_compare, "make_default_investigate", fake_factory)
    monkeypatch.setattr(ab_compare, "run_calibration", fake_run)
    monkeypatch.setattr(
        ab_compare.ReputationCassette, "load", staticmethod(lambda: None)
    )
    return order


async def test_live_main_runs_candidate_first_and_diffs_in_the_right_direction(
    monkeypatch, tmp_path, capsys
):
    """Review catch: nothing executed the live path, so swapping the
    diff's argument order (inverting every regression) or dropping the
    model= pass-through survived the suite. Pins: candidate swept FIRST
    (a typo'd model id fails before the baseline spends), candidate-worse
    lands in regressions (direction), meta and the report file written."""
    order = _fake_sweep(monkeypatch, {
        "cand": ([("brute_force_ssh.json", "phase_one",
                   _inv(verdict="inconclusive"))], []),
        "base": ([("brute_force_ssh.json", "phase_one", _inv())], []),
    })
    out = tmp_path / "ab.json"
    monkeypatch.setattr("sys.argv", [
        "ab_compare", "--candidate", "cand", "--baseline", "base",
        "--fixtures", "brute_force_ssh.json", "--n", "1",
        "--modes", "phase_one", "--out", str(out),
    ])
    assert await _main() == 0
    assert order == ["cand", "base"]

    saved = json.loads(out.read_text())
    assert saved["meta"]["baseline"] == "base"
    assert saved["meta"]["candidate"] == "cand"
    # The candidate was WORSE — that must read as a regression, never an
    # improvement (the diff's direction, pinned).
    assert [e["property"] for e in saved["diff"]["regressions"]] == ["verdict"]
    assert saved["diff"]["improvements"] == []
    assert "REGRESSIONS" in capsys.readouterr().out


async def test_a_candidate_with_zero_successes_aborts_before_the_baseline_spends(
    monkeypatch, tmp_path, capsys
):
    """A bad model id fails every run; the harness must say so and stop
    without sweeping the baseline (review catch: baseline-first spent a
    full grid before the candidate's first call could fail)."""
    order = _fake_sweep(monkeypatch, {
        "typo-model": ([], [("brute_force_ssh.json", "phase_one",
                             "NotFoundError: model 'typo-model'")]),
        "base": ([("brute_force_ssh.json", "phase_one", _inv())], []),
    })
    monkeypatch.setattr("sys.argv", [
        "ab_compare", "--candidate", "typo-model", "--baseline", "base",
        "--fixtures", "brute_force_ssh.json", "--n", "1",
        "--modes", "phase_one", "--out", str(tmp_path / "ab.json"),
    ])
    assert await _main() == 1
    assert order == ["typo-model"]  # the baseline was never swept
    out = capsys.readouterr().out
    assert "zero successful runs" in out
    assert "NotFoundError" in out

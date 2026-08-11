"""Turn the house calibration discipline into recorded pass-rate data.

The rule in this project is: before pinning an expectation, run the fixture
~12 times (six per mode) and confirm the verdict holds. Until now that was
done with throwaway scripts, and "calibrated 12/12" survived only as a
sentence in a commit message — so a pin that actually passed 9 of 12 was an
invisible latent flake, one bad sample away from a red main.

This makes it a first-class, recorded thing. It runs each fixture N times
per mode, scores every pinned property with the SAME predicate the live
eval uses (tests/eval_checks.py — never a re-implementation), and writes a
per-property pass-rate report. A property that passed every run reads k/k;
a marginal one reads 9/12 and is called out, which is the whole point:
you can see which pins are solid and which are taste with a green
checkmark.

External reputation is replayed from the cassette (tests/cassette.py), so
the ONLY thing varying between the N runs is the model — which is exactly
what calibration is meant to measure. The model still runs live, so this
costs real API money: it is opt-in and bounded (choose N and a fixture
subset), never a default sweep.

    # a cheap smoke calibration of one fixture
    uv run python -m tests.calibrate --n 2 --fixtures brute_force_ssh.json

    # the house discipline over the whole corpus (a costly live sweep)
    uv run python -m tests.calibrate --n 6 --all

The report is written to data/evals/calibration/latest.json. That path is
gitignored: a calibration is point-in-time MEASUREMENT output against a
live model (unlike the cassette, which is committed test INPUT), so casual
runs must not churn the repo. Commit a deliberate snapshot with --out if
you want one under version control.
"""
import argparse
import asyncio
import json
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from soc_copilot.config import settings
from soc_copilot.history import AlertHistoryStore
from soc_copilot.models import Alert, Investigation

from .alert_loading import SAMPLE_ALERTS_DIR, load_alert_fixture
from .cassette import CassetteMiss, ReputationCassette
from .eval_checks import evaluate
from .expectations import EXPECTATIONS
from .harness import make_copilot

MODES = ("phase_one", "agentic")
REPORT_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "evals" / "calibration" / "latest.json"
)


def make_default_investigate(cassette: ReputationCassette, model: str | None = None):
    """The production run function: a fresh copilot per run (isolated
    history so no cross-alert memory accumulates across samples) with
    reputation replayed from `cassette` and the model live. `model`
    overrides the model per call — the seam the A/B harness
    (tests/ab_compare.py) uses to run the same grid under two models;
    None means the copilot's default (settings.MODEL), exactly as before."""
    async def investigate(alert: Alert, mode: str) -> Investigation:
        with tempfile.TemporaryDirectory() as d:
            copilot = make_copilot(
                store=AlertHistoryStore(Path(d) / "h.jsonl"), cassette=cassette
            )
            if mode == "agentic":
                return await copilot.investigate_agentic(
                    alert, model=model, record=False
                )
            return await copilot.investigate(alert, model=model, record=False)
    return investigate


def add_grid_args(parser: argparse.ArgumentParser) -> None:
    """The (fixture × mode × n) grid arguments, shared with the A/B
    harness (tests/ab_compare.py) so the two CLIs can't drift — in
    particular on the cost gate below."""
    parser.add_argument("--n", type=int, default=6, help="runs per mode per fixture")
    parser.add_argument("--modes", nargs="+", choices=MODES, default=list(MODES))
    parser.add_argument("--fixtures", nargs="+", default=None,
                        help="fixture filenames to calibrate")
    parser.add_argument("--all", action="store_true",
                        help="calibrate the FULL pinned corpus — a costly live sweep")
    parser.add_argument("--concurrency", type=int, default=4)


def resolve_fixtures(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> list[str]:
    """Apply the cost gate and validate fixture names.

    The full corpus is many live investigations and real money, so it is
    never the default: an unqualified invocation must state its intent
    (review catch — "never a default sweep" was a claim the CLI broke).
    """
    if not args.fixtures and not args.all:
        parser.error(
            "specify --fixtures F [F ...] for a subset, or --all for the full "
            "corpus (a costly live sweep). This never runs by default."
        )
    fixtures = args.fixtures or sorted(EXPECTATIONS.keys())
    unknown = [f for f in fixtures if f not in EXPECTATIONS]
    if unknown:
        parser.error(f"not pinned fixtures: {unknown}")
    return fixtures


def tally(
    results: list[tuple[str, str, Investigation]],
    expectations: dict = EXPECTATIONS,
) -> dict:
    """Reduce (fixture, mode, Investigation) samples to per-property
    pass-rate data — pure, so the runner's arithmetic is tested without a
    single API call. A property's pass count is how many of its runs
    satisfied the SHARED predicate; verdict/confidence distributions ride
    along so a split (4 true_positive / 2 inconclusive) is visible even
    when both are inside `allowed_verdicts`."""
    by_cell: dict[tuple[str, str], list[Investigation]] = {}
    for fixture, mode, inv in results:
        by_cell.setdefault((fixture, mode), []).append(inv)

    report: dict = {"fixtures": {}, "marginal": []}
    for (fixture, mode), invs in sorted(by_cell.items()):
        expected = expectations.get(fixture, {})
        evals = [evaluate(inv, expected) for inv in invs]  # once per sample
        names = sorted({name for e in evals for name in e})
        props: dict[str, dict] = {}
        for name in names:
            passed = sum(1 for e in evals if name in e and e[name].ok)
            props[name] = {"pass": passed, "n": len(invs)}
            if passed < len(invs):
                report["marginal"].append({
                    "fixture": fixture, "mode": mode, "property": name,
                    "pass": passed, "n": len(invs),
                })
        cell = report["fixtures"].setdefault(fixture, {})
        cell[mode] = {
            "runs": len(invs),
            "properties": props,
            "verdicts": dict(Counter(inv.verdict for inv in invs)),
            "confidences": dict(Counter(inv.confidence for inv in invs)),
        }
    return report


async def run_calibration(
    fixtures: list[str],
    modes: tuple[str, ...],
    n: int,
    investigate,
    concurrency: int = 4,
) -> tuple[list[tuple[str, str, Investigation]], list[tuple[str, str, str]]]:
    """Run the (fixture × mode × n) grid through `investigate`, bounded by a
    semaphore. Returns (successes, failures).

    A single run that raises an ordinary error (the copilot's own
    max_iterations / max_tokens RuntimeErrors, a transient API 5xx) must not
    throw away the whole expensive sweep, so it is caught and recorded as a
    failure rather than propagated — the report shows it as a non-pass, and
    it is never silently folded into the pass count. A CassetteMiss is the
    exception: an unrecorded indicator is a correctness problem, not a flaky
    run, so it still aborts loudly (it is a BaseException, so `except
    Exception` here does not swallow it). `investigate` is injected so tests
    drive a scripted model."""
    sem = asyncio.Semaphore(concurrency)

    async def one(fixture: str, mode: str):
        alert = load_alert_fixture(SAMPLE_ALERTS_DIR / fixture)
        async with sem:
            try:
                inv = await investigate(alert, mode)
            except Exception as e:  # not CassetteMiss (BaseException)
                return ("fail", fixture, mode, f"{type(e).__name__}: {e}")
        return ("ok", fixture, mode, inv)

    tasks = [
        one(fixture, mode)
        for fixture in fixtures for mode in modes for _ in range(n)
    ]
    raw = await asyncio.gather(*tasks)
    successes = [(f, m, inv) for tag, f, m, inv in raw if tag == "ok"]
    failures = [(f, m, err) for tag, f, m, err in raw if tag == "fail"]
    return successes, failures


def write_report(path: Path, report: dict, meta: dict) -> None:
    """The on-disk calibration report shape ({"meta": ..., **report}) —
    one writer, used by the CLI and by tests that need a real report file
    (tests/test_ab_compare.py builds its --from-reports inputs with it, so
    the offline diff is pinned to what this actually writes rather than a
    hand-maintained copy that could drift)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"meta": meta, **report}, indent=2, sort_keys=True) + "\n"
    )


def format_report(report: dict, meta: dict) -> str:
    """A compact human view of the recorded report."""
    lines = [
        f"Calibration: n={meta['n']} per mode, "
        f"{len(report['fixtures'])} fixture(s), model={meta['model']}",
        "",
    ]
    for fixture, cells in report["fixtures"].items():
        lines.append(fixture)
        for mode, cell in cells.items():
            flags = " ".join(
                f"{name}={p['pass']}/{p['n']}"
                + ("*" if p["pass"] < p["n"] else "")
                for name, p in cell["properties"].items()
            )
            lines.append(f"  [{mode:9}] {flags}")
            if len(cell["verdicts"]) > 1 or len(cell["confidences"]) > 1:
                lines.append(f"    verdicts={cell['verdicts']} confidences={cell['confidences']}")
    if report["marginal"]:
        lines.append("")
        lines.append(f"MARGINAL PINS ({len(report['marginal'])}) — a pin that is not k/k is one "
                     f"bad sample from a red main:")
        for m in report["marginal"]:
            lines.append(f"  {m['fixture']} [{m['mode']}] {m['property']}: {m['pass']}/{m['n']}")
    else:
        lines.append("\nAll pinned properties passed every run (k/k).")
    return "\n".join(lines)


async def _main() -> int:
    parser = argparse.ArgumentParser(description="Recorded calibration of pinned expectations.")
    add_grid_args(parser)
    parser.add_argument("--out", type=Path, default=REPORT_PATH)
    args = parser.parse_args()
    fixtures = resolve_fixtures(args, parser)

    cassette = ReputationCassette.load()
    investigate = make_default_investigate(cassette)
    total = len(fixtures) * len(args.modes) * args.n
    print(f"Calibrating {len(fixtures)} fixture(s) × {len(args.modes)} mode(s) × "
          f"{args.n} = {total} live investigations on {settings.MODEL}...")

    try:
        successes, failures = await run_calibration(
            fixtures, tuple(args.modes), args.n, investigate,
            concurrency=args.concurrency,
        )
    except CassetteMiss as miss:
        # An indicator the model looked up has no recording. Fail loud with
        # the name rather than a traceback; the run is not trustworthy until
        # it is recorded (tests/record_cassette).
        print(f"ERROR: {miss}")
        return 1

    report = tally(successes)
    if failures:
        report["failures"] = [
            {"fixture": f, "mode": m, "error": e} for f, m, e in failures
        ]
    meta = {
        "n": args.n, "modes": list(args.modes), "model": settings.MODEL,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "fixtures": fixtures,
    }
    write_report(args.out, report, meta)
    print("\n" + format_report(report, meta))
    if failures:
        print(f"\n{len(failures)} run(s) FAILED (not counted as passes): "
              + "; ".join(f"{f} [{m}] {e[:50]}" for f, m, e in failures))
    print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))

"""Answer "is the new model safe to switch to?" with recorded diffs.

The calibration runner (tests/calibrate.py) records what the CURRENT
model does. A model upgrade changes exactly one variable, so the question
it raises is differential: same fixtures, same cassette, same shared
predicate (tests/eval_checks.py) — which pinned properties got better
under the candidate model, which got worse? Until now that meant running
two calibrations by hand and eyeballing two JSON files side by side.

This runs the same (fixture × mode × n) grid under a baseline model and a
candidate model (candidate first, so a mistyped model id fails before the
baseline sweep spends anything) and diffs the per-property pass-rates.
External reputation is replayed from the cassette for BOTH sides, so in
live mode every difference in the diff is attributable to the model
change alone. (The offline --from-reports mode cannot make that promise:
two saved reports may straddle a cassette re-recording or an expectation
edit, and the tool says so out loud.) Each regression and improvement is
named, and the k/k boundary is called out — "was solid, now marginal" is
the exact signal that blocks an upgrade, and "was marginal, now solid"
the one that motivates it. Same-rate verdict/confidence distribution
shifts are listed too — compared as PROPORTIONS, so two sides with
different sample sizes (failed runs are excluded) never fabricate drift
out of arithmetic — because a candidate that still passes
`allowed_verdicts` while answering differently inside the set is drift
worth seeing before it hardens into a surprise.

The exit code is 0 even when regressions are found: at calibration-scale
n, a 5/6-vs-6/6 delta is a signal to read, not an automated verdict —
the recorded report is the product, not a pass/fail bit.

    # is a candidate safe for one pin? (1 fixture × 2 modes × n × 2 models)
    uv run python -m tests.ab_compare --candidate claude-opus-5 \\
        --fixtures brute_force_ssh.json --n 3

    # the full upgrade audit — a costly DOUBLE live sweep
    uv run python -m tests.ab_compare --candidate claude-opus-5 --all

    # offline: diff two previously saved calibration reports, no API calls
    uv run python -m tests.ab_compare --from-reports old.json new.json

Running with --candidate equal to the baseline is allowed on purpose: it
measures the noise floor — how much pass-rates wobble between two
identical sweeps — which is what a candidate's delta must be read
against. The report lands at data/evals/calibration/ab_latest.json
(gitignored, like all calibration output: point-in-time measurement, not
committed test input; use --out for a deliberate snapshot).
"""
import argparse
import asyncio
import json
from datetime import datetime, timezone
from fractions import Fraction
from pathlib import Path

from soc_copilot.config import settings

from .calibrate import (
    add_grid_args,
    make_default_investigate,
    resolve_fixtures,
    run_calibration,
    tally,
)
from .cassette import CassetteMiss, ReputationCassette

AB_REPORT_PATH = (
    Path(__file__).resolve().parents[1]
    / "data" / "evals" / "calibration" / "ab_latest.json"
)


def _cells(report: dict) -> dict[tuple[str, str], dict]:
    return {
        (fixture, mode): cell
        for fixture, cells in report.get("fixtures", {}).items()
        for mode, cell in cells.items()
    }


# Which per-property rate governs each distribution: a shift in `verdicts`
# is only reported when the `verdict` pass-rate itself did NOT move (else
# it is already a regression/improvement, and repeating it under a
# "same pass-rate" banner would be false — review catch).
_DIST_PROPERTY = {"verdicts": "verdict", "confidences": "confidence"}


def _normalized(counter: dict) -> dict:
    """Counts -> exact proportions (Fractions, no float fuzz), so two sides
    with different n (a failed run shrinks a side's sample) compare by what
    the model ANSWERED, not by how many samples survived — the same
    rates-not-counts rule the property diff already follows (review catch:
    raw-Counter comparison fabricated 'drift' out of excluded failed runs)."""
    total = sum(counter.values())
    return {k: Fraction(v, total) for k, v in counter.items()} if total else {}


def diff_reports(baseline: dict, candidate: dict) -> dict:
    """Pure diff of two tally() reports — testable without an API call.

    Compares pass-RATES, not counts, so sides with different n (a failed
    run shrinks a side's sample) remain comparable; the raw pass/n pairs
    ride along so the reader always sees the sample sizes. Anything that
    exists on only one side — a whole (fixture, mode) cell, or a single
    property (expectations changed between two saved reports) — is
    reported as incomparable rather than silently dropped or crashed on.
    """
    diff: dict = {
        "regressions": [], "improvements": [], "unchanged": [],
        "distribution_shifts": [], "incomparable": [],
        "failures": {
            "baseline": len(baseline.get("failures", [])),
            "candidate": len(candidate.get("failures", [])),
        },
    }
    cells_b, cells_c = _cells(baseline), _cells(candidate)
    for fixture, mode in sorted(set(cells_b) | set(cells_c)):
        b, c = cells_b.get((fixture, mode)), cells_c.get((fixture, mode))
        if b is None or c is None:
            side = "baseline" if b is None else "candidate"
            # A missing cell can mean all its runs failed OR that sweep
            # never attempted it (different --modes/--fixtures between two
            # saved reports) — don't assert failures that never happened.
            diff["incomparable"].append({
                "fixture": fixture, "mode": mode,
                "reason": f"cell absent on the {side} side "
                          f"(not in that sweep, or all its runs failed)",
            })
            continue
        for name in sorted(set(b["properties"]) | set(c["properties"])):
            pb = b["properties"].get(name)
            pc = c["properties"].get(name)
            if pb is None or pc is None:
                side = "baseline" if pb is None else "candidate"
                diff["incomparable"].append({
                    "fixture": fixture, "mode": mode, "property": name,
                    "reason": f"property not tallied on the {side} side "
                              f"(expectations changed between reports?)",
                })
                continue
            entry = {
                "fixture": fixture, "mode": mode, "property": name,
                "baseline": pb, "candidate": pc,
            }
            rate_b, rate_c = pb["pass"] / pb["n"], pc["pass"] / pc["n"]
            if rate_c < rate_b:
                # was k/k on the baseline, isn't on the candidate — the
                # single most upgrade-blocking shape a diff can take.
                entry["newly_marginal"] = pb["pass"] == pb["n"]
                diff["regressions"].append(entry)
            elif rate_c > rate_b:
                entry["newly_solid"] = pc["pass"] == pc["n"]
                diff["improvements"].append(entry)
            else:
                diff["unchanged"].append(entry)
        for dist, prop in _DIST_PROPERTY.items():
            gb = b["properties"].get(prop)
            gc = c["properties"].get(prop)
            # Rate moved (cross-multiplied, no float) -> already reported as
            # a regression/improvement above; a shift entry would be a
            # mislabeled duplicate.
            if gb and gc and gb["pass"] * gc["n"] != gc["pass"] * gb["n"]:
                continue
            if _normalized(b.get(dist, {})) != _normalized(c.get(dist, {})):
                diff["distribution_shifts"].append({
                    "fixture": fixture, "mode": mode, "which": dist,
                    "baseline": b.get(dist, {}), "candidate": c.get(dist, {}),
                })
    return diff


def _fmt_entry(e: dict) -> str:
    pb, pc = e["baseline"], e["candidate"]
    line = (f"  {e['fixture']} [{e['mode']}] {e['property']}: "
            f"{pb['pass']}/{pb['n']} -> {pc['pass']}/{pc['n']}")
    if e.get("newly_marginal"):
        line += "   (was solid, now marginal)"
    if e.get("newly_solid"):
        line += "   (now solid)"
    return line


def format_diff(diff: dict, meta: dict) -> str:
    """A compact human view of the recorded diff."""
    lines = [
        f"A/B: baseline={meta['baseline']} vs candidate={meta['candidate']}",
        "",
    ]
    if diff["regressions"]:
        lines.append(f"REGRESSIONS ({len(diff['regressions'])}) — candidate is worse on:")
        lines += [_fmt_entry(e) for e in diff["regressions"]]
    if diff["improvements"]:
        lines.append(f"IMPROVEMENTS ({len(diff['improvements'])}) — candidate is better on:")
        lines += [_fmt_entry(e) for e in diff["improvements"]]
    if diff["distribution_shifts"]:
        lines.append(f"DISTRIBUTION SHIFTS ({len(diff['distribution_shifts'])}) "
                     f"— same pass-rate, different answers:")
        for s in diff["distribution_shifts"]:
            lines.append(f"  {s['fixture']} [{s['mode']}] {s['which']}: "
                         f"{s['baseline']} -> {s['candidate']}")
    if diff["incomparable"]:
        lines.append(f"INCOMPARABLE ({len(diff['incomparable'])}):")
        for i in diff["incomparable"]:
            what = f" {i['property']}" if "property" in i else ""
            lines.append(f"  {i['fixture']} [{i['mode']}]{what}: {i['reason']}")
    fails = diff["failures"]
    if fails["baseline"] or fails["candidate"]:
        lines.append(f"Failed runs (excluded from rates): "
                     f"baseline {fails['baseline']}, candidate {fails['candidate']}")
    lines.append(f"Unchanged: {len(diff['unchanged'])} propert"
                 f"{'y' if len(diff['unchanged']) == 1 else 'ies'} at identical rates.")
    compared = (len(diff["regressions"]) + len(diff["improvements"])
                + len(diff["unchanged"]))
    if not compared:
        # The approval line below is the sentence a human reads to
        # green-light a switch — it must never print over an empty
        # comparison (wrong file, all-failed side): that's not a clean
        # bill of health, it's no examination at all (review catch).
        lines.append(
            "NOTHING COMPARED — zero properties were comparable between "
            "the two sides. This is not a clean result; check the inputs."
        )
    elif not diff["regressions"]:
        lines.append(
            "No regressions — the candidate matches or beats the baseline "
            "on every comparable pin."
        )
    return "\n".join(lines)


async def _main() -> int:
    parser = argparse.ArgumentParser(
        description="A/B a candidate model against a baseline over the pinned corpus."
    )
    parser.add_argument("--candidate", default=None,
                        help="model id to evaluate (required unless --from-reports)")
    parser.add_argument("--baseline", default=settings.MODEL,
                        help="model to compare against (default: the production model)")
    parser.add_argument("--from-reports", nargs=2, metavar=("BASELINE", "CANDIDATE"),
                        type=Path, default=None,
                        help="diff two saved calibration reports offline — no API calls")
    add_grid_args(parser)
    parser.add_argument("--out", type=Path, default=AB_REPORT_PATH)
    args = parser.parse_args()

    if args.from_reports:
        # Offline mode: every live-sweep argument describes a sweep this
        # invocation will never run, so mixing any in is a confused command
        # line — refuse rather than half-obey. Detected by deviation from
        # the parser's own defaults (an explicitly passed default value is
        # indistinguishable and harmless).
        touched = [
            name for name in ("baseline", "out", "n", "modes", "concurrency")
            if getattr(args, name) != parser.get_default(name)
        ]
        if args.candidate or args.fixtures or args.all or touched:
            parser.error(
                "--from-reports diffs two saved reports; it cannot be "
                "combined with live-sweep arguments (--candidate/--baseline/"
                "--fixtures/--all/--n/--modes/--concurrency/--out)"
            )
        loaded = []
        for p in args.from_reports:
            try:
                data = json.loads(p.read_text())
            except OSError as e:
                parser.error(f"cannot read {p}: {e}")
            except json.JSONDecodeError as e:
                parser.error(f"{p} is not valid JSON: {e}")
            # A wrong file must not degrade to an empty diff and a clean
            # verdict (the natural mistake: ab_latest.json lives in the
            # same directory and has no top-level fixtures table).
            if not isinstance(data, dict) or not data.get("fixtures"):
                parser.error(
                    f"{p} is not a calibration report (no 'fixtures' table). "
                    f"Expected a file written by `python -m tests.calibrate` "
                    f"— note ab_latest.json is an A/B report, not a "
                    f"calibration report."
                )
            loaded.append(data)
        meta_a = loaded[0].get("meta", {})
        meta_b = loaded[1].get("meta", {})
        for key in ("n", "modes", "fixtures"):
            if key in meta_a and key in meta_b and meta_a[key] != meta_b[key]:
                print(f"note: the two reports differ in {key} "
                      f"({meta_a[key]} vs {meta_b[key]}) — expect "
                      f"incomparable cells or different sample sizes")
        print("note: offline diff — cassette and expectation parity between "
              "the two recordings is not verifiable from the reports; a "
              "delta may include harness drift, not only the model.\n")
        meta = {
            "baseline": meta_a.get("model", str(args.from_reports[0])),
            "candidate": meta_b.get("model", str(args.from_reports[1])),
            "from_reports": [str(p) for p in args.from_reports],
        }
        print(format_diff(diff_reports(loaded[0], loaded[1]), meta))
        return 0

    if not args.candidate:
        parser.error("--candidate MODEL is required (or use --from-reports)")
    fixtures = resolve_fixtures(args, parser)  # the cost gate, doubled here

    cassette = ReputationCassette.load()
    per_side = len(fixtures) * len(args.modes) * args.n
    print(f"A/B: {len(fixtures)} fixture(s) × {len(args.modes)} mode(s) × {args.n} "
          f"= {per_side} live investigations PER MODEL "
          f"({args.baseline} vs {args.candidate})...")

    meta = {
        "baseline": args.baseline, "candidate": args.candidate,
        "n": args.n, "modes": list(args.modes), "fixtures": fixtures,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    def write_out(payload: dict) -> None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n"
        )

    reports: dict[str, dict] = {}
    try:
        # Candidate first, deliberately: it is the user-typed model id, so a
        # typo or unavailable model dies on the cheap side — before the
        # baseline sweep has spent a full grid of live investigations
        # (review catch: baseline-first paid for the whole sweep before the
        # candidate's first call could fail).
        for side, model in (("candidate", args.candidate),
                            ("baseline", args.baseline)):
            print(f"  running {side}: {model} ...")
            successes, failures = await run_calibration(
                fixtures, tuple(args.modes), args.n,
                make_default_investigate(cassette, model=model),
                concurrency=args.concurrency,
            )
            if not successes:
                # An entire side failing is not a diffable measurement —
                # it's usually a bad model id or auth error repeated n
                # times. Say so and stop before spending on the other side.
                first = failures[0][2] if failures else "no error recorded"
                print(f"ERROR: the {side} sweep ({model}) produced zero "
                      f"successful runs — nothing to diff. "
                      f"First error: {first}")
                if reports:
                    write_out({"meta": {**meta, "aborted":
                               f"{side} sweep had zero successes"}, **reports})
                    print(f"Wrote partial (completed side only, no diff) {args.out}")
                return 1
            report = tally(successes)
            if failures:
                report["failures"] = [
                    {"fixture": f, "mode": m, "error": e} for f, m, e in failures
                ]
            reports[side] = report
    except CassetteMiss as miss:
        print(f"ERROR: {miss}")
        # A completed side is paid-for data — the miss aborts the diff,
        # not the record (review catch: it used to be discarded).
        if reports:
            write_out({"meta": {**meta, "aborted": f"CassetteMiss: {miss}"},
                       **reports})
            print(f"Wrote partial (completed side only, no diff) {args.out}")
        return 1

    diff = diff_reports(reports["baseline"], reports["candidate"])
    write_out({"meta": meta, "baseline": reports["baseline"],
               "candidate": reports["candidate"], "diff": diff})
    print("\n" + format_diff(diff, meta))
    print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))

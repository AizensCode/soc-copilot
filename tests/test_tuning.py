"""Unit tests for the detection tuning report (no API, no network).

    uv run pytest tests/test_tuning.py -v

The report recommends narrowing production sensors, so most of what is
pinned here is what it REFUSES to say: not enough firings, evidence the
copilot's own verdicts can't carry, an exception entity the same rule
has already caught something on.
"""
from datetime import datetime, timedelta, timezone

import pytest

from soc_copilot.history import AlertHistoryStore
from soc_copilot.models import (
    Alert,
    AssetMatch,
    InjectionFlag,
    Investigation,
)
from soc_copilot.tuning import (
    MIN_FIRINGS,
    build_tuning_report,
    detection_of,
    render_tuning_report,
)

_T = datetime(2026, 8, 1, 9, 0, tzinfo=timezone.utc)


def _store(tmp_path) -> AlertHistoryStore:
    return AlertHistoryStore(tmp_path / "investigations.jsonl")


def _record(
    store,
    alert_id,
    verdict="false_positive",
    rule="Credentialed scan",
    title=None,
    severity="medium",
    ips=("10.0.0.5",),
    users=(),
    host="srv-1",
    assets=(),
    injection=False,
    duplicate_of=None,
    techniques=(),
    escalate=False,
    raw_log=None,
):
    """One recorded investigation. `rule` lands where elastic.py writes
    the detection name; pass raw_log to test another shape."""
    if raw_log is None:
        raw_log = {"host": host}
        if rule:
            raw_log["detection"] = {"rule_name": rule}
    store.record(
        Alert(
            alert_id=alert_id,
            timestamp=_T,
            source="siem",
            severity=severity,
            title=title if title is not None else f"alert {alert_id}",
            raw_log=raw_log,
            indicators={"ips": list(ips), "users": list(users)},
        ),
        Investigation(
            alert_id=alert_id,
            verdict=verdict,
            confidence="high",
            hypothesis="h",
            escalation_recommended=escalate,
            attack_techniques=list(techniques),
            asset_matches=list(assets),
            duplicate_of=duplicate_of,
            injection_flags=(
                [InjectionFlag(location="raw_log.notes", pattern="p", excerpt="e")]
                if injection
                else []
            ),
        ),
    )


def _scanner_asset(entity="10.0.0.5", name="scanner-01"):
    return AssetMatch(
        entity=entity,
        entity_type="ip",
        name=name,
        role="authorized vulnerability scanner",
    )


def _noisy_rule(store, n=MIN_FIRINGS, **kwargs):
    """n false positives on one rule, all sharing the scanner IP."""
    for i in range(n):
        _record(store, f"FP{i}", users=[f"u{i}"], **kwargs)


# --------------------------------------------------------------------
# detection identity
# --------------------------------------------------------------------

def test_rule_name_beats_title_and_is_marked_authoritative():
    name, provenance = detection_of(
        {
            "title": "463 failed logons on fin-app-02 from 185.129.62.62",
            "alert": {"raw_log": {"detection": {"rule_name": "RDP brute force"}}},
        }
    )
    assert (name, provenance) == ("RDP brute force", "rule")


@pytest.mark.parametrize(
    "raw_log",
    [
        {"detection": {"rule_name": "R"}},
        {"detection": {"rule": "R"}},
        {"detection_rule": "R"},
        {"signal": {"rule": {"name": "R"}}},
        {"rule": {"name": "R"}},
        {"rule_name": "R"},
        {"rule": "R"},
    ],
)
def test_every_allowlisted_rule_shape_resolves(raw_log):
    assert detection_of({"alert": {"raw_log": raw_log}}) == ("R", "rule")


def test_a_rule_container_is_declined_rather_than_stringified():
    """`rule` as an ECS object must not become the group key. Grouping by
    "{'name': ...}" would key every alert by a dict repr — a conflation,
    the one direction that can invent a recommendation."""
    name, provenance = detection_of(
        {"title": "T", "alert": {"raw_log": {"rule": {"id": 7}}}}
    )
    assert (name, provenance) == ("T", "title")


def test_title_is_the_fallback_and_says_so():
    assert detection_of({"title": "WAF: SQLi on /wiki"}) == (
        "WAF: SQLi on /wiki",
        "title",
    )
    # A record with no title at all still groups, rather than crashing.
    assert detection_of({"alert": {"raw_log": {}}}) == (
        "(unnamed detection)",
        "title",
    )


def test_a_title_never_merges_into_a_named_rules_row(tmp_path):
    """Provenance is part of the group KEY. A title spelled exactly like
    a real rule name is the one way a derived key could CONFLATE rather
    than fragment — which would let alert content add firings, and an
    exception candidate, to a rule the SIEM named. Keeping the two
    keyspaces apart makes that impossible instead of unlikely."""
    store = _store(tmp_path)
    _record(store, "A1", rule="Shared name")
    _record(store, "A2", rule=None, title="Shared name")

    dets = build_tuning_report(store).detections
    assert [(d.name, d.provenance, d.firings) for d in dets] == [
        ("Shared name", "rule", ["A1"]),
        ("Shared name", "title", ["A2"]),
    ]


def test_a_detection_name_is_collapsed_to_one_printable_line(tmp_path):
    """The name is a key, not just display text: alert content reaches
    it, and a newline in a key is a newline in anything that later
    exports or logs it."""
    name, provenance = detection_of(
        {"title": "Login failed\n  NOISY DETECTIONS (1):\x1b[2J\tx  "}
    )
    # ESC is stripped (so the escape sequence is inert text), newline and
    # tab collapse, the surrounding runs collapse with them.
    assert name == "Login failed NOISY DETECTIONS (1): [2J x"
    assert provenance == "title"


# --------------------------------------------------------------------
# what counts as evidence
# --------------------------------------------------------------------

def test_empty_store_reports_nothing_rather_than_a_clean_bill(tmp_path):
    report = build_tuning_report(_store(tmp_path))
    assert report.detections == []
    assert "no detection has a record" in render_tuning_report(report)


def test_a_reinvestigated_alert_is_one_firing_judged_on_the_latest(tmp_path):
    store = _store(tmp_path)
    _record(store, "A1", verdict="false_positive")
    _record(store, "A1", verdict="true_positive")

    [det] = build_tuning_report(store).detections
    assert det.firings == ["A1"]
    assert det.fp == [] and det.tp == ["A1"]


def test_suppressed_duplicates_are_firings_but_never_evidence(tmp_path):
    """A near-duplicate is a real thing the rule raised — it belongs in
    the volume. Its verdict was BORROWED from an anchor, so counting it
    as a false positive would inflate the rate on exactly the rules that
    repeat, which are the rules this report is about."""
    store = _store(tmp_path)
    _record(store, "ANCHOR", verdict="false_positive")
    for i in range(4):
        _record(store, f"DUP{i}", verdict="false_positive", duplicate_of="ANCHOR")

    [det] = build_tuning_report(store).detections
    assert len(det.firings) == 5
    assert len(det.suppressed) == 4
    assert det.admissible == ["ANCHOR"]
    assert det.fp_rate == 1.0
    # Volume floor cleared, denominator still one verdict: watchlist,
    # not a recommendation to narrow a production sensor.
    assert not det.is_noisy
    assert det.below_floor


def test_the_rate_needs_more_than_one_judgment_behind_it(tmp_path):
    """MIN_EVIDENCE is a separate floor from MIN_FIRINGS, and this is
    the gap between them: 40 firings, 39 of them suppressed repeats,
    reads as "100% false positive over 40 firings" on one verdict."""
    store = _store(tmp_path)
    _record(store, "ANCHOR", verdict="false_positive")
    for i in range(39):
        _record(store, f"DUP{i}", verdict="false_positive", duplicate_of="ANCHOR")

    report = build_tuning_report(store)
    assert report.noisy == []
    assert len(report.watchlist) == 1

    # One more real investigation of the same benign thing, and it is a
    # finding — the evidence floor is low, it is just not zero.
    _record(store, "SECOND", verdict="false_positive", users=["u9"])
    assert [d.name for d in build_tuning_report(store).noisy] == [
        "Credentialed scan"
    ]


def test_analyst_ruling_outranks_the_copilots_verdict(tmp_path):
    store = _store(tmp_path)
    _record(store, "A1", verdict="true_positive")
    store.record_disposition("A1", "false_positive", "thehive")

    [det] = build_tuning_report(store).detections
    assert det.fp == ["A1"] and det.tp == []
    assert det.analyst_backed_fp == ["A1"]


def test_the_rate_says_how_much_of_it_a_human_confirmed(tmp_path):
    store = _store(tmp_path)
    _noisy_rule(store, n=5)
    store.record_disposition("FP0", "false_positive", "thehive")

    [det] = build_tuning_report(store).detections
    assert len(det.fp) == 5 and det.analyst_backed_fp == ["FP0"]
    rendered = render_tuning_report(build_tuning_report(store))
    assert "1 confirmed by an analyst, 4 the copilot's own call" in rendered


def test_inconclusive_dilutes_the_rate_rather_than_counting_either_way(tmp_path):
    store = _store(tmp_path)
    _noisy_rule(store, n=4)
    _record(store, "INC", verdict="inconclusive")

    [det] = build_tuning_report(store).detections
    assert len(det.admissible) == 5 and len(det.fp) == 4
    assert det.fp_rate == 0.8
    assert det.is_noisy


def test_no_admissible_evidence_is_not_a_clean_detection(tmp_path):
    store = _store(tmp_path)
    for i in range(MIN_FIRINGS):
        _record(store, f"D{i}", duplicate_of="ELSEWHERE")

    [det] = build_tuning_report(store).detections
    assert det.fp_rate is None       # not 0.0
    assert not det.is_noisy


# --------------------------------------------------------------------
# the volume floor
# --------------------------------------------------------------------

def test_below_the_floor_it_is_a_watchlist_entry_not_a_recommendation(tmp_path):
    store = _store(tmp_path)
    _noisy_rule(store, n=MIN_FIRINGS - 1)

    report = build_tuning_report(store)
    assert report.noisy == []
    [watched] = report.watchlist
    assert len(watched.firings) == MIN_FIRINGS - 1
    rendered = render_tuning_report(report)
    assert "WATCHLIST" in rendered
    assert "no recommendation" in rendered


def test_at_the_floor_it_becomes_a_finding(tmp_path):
    store = _store(tmp_path)
    _noisy_rule(store, n=MIN_FIRINGS)

    report = build_tuning_report(store)
    assert [d.name for d in report.noisy] == ["Credentialed scan"]
    assert report.watchlist == []


def test_a_rule_below_the_noise_threshold_is_not_reported(tmp_path):
    store = _store(tmp_path)
    _noisy_rule(store, n=6)
    _record(store, "TP1", verdict="true_positive", ips=["8.8.8.8"])
    _record(store, "TP2", verdict="true_positive", ips=["8.8.4.4"])

    report = build_tuning_report(store)
    [det] = report.detections
    assert det.fp_rate == 0.75
    assert report.noisy == []


def test_suppressed_repeats_count_toward_the_floor(tmp_path):
    """Volume is volume: a rule whose repeats the desk absorbed silently
    is still firing that often, and the operator should still hear it."""
    store = _store(tmp_path)
    _noisy_rule(store, n=2)
    for i in range(3):
        _record(store, f"D{i}", duplicate_of="FP0")

    [det] = build_tuning_report(store).detections
    assert len(det.firings) == MIN_FIRINGS
    assert det.is_noisy


def test_noisy_detections_are_ranked_by_attention_spent(tmp_path):
    store = _store(tmp_path)
    _noisy_rule(store, n=5, rule="Small")
    for i in range(9):
        _record(store, f"B{i}", rule="Big", users=[f"b{i}"])

    assert [d.name for d in build_tuning_report(store).noisy] == ["Big", "Small"]


# --------------------------------------------------------------------
# blockers: the rule catches real things
# --------------------------------------------------------------------

def test_a_confirmed_true_positive_is_stated_beside_the_rate(tmp_path):
    store = _store(tmp_path)
    _noisy_rule(store, n=8)
    _record(store, "REAL", verdict="true_positive", ips=["203.0.113.9"])
    store.record_disposition("REAL", "true_positive", "thehive:case-4")

    [det] = build_tuning_report(store).detections
    assert det.is_noisy                      # 8/9 is still noisy
    assert det.ruled_tp == ["REAL"]
    assert any("analyst-confirmed true positive" in b for b in det.blockers)
    assert "REAL" in render_tuning_report(build_tuning_report(store))


def test_an_overturned_false_positive_discredits_the_unruled_verdicts(tmp_path):
    """The copilot called it benign and a human disagreed. Its other,
    unruled false-positive calls on this rule are the same judgment —
    the report says so instead of quietly averaging them in."""
    store = _store(tmp_path)
    _noisy_rule(store, n=8)
    _record(store, "OOPS", verdict="false_positive", ips=["203.0.113.9"])
    store.record_disposition("OOPS", "true_positive", "thehive:case-9")

    [det] = build_tuning_report(store).detections
    assert det.overturned_fp == ["OOPS"]
    assert any("OVERTURNED" in b for b in det.blockers)


# --------------------------------------------------------------------
# injection: the attacker's route into a tuning recommendation
# --------------------------------------------------------------------

def test_injection_flagged_alerts_cannot_argue_a_rule_into_silence(tmp_path):
    """The attack this feature invites: flood a rule with alerts whose
    content talks the triager into 'benign', collect a recommendation to
    except your own infrastructure. Those firings still count as volume;
    they contribute no evidence."""
    store = _store(tmp_path)
    _noisy_rule(store, n=MIN_FIRINGS, injection=True, ips=["45.9.148.99"])

    report = build_tuning_report(store)
    [det] = report.detections
    assert len(det.firings) == MIN_FIRINGS
    assert len(det.injection_excluded) == MIN_FIRINGS
    assert det.admissible == [] and det.fp_rate is None
    assert report.noisy == []


def test_a_human_ruling_restores_an_injection_flagged_alert(tmp_path):
    """A ruling is ground truth everywhere else in this project; an
    analyst who looked at the alert and called it benign is not the
    alert's own content talking."""
    store = _store(tmp_path)
    _record(store, "A1", injection=True)
    store.record_disposition("A1", "false_positive", "thehive")

    [det] = build_tuning_report(store).detections
    assert det.injection_excluded == []
    assert det.fp == ["A1"] and det.analyst_backed_fp == ["A1"]


def test_the_exclusion_is_visible_in_the_report(tmp_path):
    store = _store(tmp_path)
    _noisy_rule(store, n=6)
    _record(store, "POISON", injection=True, ips=["45.9.148.99"])

    rendered = render_tuning_report(build_tuning_report(store))
    assert "prompt-injection attempt" in rendered


# --------------------------------------------------------------------
# the exception candidate, and refusing it
# --------------------------------------------------------------------

def test_the_shared_entity_is_proposed_with_its_inventory_role(tmp_path):
    store = _store(tmp_path)
    _noisy_rule(store, n=MIN_FIRINGS, assets=[_scanner_asset()])

    [det] = build_tuning_report(store).detections
    assert det.exception is not None
    assert det.exception.entity == "10.0.0.5"
    assert det.exception.role == "authorized vulnerability scanner"
    assert det.exception.shared_by == MIN_FIRINGS
    rendered = render_tuning_report(build_tuning_report(store))
    assert "scope an exception to it" in rendered


def test_an_inventory_known_entity_outranks_a_bare_shared_ioc(tmp_path):
    """Both are present in every false positive; the operator already
    documented one of them, so that is the defensible exception.

    The inventoried IP sorts AFTER the bare one alphabetically, so this
    fails if the ranking degrades to plain alphabetical order. The first
    version of this test used a fixture where the two orders agreed, and
    the mutation it names survived the whole suite (review catch)."""
    store = _store(tmp_path)
    _noisy_rule(
        store, n=MIN_FIRINGS, ips=["10.0.0.5", "192.0.2.7"], host=None,
        assets=[_scanner_asset(entity="192.0.2.7", name="scanner-02")],
    )

    [det] = build_tuning_report(store).detections
    assert det.exception.entity == "192.0.2.7"
    assert det.exception.role == "authorized vulnerability scanner"


def test_an_entity_the_rule_has_caught_something_on_is_refused(tmp_path):
    store = _store(tmp_path)
    _noisy_rule(store, n=8)
    _record(store, "REAL", verdict="true_positive", ips=["10.0.0.5"])
    store.record_disposition("REAL", "true_positive", "thehive:case-4")

    [det] = build_tuning_report(store).detections
    assert det.exception is None
    refused = {c.entity for c in det.refused}
    assert "10.0.0.5" in refused
    rendered = render_tuning_report(build_tuning_report(store))
    assert "NO SAFE EXCEPTION" in rendered
    assert "analyst-confirmed: REAL" in rendered


def test_an_alias_of_a_caught_asset_is_refused_too(tmp_path):
    """The regression for this feature's first real bug. The false
    positives matched the inventory, so they carry BOTH the scanner's IP
    and its hostname. The true positive matched by IP only — the
    ordinary case, since a record carries only the aliases the inventory
    matched for it. Checking the literal string refused 10.0.0.5 and
    then recommended excepting scanner-01, the same machine, with the
    words "no true positive on this detection has involved it"."""
    store = _store(tmp_path)
    _noisy_rule(store, n=8, assets=[_scanner_asset()])
    _record(store, "REAL", verdict="true_positive", ips=["10.0.0.5"])
    store.record_disposition("REAL", "true_positive", "thehive:case-4")

    [det] = build_tuning_report(store).detections
    assert det.exception is None, (
        f"recommended excepting {det.exception and det.exception.entity} "
        "on a detection that caught REAL on the same asset"
    )
    # scanner-01 appears in no true-positive record LITERALLY; only the
    # alias link to 10.0.0.5 disqualifies it.
    [alias] = [c for c in det.refused if c.entity == "scanner-01"]
    assert alias.blinded == ["REAL"] and alias.blinded_confirmed == ["REAL"]


def test_an_unruled_true_positive_still_refuses_the_exception(tmp_path):
    """An exception is forever; an unconfirmed hit is not nothing. It
    blocks — but the report must not call it analyst-confirmed."""
    store = _store(tmp_path)
    _noisy_rule(store, n=8)
    _record(store, "MAYBE", verdict="true_positive", ips=["10.0.0.5"])

    [det] = build_tuning_report(store).detections
    assert det.exception is None
    [candidate] = [c for c in det.refused if c.entity == "10.0.0.5"]
    assert candidate.blinded == ["MAYBE"]
    assert candidate.blinded_confirmed == []
    assert "analyst-confirmed" not in render_tuning_report(
        build_tuning_report(store)
    )


def test_an_entity_missing_from_one_false_positive_is_not_the_cause(tmp_path):
    """Present-in-all, not present-in-most: an exception written around
    an entity that only explains four of five false positives leaves the
    fifth firing and opens a hole for nothing."""
    store = _store(tmp_path)
    _noisy_rule(store, n=4)
    _record(store, "ODD", ips=["192.0.2.50"], host="other-host")

    [det] = build_tuning_report(store).detections
    assert det.is_noisy
    assert det.exception is None and det.refused == []
    assert "more than one cause" in render_tuning_report(
        build_tuning_report(store)
    )


# --------------------------------------------------------------------
# the loud direction
# --------------------------------------------------------------------

def test_one_confirmed_true_positive_at_routine_severity_is_a_finding(tmp_path):
    """No volume threshold in this direction: raising a detection costs
    attention, and a confirmed compromise that arrived as `low` is the
    finding by itself."""
    store = _store(tmp_path)
    _record(store, "A1", verdict="true_positive", severity="low")
    store.record_disposition("A1", "true_positive", "thehive:case-1")

    report = build_tuning_report(store)
    [det] = report.under_ranked
    assert det.under_ranked == ["A1"]
    rendered = render_tuning_report(report)
    assert "UNDER-RANKED" in rendered
    assert "raise this detection's severity" in rendered


def test_a_confirmed_true_positive_ranked_high_is_not_under_ranked(tmp_path):
    store = _store(tmp_path)
    _record(store, "A1", verdict="true_positive", severity="high")
    store.record_disposition("A1", "true_positive", "thehive:case-1")

    assert build_tuning_report(store).under_ranked == []


def test_the_copilots_own_true_positive_does_not_raise_a_detection(tmp_path):
    """Loudening is cheap, not free — and the copilot promoting its own
    verdicts into detection changes is the loop this project keeps
    closed. A human has to have ruled."""
    store = _store(tmp_path)
    _record(store, "A1", verdict="true_positive", severity="low", escalate=True)

    assert build_tuning_report(store).under_ranked == []


def test_confirmed_techniques_come_only_from_ruled_true_positives(tmp_path):
    store = _store(tmp_path)
    _record(store, "A1", verdict="true_positive", techniques=["T1110.003"])
    _record(store, "A2", verdict="true_positive", techniques=["T1059.001"],
            ips=["1.2.3.4"])
    store.record_disposition("A1", "true_positive", "thehive:case-1")

    report = build_tuning_report(store)
    assert report.confirmed_techniques == [
        ("T1110.003", 1, ["Credentialed scan"])
    ]
    assert "NOT a coverage map" in render_tuning_report(report)


# --------------------------------------------------------------------
# the window
# --------------------------------------------------------------------

def test_the_window_filters_on_when_the_desk_did_the_work(tmp_path):
    """Both alerts carry the same alert timestamp; only the write time
    differs. The window reads investigated_at, like the digest — "what
    has this desk seen lately", not "which alerts are recent"."""
    import json

    store = _store(tmp_path)
    _record(store, "OLD")
    _record(store, "NEW")
    path = tmp_path / "investigations.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[0]["investigated_at"] = (
        datetime.now(timezone.utc) - timedelta(days=40)
    ).isoformat()
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    assert build_tuning_report(store).records_considered == 2
    windowed = build_tuning_report(store, days=30)
    assert windowed.records_considered == 1
    assert windowed.window_days == 30
    assert windowed.detections[0].firings == ["NEW"]


def test_a_record_with_no_write_time_is_counted_out_not_assumed_recent(tmp_path):
    import json

    store = _store(tmp_path)
    _record(store, "A1")
    path = tmp_path / "investigations.jsonl"
    rec = json.loads(path.read_text().splitlines()[0])
    rec.pop("investigated_at")
    path.write_text(json.dumps(rec) + "\n")

    unwindowed = build_tuning_report(store)
    assert unwindowed.records_considered == 1 and unwindowed.undated_excluded == 0

    windowed = build_tuning_report(store, days=30)
    assert windowed.records_considered == 0
    assert windowed.undated_excluded == 1
    assert "no investigated_at" in render_tuning_report(windowed)


# --------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------

def test_a_title_derived_key_is_flagged_in_the_report(tmp_path):
    store = _store(tmp_path)
    for i in range(MIN_FIRINGS):
        _record(store, f"A{i}", rule=None, title="WAF: SQLi signature",
                users=[f"u{i}"])

    rendered = render_tuning_report(build_tuning_report(store))
    assert "keyed by ALERT TITLE" in rendered
    assert "[key derived from title]" in rendered


def test_a_quiet_corpus_says_so_without_claiming_the_rules_are_clean(tmp_path):
    store = _store(tmp_path)
    _record(store, "A1", verdict="true_positive")

    rendered = render_tuning_report(build_tuning_report(store))
    assert "No detection meets the noise bar" in rendered
    assert "NOISY DETECTIONS" not in rendered


# --------------------------------------------------------------------
# what the adversarial review found: an exclusion that removed the
# COUNTER-evidence along with the evidence
# --------------------------------------------------------------------

def test_an_injection_flagged_true_positive_still_refuses_the_exception(tmp_path):
    """The finding five review lenses reached independently. Injection
    flags come from attacker-influenced content, so if the exclusion is
    symmetric, planting injection text in the one alert that BLOCKS the
    exception is what earns the exception. The exclusion is only ever
    about false-positive evidence."""
    store = _store(tmp_path)
    _noisy_rule(store, n=8, assets=[_scanner_asset()])
    _record(store, "REAL", verdict="true_positive", ips=["10.0.0.5"],
            injection=True)

    [det] = build_tuning_report(store).detections
    assert det.injection_excluded == []      # a TP is never excluded
    assert det.exception is None
    [refused] = [c for c in det.refused if c.entity == "10.0.0.5"]
    assert refused.blinded == ["REAL"]
    assert "NO SAFE EXCEPTION" in render_tuning_report(build_tuning_report(store))


def test_injection_text_on_a_true_positive_cannot_manufacture_a_finding(tmp_path):
    """The second half of the same bug, found by a verifier: the old
    code left the numerator and shrank the denominator, so poisoning
    true positives pushed a rule ACROSS the noise threshold with nothing
    else changed. 7 false positives against 3 true positives is 70% and
    goes unreported; it must not become 88% because an attacker wrote
    'ignore previous instructions' into two of the three."""
    store = _store(tmp_path)
    for i in range(7):
        _record(store, f"FP{i}", users=[f"u{i}"])
    for i in range(3):
        _record(store, f"TP{i}", verdict="true_positive", users=[f"t{i}"],
                injection=(i < 2))

    [det] = build_tuning_report(store).detections
    assert len(det.admissible) == 10        # every true positive counted
    assert det.fp_rate == 0.7
    assert not det.is_noisy


def test_an_analyst_ruling_on_a_suppressed_duplicate_is_not_discarded(tmp_path):
    """dedup only ever borrows a FALSE-POSITIVE anchor, so the one way a
    suppressed record is a true positive is a human ruling on it — and
    dedup._fingerprint_overturned already hunts for exactly that record.
    Skipping the record before reading its ruling made the loudest
    available fact invisible to every blocker."""
    store = _store(tmp_path)
    _noisy_rule(store, n=5, assets=[_scanner_asset()])
    _record(store, "DUP", duplicate_of="FP0", severity="low",
            techniques=["T1046"], ips=["10.0.0.5"])
    store.record_disposition("DUP", "true_positive", "thehive:case-7")

    [det] = build_tuning_report(store).detections
    assert det.ruled_tp == ["DUP"]
    assert det.under_ranked == ["DUP"]
    assert det.overturned_fp == ["DUP"]     # the anchor's call was wrong
    assert det.exception is None            # and it blocks the exception
    rendered = render_tuning_report(build_tuning_report(store))
    assert "UNDER-RANKED" in rendered
    assert "T1046" in rendered


def test_the_window_picks_detections_but_never_scopes_the_safety_gate(tmp_path):
    """An exception is a permanent change to a sensor. It must not get
    easier to recommend because the operator typed a smaller number —
    the review reproduced the same store flipping from NO SAFE EXCEPTION
    to a clean recommendation purely by passing DAYS."""
    import json

    store = _store(tmp_path)
    _noisy_rule(store, n=5, assets=[_scanner_asset()])
    _record(store, "REAL", verdict="true_positive", ips=["10.0.0.5"])
    store.record_disposition("REAL", "true_positive", "thehive:case-4")
    # Push the true positive 40 days into the past.
    path = tmp_path / "investigations.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[-1]["investigated_at"] = (
        datetime.now(timezone.utc) - timedelta(days=40)
    ).isoformat()
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    for report in (build_tuning_report(store), build_tuning_report(store, days=7)):
        [det] = report.detections
        assert det.ruled_tp == ["REAL"], "the blocker fell out of the window"
        assert det.exception is None, "DAYS bought a recommendation"

    # ...while the VOLUME side is windowed as documented: the 40-day-old
    # true positive is not part of this week's firings.
    [windowed] = build_tuning_report(store, days=7).detections
    assert "REAL" not in windowed.firings
    assert len(windowed.firings) == 5


def test_the_alias_map_reads_records_the_window_and_latest_rule_drop(tmp_path):
    """The alias map is environment knowledge, not evidence: a
    superseded record can be the only place the inventory linked an IP
    to its host. Feeding it only the surviving in-window records
    reinstated the exact bug it exists to prevent."""
    import json

    store = _store(tmp_path)
    # A1's FIRST record carries the inventory match; its later record
    # (same alert, re-investigated) does not.
    _record(store, "A1", assets=[_scanner_asset()])
    _record(store, "A1")
    _noisy_rule(store, n=5, host=None)          # FPs share only 10.0.0.5
    _record(store, "REAL", verdict="true_positive", ips=["scanner-01"],
            host=None)
    store.record_disposition("REAL", "true_positive", "thehive:case-4")
    path = tmp_path / "investigations.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[0]["investigated_at"] = (
        datetime.now(timezone.utc) - timedelta(days=99)
    ).isoformat()
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    [det] = build_tuning_report(store, days=30).detections
    assert det.exception is None, (
        "10.0.0.5 was proposed although REAL names the same asset as "
        "scanner-01 — the alias link lives in a record the window dropped"
    )


def test_a_refused_candidate_is_shown_even_when_a_safe_one_exists(tmp_path):
    """ExceptionCandidate promises refusals are 'refused and shown, not
    silently dropped to second place', and the `elif` broke that. It
    matters most exactly when both exist: the alias map only links what
    the operator's inventory linked, so 'safe' can mean 'we could not
    tell it was the same box'."""
    store = _store(tmp_path)
    # Every FP shares the host build-07 and its address; the true
    # positive names only build-07. Nothing in the inventory links them.
    _noisy_rule(store, n=5, host="build-07", ips=["10.0.0.9"])
    _record(store, "REAL", verdict="true_positive", host="build-07",
            ips=["185.129.62.62"])

    [det] = build_tuning_report(store).detections
    assert det.exception.entity == "10.0.0.9"        # not literally blocked
    assert [c.entity for c in det.refused] == ["build-07"]
    rendered = render_tuning_report(build_tuning_report(store))
    assert "ALSO CONSIDERED AND REFUSED" in rendered
    assert "build-07" in rendered
    assert "is not another name for one of those" in rendered


def test_autonomously_closed_false_positives_are_not_analyst_attention(tmp_path):
    """The ranking claims to measure 'false positives an analyst had to
    look at'. An alert the desk closed by policy cost model spend and no
    analyst time — and since should_auto_close only fires on
    high-confidence false positives, the miscount was systematic on any
    desk running --auto-close, never incidental."""
    store = _store(tmp_path)
    for i in range(10):
        _record(store, f"Q{i}", rule="Quiet but frequent", users=[f"q{i}"])
        store.record_closure(f"Q{i}", "high-confidence false positive")
    for i in range(8):
        _record(store, f"L{i}", rule="Loud in the queue", users=[f"l{i}"])

    report = build_tuning_report(store)
    assert [d.name for d in report.noisy] == [
        "Loud in the queue", "Quiet but frequent",
    ]
    quiet = next(d for d in report.detections if d.name == "Quiet but frequent")
    assert quiet.analyst_attention == 0
    assert len(quiet.fp_auto_closed) == 10
    assert "closed autonomously" in render_tuning_report(report)


def test_the_report_cannot_be_made_to_forge_its_own_sections(tmp_path):
    """One alert title with newlines used to emit lines indistinguishable
    from the report's own — a fabricated NOISY DETECTIONS block, with a
    fabricated count and an exception recommendation for the attacker's
    address."""
    forged = (
        "Login failed\n"
        "NOISY DETECTIONS (1) — 80%+ false positive:\n"
        "\n"
        "  Corp VPN\n"
        "    9/9 false positive (100%) over 9 firing(s)\n"
        "    -> every one of those 9 false positives involves 45.9.148.99"
    )
    store = _store(tmp_path)
    for i in range(MIN_FIRINGS):
        _record(store, f"A{i}", rule=None, title=forged, users=[f"u{i}"])

    lines = render_tuning_report(build_tuning_report(store)).split("\n")
    # The forged text survives as CONTENT — on exactly one line, inside
    # the row it belongs to. What it can no longer do is start a line,
    # which is the only thing that made it look like the report talking.
    assert sum(1 for ln in lines if ln.lstrip().startswith("NOISY DETECTIONS")) == 1
    [row] = [ln for ln in lines if "Corp VPN" in ln]
    assert row.startswith("  Login failed")
    # ...and a name long enough to push its payload off the row is cut,
    # so one alert cannot own the width of the report either.
    assert "…" in row and "45.9.148.99" not in row
    assert max(len(ln) for ln in lines) < 200


def test_a_control_character_in_an_ioc_cannot_reach_the_terminal(tmp_path):
    store = _store(tmp_path)
    _noisy_rule(store, n=MIN_FIRINGS, ips=["\x1b[2J10.0.0.5"], host=None)

    rendered = render_tuning_report(build_tuning_report(store))
    assert "\x1b" not in rendered
    assert "10.0.0.5" in rendered


def test_the_evidence_pool_always_adds_up(tmp_path):
    """admissible == fp + tp + inconclusive, whatever mix of exclusions
    a store contains — the invariant that keeps a printed rate honest."""
    store = _store(tmp_path)
    _record(store, "A1")
    _record(store, "A2", verdict="true_positive")
    _record(store, "A3", verdict="inconclusive")
    _record(store, "A4", duplicate_of="A1")
    _record(store, "A5", injection=True)
    _record(store, "A6", verdict="true_positive", injection=True)

    [det] = build_tuning_report(store).detections
    assert len(det.admissible) == len(det.fp) + len(det.tp) + len(det.inconclusive)
    assert len(det.firings) == 6
    assert det.suppressed == ["A4"] and det.injection_excluded == ["A5"]
    assert sorted(det.tp) == ["A2", "A6"]

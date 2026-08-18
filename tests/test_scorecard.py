"""Unit tests for the accuracy scorecard (no API, no network).

    uv run pytest tests/test_scorecard.py -v
"""
from datetime import datetime, timezone

import pytest

from soc_copilot.history import AlertHistoryStore
from soc_copilot.models import Alert, Investigation
from soc_copilot.scorecard import build_scorecard, render_scorecard

_T = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _store(tmp_path) -> AlertHistoryStore:
    return AlertHistoryStore(tmp_path / "investigations.jsonl")


def _record(store, alert_id, verdict, ip="9.9.9.9", title="t"):
    store.record(
        Alert(
            alert_id=alert_id, timestamp=_T, source="edr", severity="high",
            title=title, raw_log={}, indicators={"ips": [ip]},
        ),
        Investigation(
            alert_id=alert_id, verdict=verdict, confidence="high",
            hypothesis="h", escalation_recommended=True,
        ),
    )


def test_empty_store_has_no_data_not_a_perfect_record(tmp_path):
    card = build_scorecard(_store(tmp_path))
    assert card.investigated == 0
    assert card.agreement_rate is None          # no data != 100%
    assert "no accuracy data yet" in render_scorecard(card)


def test_agreement_and_disagreement_are_counted(tmp_path):
    store = _store(tmp_path)
    _record(store, "A1", "true_positive", ip="1.1.1.1")
    _record(store, "A2", "true_positive", ip="2.2.2.2")
    _record(store, "A3", "inconclusive", ip="3.3.3.3")   # never ruled
    store.record_disposition("A1", "true_positive", "thehive:case-1")
    store.record_disposition("A2", "false_positive", "thehive:alert-status",
                             "Sanctioned test.")

    card = build_scorecard(store)
    assert card.investigated == 3
    assert card.ruled == 2
    assert card.agreements == 1
    assert card.agreement_rate == 0.5
    [dis] = card.disagreements
    assert (dis.alert_id, dis.copilot_verdict, dis.human_verdict) == (
        "A2", "true_positive", "false_positive"
    )


def test_copilots_latest_verdict_is_the_one_judged(tmp_path):
    """An alert investigated twice is scored on the copilot's final
    opinion — the one that stood when the human ruled."""
    store = _store(tmp_path)
    _record(store, "A1", "inconclusive")
    _record(store, "A1", "false_positive")     # later, better-grounded run
    store.record_disposition("A1", "false_positive", "thehive:alert-status")

    card = build_scorecard(store)
    assert card.investigated == 1
    assert card.agreements == 1


def test_ruling_without_local_record_is_ignored(tmp_path):
    store = _store(tmp_path)
    store.record_disposition("GHOST", "false_positive", "thehive:alert-status")
    card = build_scorecard(store)
    assert card.ruled == 0 and card.agreement_rate is None


def test_render_puts_disagreements_and_notes_up_front(tmp_path):
    store = _store(tmp_path)
    _record(store, "A1", "true_positive", title="Beaconing to external host")
    store.record_disposition("A1", "false_positive", "thehive:case-3",
                             "Purple team exercise.")
    text = render_scorecard(build_scorecard(store))
    assert "0/1 (0%)" in text
    assert "copilot said true_positive (high), analyst ruled false_positive" in text
    assert 'analyst note: "Purple team exercise."' in text
    assert "Beaconing to external host" in text


# --- v2: the desk, not only the verdicts -----------------------------------


def _record2(store, alert_id, verdict, *, confidence="high", escalate=True,
             duplicate_of=None, ip="9.9.9.9"):
    """Like _record, with the knobs the v2 metrics read."""
    store.record(
        Alert(
            alert_id=alert_id, timestamp=_T, source="edr", severity="high",
            title="t", raw_log={}, indicators={"ips": [ip]},
        ),
        Investigation(
            alert_id=alert_id, verdict=verdict, confidence=confidence,
            hypothesis="h", escalation_recommended=escalate,
            duplicate_of=duplicate_of,
        ),
    )


class _Clock:
    """Frozen, steerable stand-in for history's datetime.now()."""
    def __init__(self, start):
        self.now_value = start


def _freeze_history_clock(monkeypatch, clock):
    import soc_copilot.history as history_mod
    real = history_mod.datetime

    class _FakeDT(real):
        @classmethod
        def now(cls, tz=None):
            return clock.now_value

    monkeypatch.setattr(history_mod, "datetime", _FakeDT)


def test_agreement_is_sliced_by_stated_confidence(tmp_path):
    """Auto-close bets on the confidence gate meaning something; this row
    measures the bet against real rulings, not harness labels."""
    store = _store(tmp_path)
    _record2(store, "H1", "true_positive", confidence="high", ip="1.1.1.1")
    _record2(store, "H2", "true_positive", confidence="high", ip="2.2.2.2")
    _record2(store, "M1", "false_positive", confidence="medium", ip="3.3.3.3")
    store.record_disposition("H1", "true_positive", "thehive:case-1")
    store.record_disposition("H2", "false_positive", "thehive:case-2")
    store.record_disposition("M1", "false_positive", "thehive:case-3")

    card = build_scorecard(store)
    assert card.by_confidence == {"high": (1, 2), "medium": (1, 1)}
    text = render_scorecard(card)
    assert "high 1/2 (50%)" in text
    assert "medium 1/1 (100%)" in text


def test_escalation_precision_and_the_missed_list(tmp_path):
    # Deliberately ASYMMETRIC counts (2 confirmed vs 1 dismissed): a
    # symmetric fixture let a confirmed/dismissed swap survive the suite
    # (review catch, mutation-proven).
    store = _store(tmp_path)
    _record2(store, "E1", "true_positive", escalate=True, ip="1.1.1.1")
    _record2(store, "E2", "true_positive", escalate=True, ip="2.2.2.2")
    _record2(store, "E3", "true_positive", escalate=False, ip="3.3.3.3")
    _record2(store, "E4", "true_positive", escalate=True, ip="4.4.4.4")
    store.record_disposition("E1", "true_positive", "thehive:case-1")   # confirmed
    store.record_disposition("E2", "false_positive", "thehive:case-2")  # fatigue
    store.record_disposition("E3", "true_positive", "thehive:case-3")   # MISSED
    store.record_disposition("E4", "true_positive", "thehive:case-4")   # confirmed

    card = build_scorecard(store)
    assert card.escalations_confirmed == 2
    assert card.escalations_dismissed == 1
    assert [r.alert_id for r in card.missed_escalations] == ["E3"]
    text = render_scorecard(card)
    assert "confirmed true positive:      2" in text
    assert "dismissed as false positive:  1" in text
    assert "alert-fatigue cost" in text
    assert "MISSED (1)" in text
    assert "E3" in text


def test_an_inconclusive_ruling_on_an_escalation_is_other_not_dismissed(tmp_path):
    store = _store(tmp_path)
    _record2(store, "E1", "true_positive", escalate=True, ip="1.1.1.1")
    store.record_disposition("E1", "inconclusive", "thehive:case-1")
    card = build_scorecard(store)
    assert card.escalations_confirmed == 0
    assert card.escalations_dismissed == 0
    assert "other rulings:                1" in render_scorecard(card)


def test_escalation_section_is_absent_when_every_ruled_record_is_legacy(tmp_path):
    import json as _json
    store = _store(tmp_path)
    legacy = {
        "alert_id": "OLD", "timestamp": _T.isoformat(),
        "investigated_at": _T.isoformat(), "title": "t",
        "verdict": "true_positive", "confidence": "high",
        "host": None, "iocs": [], "attack_techniques": [],
        "duplicate_of": None, "alert": {}, "investigation": {},
    }
    with store.path.open("a") as f:
        f.write(_json.dumps(legacy) + "\n")
    store.record_disposition("OLD", "true_positive", "s")
    text = render_scorecard(build_scorecard(store))
    assert "Escalation precision" not in text   # unknown is not a section


def test_legacy_records_without_the_escalation_flag_are_excluded(tmp_path):
    """A record written before escalation_recommended was dumped is
    UNKNOWN — it must not be assumed either way, in either metric."""
    import json as _json
    store = _store(tmp_path)
    _record2(store, "NEW", "true_positive", escalate=True, ip="1.1.1.1")
    legacy = {
        "alert_id": "OLD", "timestamp": _T.isoformat(),
        "investigated_at": _T.isoformat(), "title": "t",
        "verdict": "true_positive", "confidence": "high",
        "host": None, "iocs": [], "attack_techniques": [],
        "duplicate_of": None, "alert": {}, "investigation": {},
    }
    with store.path.open("a") as f:
        f.write(_json.dumps(legacy) + "\n")
    store.record_disposition("NEW", "true_positive", "s")
    store.record_disposition("OLD", "true_positive", "s")

    card = build_scorecard(store)
    assert len(card.escalations_ruled) == 1          # OLD is not assumed True
    assert card.missed_escalations == []             # ...nor assumed False


def test_automation_rate_counts_what_the_desk_did(tmp_path):
    store = _store(tmp_path)
    _record2(store, "A1", "true_positive", ip="1.1.1.1")          # human queue
    _record2(store, "A2", "false_positive", ip="2.2.2.2")
    store.record_closure("A2", "high-confidence FP, no escalation")
    _record2(store, "A3", "false_positive", duplicate_of="A2", ip="2.2.2.2")
    store.record_closure("GHOST", "reason")          # no local record: ignored
    store.record_closure("A3", "borrowed FP closed") # already suppressed: no double count
    # A suppression with NO closure event must contribute on its own —
    # without this row, `automated = closures only` survived the suite
    # (review catch, mutation-proven).
    _record2(store, "A4", "false_positive", duplicate_of="A2", ip="2.2.2.2")

    card = build_scorecard(store)
    assert (card.worked, card.auto_closed, card.suppressed) == (4, 2, 2)
    assert card.automated == 3                        # {A2} ∪ {A3, A4}
    assert card.automation_rate == pytest.approx(3 / 4)
    text = render_scorecard(card)
    assert "alerts worked: 4" in text
    assert "left for humans: 1" in text
    assert "automation rate:  3/4 (75%)" in text
    # auto-closed(2) + suppressed(2) > automated(3): the breakdown line
    # must say the overlap out loud, or its arithmetic contradicts itself
    # (review catch).
    assert "(overlap counted once: 1)" in text


def test_a_closure_superseded_by_later_human_work_is_not_automation(
    tmp_path, monkeypatch
):
    """An alert auto-closed, then reopened, re-investigated, and ruled by
    an analyst consumed real human attention — autonomy FAILED on it.
    Counting it automated inflated the rate on exactly those alerts
    (review catch, reproduced there end-to-end)."""
    from datetime import timedelta

    store = _store(tmp_path)
    clock = _Clock(_T)
    _freeze_history_clock(monkeypatch, clock)

    _record2(store, "R1", "false_positive", ip="1.1.1.1")
    store.record_closure("R1", "clean FP")           # closed at _T
    clock.now_value = _T + timedelta(hours=4)        # analyst reopens...
    _record2(store, "R1", "true_positive", ip="1.1.1.1")

    card = build_scorecard(store)
    assert card.auto_closed == 0
    assert card.automated == 0
    assert card.closures_superseded == 1
    assert "1 closure(s) superseded by later human work" in render_scorecard(card)

    # A later analyst RULING alone (no re-investigation) also supersedes.
    store2 = AlertHistoryStore(tmp_path / "second" / "investigations.jsonl")
    clock.now_value = _T
    _record2(store2, "R2", "false_positive", ip="2.2.2.2")
    store2.record_closure("R2", "clean FP")
    clock.now_value = _T + timedelta(hours=1)
    store2.record_disposition("R2", "true_positive", "thehive:case-9")
    card2 = build_scorecard(store2)
    assert card2.auto_closed == 0 and card2.closures_superseded == 1


def test_overturning_an_anchor_supersedes_its_suppressed_copies(
    tmp_path, monkeypatch
):
    """A suppressed duplicate is closed on its ANCHOR's conclusion, never
    its own, so the anchor is where that justification can be revoked.
    Overturn the anchor and the copy's closure is stale even though
    nothing about the copy changed — before this, supersession keyed on
    alert_id alone and the copy kept counting as automation, so a digest
    could narrate a copy of a just-confirmed intrusion as work the desk
    finished by itself (review catch)."""
    from datetime import timedelta

    store = _store(tmp_path)
    clock = _Clock(_T)
    _freeze_history_clock(monkeypatch, clock)

    _record2(store, "ANCHOR", "false_positive", ip="1.1.1.1")
    _record2(store, "DUP", "false_positive", duplicate_of="ANCHOR",
             ip="1.1.1.1")
    store.record_closure("DUP", "borrowed high-confidence FP")
    clock.now_value = _T + timedelta(hours=3)
    store.record_disposition("ANCHOR", "true_positive", "thehive:case-7")

    card = build_scorecard(store)
    assert card.auto_closed_ids == set()             # the copy no longer stands
    assert card.closures_superseded == 1

    # ...and the digest, which reads that judgment, stops calling it done.
    from soc_copilot.digest import build_digest_data

    data = build_digest_data(
        store, since_hours=24, now=_T + timedelta(hours=4)
    )
    dup = [e for e in data["investigated"] if e["alert_id"] == "DUP"][0]
    assert dup["auto_closed"] is False
    assert "closure_reason" not in dup
    assert data["counts"]["auto_closed"] == 0


def test_an_unrelated_ruling_does_not_supersede_a_duplicates_closure(
    tmp_path, monkeypatch
):
    """The anchor lookup must follow `duplicate_of`, not any ruling in the
    store: a copy whose own anchor was never overturned keeps counting."""
    from datetime import timedelta

    store = _store(tmp_path)
    clock = _Clock(_T)
    _freeze_history_clock(monkeypatch, clock)

    _record2(store, "ANCHOR", "false_positive", ip="1.1.1.1")
    _record2(store, "DUP", "false_positive", duplicate_of="ANCHOR",
             ip="1.1.1.1")
    store.record_closure("DUP", "borrowed high-confidence FP")
    _record2(store, "OTHER", "true_positive", ip="5.5.5.5")
    clock.now_value = _T + timedelta(hours=3)
    store.record_disposition("OTHER", "true_positive", "thehive:case-8")

    card = build_scorecard(store)
    assert card.auto_closed_ids == {"DUP"}
    assert card.closures_superseded == 0


def test_a_standing_closure_is_not_superseded_by_its_own_investigation(
    tmp_path, monkeypatch
):
    """The normal cycle — investigate, then close moments later — must
    keep counting: only work AFTER the closure supersedes it."""
    store = _store(tmp_path)
    clock = _Clock(_T)
    _freeze_history_clock(monkeypatch, clock)
    _record2(store, "A1", "false_positive", ip="1.1.1.1")
    store.record_closure("A1", "clean FP")           # same frozen instant
    card = build_scorecard(store)
    assert card.auto_closed == 1 and card.closures_superseded == 0


def test_time_to_verdict_uses_the_first_verdict_per_alert(
    tmp_path, monkeypatch
):
    from datetime import timedelta

    store = _store(tmp_path)
    clock = _Clock(_T)
    _freeze_history_clock(monkeypatch, clock)

    clock.now_value = _T + timedelta(seconds=60)
    _record2(store, "A1", "true_positive", ip="1.1.1.1")     # fired _T -> 60s
    clock.now_value = _T + timedelta(seconds=600)
    _record2(store, "A2", "true_positive", ip="2.2.2.2")     # 600s
    # A re-investigation much later must not move A1's number: time to
    # verdict is how long the alert WAITED, and it stopped waiting at 60s.
    clock.now_value = _T + timedelta(days=2)
    _record2(store, "A1", "true_positive", ip="1.1.1.1")
    # A suppressed duplicate borrows its verdict in zero seconds — that's
    # dedup's savings, not pipeline speed; excluded.
    _record2(store, "A3", "false_positive", duplicate_of="A2", ip="2.2.2.2")

    card = build_scorecard(store)
    assert sorted(card.time_to_verdict_s) == [60.0, 600.0]
    assert card.time_to_verdict_median_s == 330.0
    assert card.time_to_verdict_p90_s == 600.0       # nearest-rank
    text = render_scorecard(card)
    assert "median 5m30s" in text
    assert "p90 10m00s" in text
    assert "(n=2)" in text


def test_suppressed_first_then_really_investigated_is_timed_on_the_real_verdict(
    tmp_path, monkeypatch
):
    """An alert whose FIRST record is a suppression but which later got a
    real investigation is a fully scored alert — dropping its latency
    sample biased the median toward never-suppressed alerts (review
    catch)."""
    from datetime import timedelta

    store = _store(tmp_path)
    clock = _Clock(_T + timedelta(seconds=5))
    _freeze_history_clock(monkeypatch, clock)
    _record2(store, "B1", "false_positive", duplicate_of="ANCHOR", ip="1.1.1.1")
    clock.now_value = _T + timedelta(seconds=120)    # anchor overturned, real run
    _record2(store, "B1", "true_positive", ip="1.1.1.1")

    card = build_scorecard(store)
    assert card.suppressed == 0                      # latest record is real
    assert card.time_to_verdict_s == [120.0]         # timed on the real verdict


def test_p90_is_nearest_rank_not_max():
    """n=10: nearest-rank p90 is the 9th value, not the 10th — a plain
    max() impostor passed the whole suite at n=2 (review catch,
    mutation-proven)."""
    from soc_copilot.scorecard import Scorecard

    card = Scorecard(
        investigated=0, ruled=0, agreements=0,
        time_to_verdict_s=[float(v) for v in
                           (10, 20, 30, 40, 50, 60, 70, 80, 90, 1000)],
    )
    assert card.time_to_verdict_p90_s == 90.0
    assert card.time_to_verdict_median_s == 55.0


def test_legacy_record_without_investigated_at_is_excluded_not_a_crash(tmp_path):
    import json as _json
    store = _store(tmp_path)
    _record2(store, "NEW", "true_positive", ip="1.1.1.1")
    legacy = {
        "alert_id": "OLD", "timestamp": _T.isoformat(), "title": "t",
        "verdict": "true_positive", "confidence": "high",
        "host": None, "iocs": [], "attack_techniques": [],
        "duplicate_of": None, "alert": {}, "investigation": {},
    }  # note: no investigated_at
    with store.path.open("a") as f:
        f.write(_json.dumps(legacy) + "\n")
    card = build_scorecard(store)
    assert len(card.time_to_verdict_s) == 1          # OLD contributes nothing


def test_fmt_duration_covers_every_scale_including_negative():
    from soc_copilot.scorecard import _fmt_duration

    assert _fmt_duration(42) == "42s"
    assert _fmt_duration(330) == "5m30s"
    assert _fmt_duration(7380) == "2h03m"
    assert _fmt_duration(266400) == "3d02h"
    # Clock skew produces negative deltas; they must render signed, not
    # masquerade as positive latency.
    assert _fmt_duration(-90) == "-1m30s"


def test_by_confidence_renders_high_before_medium_before_low(tmp_path):
    store = _store(tmp_path)
    # Inserted LOW first: insertion order must not leak into the render.
    _record2(store, "L1", "true_positive", confidence="low", ip="1.1.1.1")
    _record2(store, "M1", "true_positive", confidence="medium", ip="2.2.2.2")
    _record2(store, "H1", "true_positive", confidence="high", ip="3.3.3.3")
    for aid in ("L1", "M1", "H1"):
        store.record_disposition(aid, "true_positive", "s")
    card = build_scorecard(store)
    assert list(card.by_confidence) == ["high", "medium", "low"]


def test_a_naive_alert_timestamp_is_treated_as_utc_not_a_crash(tmp_path):
    from datetime import datetime as dt
    store = _store(tmp_path)
    store.record(
        Alert(
            alert_id="N1", timestamp=dt(2026, 6, 1, 12, 0),  # naive
            source="edr", severity="high", title="t", raw_log={},
            indicators={"ips": ["1.1.1.1"]},
        ),
        Investigation(
            alert_id="N1", verdict="true_positive", confidence="high",
            hypothesis="h", escalation_recommended=True,
        ),
    )
    card = build_scorecard(store)
    # The naive timestamp is TREATED AS UTC: with investigated_at stamped
    # at real now(), the delta equals now-minus-_T-as-UTC — assert the
    # interpretation, not merely survival (review catch).
    from datetime import datetime as _dt
    from datetime import timezone as _tz
    [delta] = card.time_to_verdict_s
    expected = (_dt.now(_tz.utc) - _T).total_seconds()
    assert abs(delta - expected) < 60


def test_desk_metrics_render_even_with_zero_rulings(tmp_path):
    """The desk sections don't need an analyst: automation and latency are
    facts about what happened, not about agreement."""
    store = _store(tmp_path)
    _record2(store, "A1", "false_positive", ip="1.1.1.1")
    store.record_closure("A1", "clean FP")
    text = render_scorecard(build_scorecard(store))
    assert "no accuracy data yet" in text            # honesty preserved
    assert "Desk automation:" in text
    assert "automation rate:  1/1 (100%)" in text
    assert "Time to verdict" in text


def test_an_analyst_note_cannot_forge_a_line_of_the_scorecard(tmp_path):
    """This renderer predates textsafe.py and quoted analyst notes and
    alert titles verbatim — both attacker-influenced, both newline-joined
    into a report an operator reads. Same class as the tuning report and
    the action list; it just had not been looked at yet."""
    store = _store(tmp_path)
    _record(store, "A1", "true_positive", title="t\nAgreement: 99/99 (100%)")
    store.record_disposition(
        "A1", "false_positive", "thehive",
        "benign\n  A2: copilot said false_positive (high), analyst ruled "
        "false_positive [thehive]",
    )

    lines = render_scorecard(build_scorecard(store)).split("\n")
    assert not any(ln.strip().startswith("Agreement: 99/99") for ln in lines)
    assert not any(ln.strip().startswith("A2:") for ln in lines)
    assert sum(1 for ln in lines if ln.startswith("Agreement:")) == 1

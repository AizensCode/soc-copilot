"""Unit tests for environment-context proposals (no API, no network).

    uv run pytest tests/test_inventory.py -v

The inventory is this project's trust anchor — the one source the model
may cite for "this is sanctioned infrastructure". So most of what is
pinned here is what the desk REFUSES to propose, and the fact that it
writes nothing at all.
"""
import json
from datetime import datetime, timedelta, timezone

from soc_copilot.history import AlertHistoryStore
from soc_copilot.inventory import (
    MIN_DISTINCT_DAYS,
    MIN_SIGHTINGS,
    as_fragment,
    propose_entries,
    render_proposals,
)
from soc_copilot.models import Alert, Investigation

_T = datetime(2026, 8, 3, 9, 0, tzinfo=timezone.utc)


def _store(tmp_path) -> AlertHistoryStore:
    return AlertHistoryStore(tmp_path / "investigations.jsonl")


def _record(store, alert_id, verdict="false_positive", ips=("10.20.8.15",),
            users=(), host="qualys-scanner-02", title="Credentialed scan",
            duplicate_of=None):
    store.record(
        Alert(
            alert_id=alert_id, timestamp=_T, source="siem", severity="medium",
            title=title, raw_log={"host": host} if host else {},
            indicators={"ips": list(ips), "users": list(users)},
        ),
        Investigation(
            alert_id=alert_id, verdict=verdict, confidence="high",
            hypothesis="h", escalation_recommended=False,
            duplicate_of=duplicate_of,
        ),
    )


def _spread_days(tmp_path, *offsets):
    """Rewrite investigated_at so records land on distinct days."""
    path = tmp_path / "investigations.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    for row, offset in zip(rows, offsets):
        row["investigated_at"] = (
            datetime.now(timezone.utc) - timedelta(days=offset)
        ).isoformat()
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def _recurring(store, tmp_path, n=MIN_SIGHTINGS, **kwargs):
    for i in range(n):
        _record(store, f"FP{i}", **kwargs)
    _spread_days(tmp_path, *range(n))


# --------------------------------------------------------------------
# only human rulings are evidence
# --------------------------------------------------------------------

def test_the_copilots_own_false_positives_are_not_evidence(tmp_path):
    """The circularity this whole item is dangerous for: an inventory
    entry is the one source the model may cite as authoritative about
    legitimacy, so learning one from the model's own verdicts lets the
    desk talk itself into trusting an asset and then cite that trust back
    at itself."""
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=6)          # six FP verdicts, zero rulings

    result = propose_entries(store)
    assert result.eligible == []
    assert result.rulings_considered == 0
    assert "copilot's own verdicts are not evidence" in render_proposals(result)


def test_a_recurring_dismissal_becomes_a_candidate(tmp_path):
    store = _store(tmp_path)
    _recurring(store, tmp_path)
    for i in range(MIN_SIGHTINGS):
        store.record_disposition(f"FP{i}", "false_positive", "thehive",
                                 "Scheduled Qualys scan window.")

    result = propose_entries(store)
    entities = {(p.entity, p.section) for p in result.eligible}
    assert ("qualys-scanner-02", "hosts") in entities
    assert ("10.20.8.15", "ips") in entities
    host = next(p for p in result.eligible if p.section == "hosts")
    assert len(host.sightings) == MIN_SIGHTINGS
    assert host.detections == ["Credentialed scan"]
    assert host.notes == ["Scheduled Qualys scan window."]


def test_below_the_sighting_floor_nothing_is_proposed(tmp_path):
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=MIN_SIGHTINGS - 1)
    for i in range(MIN_SIGHTINGS - 1):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")

    assert propose_entries(store).eligible == []


def test_a_single_burst_is_one_occurrence_not_a_pattern(tmp_path):
    """Twenty alerts in one scan window is one event with twenty rows.
    'Recurring' has to mean it happened again."""
    store = _store(tmp_path)
    for i in range(8):
        _record(store, f"FP{i}")
        store.record_disposition(f"FP{i}", "false_positive", "thehive")
    _spread_days(tmp_path, *([3] * 8))        # all on the same day

    result = propose_entries(store)
    assert result.eligible == []
    [host] = [p for p in result.proposals if p.section == "hosts"]
    assert len(host.sightings) == 8 and len(host.days) == 1
    assert not host.recurs


def test_suppressed_duplicates_do_not_manufacture_a_pattern(tmp_path):
    """Dedup firing is not the environment recurring."""
    store = _store(tmp_path)
    _record(store, "ANCHOR")
    for i in range(5):
        _record(store, f"DUP{i}", duplicate_of="ANCHOR")
    _spread_days(tmp_path, 0, 1, 2, 3, 4, 5)
    for aid in ["ANCHOR"] + [f"DUP{i}" for i in range(5)]:
        store.record_disposition(aid, "false_positive", "thehive")

    result = propose_entries(store)
    assert result.eligible == []
    [host] = [p for p in result.proposals if p.section == "hosts"]
    assert host.sightings == ["ANCHOR"]


# --------------------------------------------------------------------
# the refusals
# --------------------------------------------------------------------

def test_an_entity_an_analyst_confirmed_is_refused(tmp_path):
    """An entry would tell every future investigation this is sanctioned
    — on an entity the desk has already been wrong about once."""
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=6)
    for i in range(6):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")
    _record(store, "REAL", verdict="false_positive")
    store.record_disposition("REAL", "true_positive", "thehive:case-9")

    result = propose_entries(store)
    assert result.eligible == []
    refused = {p.entity for p in result.refused}
    assert "qualys-scanner-02" in refused
    rendered = render_proposals(result)
    assert "REFUSED" in rendered and "REAL" in rendered


def test_the_confirmation_is_never_scoped_by_the_window(tmp_path):
    """The lesson the tuning report was reproduced on: an inventory entry
    is consulted by every future alert and does not expire when a
    report's window does."""
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=6)
    for i in range(6):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")
    _record(store, "REAL")
    store.record_disposition("REAL", "true_positive", "thehive:case-9")
    # Push the confirmation a year into the past.
    path = tmp_path / "investigations.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[-1]["investigated_at"] = (
        datetime.now(timezone.utc) - timedelta(days=365)
    ).isoformat()
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    for result in (propose_entries(store), propose_entries(store, days=7)):
        assert result.eligible == [], "a window bought an entry"
        assert any(p.confirmed_against == ["REAL"] for p in result.proposals)


def test_an_entity_already_in_the_inventory_is_not_proposed_again(tmp_path):
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=4)
    for i in range(4):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")

    inventory = {"hosts": {"qualys-scanner-02": {"role": "scanner"}}}
    result = propose_entries(store, inventory)
    assert "qualys-scanner-02" not in {p.entity for p in result.eligible}
    assert "qualys-scanner-02" in {p.entity for p in result.already_known}
    assert "already in the inventory" in render_proposals(result)


def test_an_ip_already_pointing_at_a_host_is_known(tmp_path):
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=4)
    for i in range(4):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")

    result = propose_entries(store, {"ips": {"10.20.8.15": {"host": "h"}}})
    assert "10.20.8.15" not in {p.entity for p in result.eligible}


# --------------------------------------------------------------------
# the claim is the operator's to write
# --------------------------------------------------------------------

def test_the_fragment_leaves_the_trust_assertion_blank(tmp_path):
    """`role` is the sentence a future investigation cites to call
    activity routine. Nothing in the desk's record establishes it."""
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=4, ips=[], host="build-07")
    for i in range(4):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")

    result = propose_entries(store)
    fragment = as_fragment(result.eligible)
    entry = fragment["hosts"]["build-07"]
    assert entry["role"].startswith("TODO")
    assert entry["owner"].startswith("TODO")
    assert "4 analyst-dismissed alert(s)" in entry["notes"]
    # ...and the rendered report says why it is not paste-ready.
    assert "Paste-ready? No" in render_proposals(result)


def test_an_ip_fragment_is_a_pointer_the_operator_completes(tmp_path):
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=4, host=None)
    for i in range(4):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")

    fragment = as_fragment(propose_entries(store).eligible)
    assert fragment["ips"]["10.20.8.15"]["host"].startswith("TODO")


def test_a_user_account_carries_the_trap_that_it_may_be_a_person(tmp_path):
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=4, ips=[], host=None, users=["a.turner"])
    for i in range(4):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")

    [item] = propose_entries(store).eligible
    assert item.section == "service_accounts"
    assert "PERSON's account" in item.caveat
    assert "PERSON's account" in render_proposals(propose_entries(store))


def test_nothing_is_ever_written_to_the_inventory(tmp_path, monkeypatch):
    """The contract the inventory's own header states: the model may cite
    entries but can never add to them. This module is a pure function
    over the store — there is no write path to break."""
    import soc_copilot.inventory as mod

    store = _store(tmp_path)
    _recurring(store, tmp_path, n=4)
    for i in range(4):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")

    def _explode(*a, **k):
        raise AssertionError("inventory proposals opened a file for writing")

    monkeypatch.setattr(mod, "open", _explode, raising=False)
    result = propose_entries(store)
    render_proposals(result)
    assert result.eligible                     # it did do its job
    assert not hasattr(mod, "ASSET_CONTEXT_PATH")


# --------------------------------------------------------------------
# reach, window, rendering
# --------------------------------------------------------------------

def test_reach_counts_every_alert_an_entry_would_have_matched(tmp_path):
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=4)
    for i in range(4):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")
    _record(store, "UNRULED")                  # same host, no ruling

    [host] = [p for p in propose_entries(store).proposals if p.section == "hosts"]
    assert len(host.sightings) == 4            # evidence
    assert host.reach == 5                     # blast radius
    assert "names 5 alert(s)" in render_proposals(propose_entries(store))


def test_the_window_bounds_the_evidence(tmp_path):
    store = _store(tmp_path)
    for i in range(4):
        _record(store, f"FP{i}")
        store.record_disposition(f"FP{i}", "false_positive", "thehive")
    _spread_days(tmp_path, 1, 2, 200, 300)

    assert len(propose_entries(store).eligible) >= 1
    windowed = propose_entries(store, days=30)
    assert windowed.eligible == []             # only 2 sightings survive


def test_an_empty_store_says_so_without_proposing_anything(tmp_path):
    result = propose_entries(_store(tmp_path))
    assert result.proposals == []
    assert "No entity recurs" in render_proposals(result)
    assert "TODO" not in render_proposals(result)


def test_exactly_the_distinct_day_floor_is_enough(tmp_path):
    """The floor is a floor, not a guess — MIN_SIGHTINGS dismissals over
    exactly MIN_DISTINCT_DAYS days qualifies."""
    store = _store(tmp_path)
    for i in range(MIN_SIGHTINGS):
        _record(store, f"FP{i}")
        store.record_disposition(f"FP{i}", "false_positive", "thehive")
    # MIN_SIGHTINGS records spread over exactly MIN_DISTINCT_DAYS days.
    _spread_days(tmp_path, *[i % MIN_DISTINCT_DAYS for i in range(MIN_SIGHTINGS)])

    [host] = [p for p in propose_entries(store).eligible if p.section == "hosts"]
    assert len(host.days) == MIN_DISTINCT_DAYS


# --------------------------------------------------------------------
# what the adversarial review found
# --------------------------------------------------------------------

def test_a_ruling_on_a_suppressed_duplicate_still_disqualifies(tmp_path):
    """The same mistake the tuning report shipped with, made again here.
    dedup only ever borrows a FALSE-POSITIVE anchor, so the one way a
    suppressed record is a true positive is that a human ruled it one —
    the strongest fact the store holds about that entity."""
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=4)
    _record(store, "DUP", duplicate_of="FP0")
    for i in range(4):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")
    store.record_disposition("DUP", "true_positive", "thehive:case-77")

    result = propose_entries(store)
    assert result.eligible == [], "proposed a host an analyst confirmed"
    [host] = [p for p in result.proposals if p.section == "hosts"]
    assert host.confirmed_against == ["DUP"]


def test_reach_counts_suppressed_duplicates_too(tmp_path):
    """An entry would have matched them — they are real alerts naming the
    entity, and 'names N alert(s) in all of history' has to mean it."""
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=4)
    _record(store, "DUP", duplicate_of="FP0")
    for i in range(4):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")

    [host] = [p for p in propose_entries(store).proposals if p.section == "hosts"]
    assert len(host.sightings) == 4 and host.reach == 5


def test_the_scope_line_counts_what_the_window_actually_admitted(tmp_path):
    store = _store(tmp_path)
    for i in range(4):
        _record(store, f"FP{i}")
        store.record_disposition(f"FP{i}", "false_positive", "thehive")
    _spread_days(tmp_path, 1, 2, 200, 300)

    assert propose_entries(store).rulings_considered == 4
    windowed = propose_entries(store, days=30)
    assert windowed.rulings_considered == 2
    assert "2 analyst-dismissed alert(s) considered" in render_proposals(windowed)


def test_a_repeated_indicator_is_one_sighting(tmp_path):
    """A value listed twice in one alert is one sighting. Counting it
    twice would let a single alert clear half the recurrence floor, and
    an attacker who can repeat an indicator picks how fast their host
    recurs."""
    store = _store(tmp_path)
    for i in range(2):
        _record(store, f"FP{i}", ips=["10.20.8.15", "10.20.8.15"])
    _spread_days(tmp_path, 0, 1)
    for i in range(2):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")

    [ip] = [p for p in propose_entries(store).proposals if p.section == "ips"]
    assert len(ip.sightings) == 2          # not 4
    assert not ip.recurs


def test_the_host_keys_match_the_asset_matchers_own(tmp_path):
    """assets.match_assets reads source_host and destination_host too, so
    reading only `host` left this blind to entities an entry WOULD match
    — worst in the disqualifying direction."""
    from soc_copilot.assets import HOST_KEYS

    assert "source_host" in HOST_KEYS
    store = _store(tmp_path)
    for i in range(3):
        store.record(
            Alert(alert_id=f"FP{i}", timestamp=_T, source="siem",
                  severity="medium", title="t",
                  raw_log={"source_host": {"name": "jump-01"}},
                  indicators={"ips": []}),
            Investigation(alert_id=f"FP{i}", verdict="false_positive",
                          confidence="high", hypothesis="h",
                          escalation_recommended=False),
        )
    _spread_days(tmp_path, 0, 1, 2)
    for i in range(3):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")

    assert "jump-01" in {p.entity for p in propose_entries(store).eligible}


def test_an_identifier_that_is_not_one_line_is_dropped(tmp_path):
    """A hostname containing a newline is not a hostname. An inventory key
    derived from one would match nothing while reading, to an operator,
    exactly like one that would."""
    store = _store(tmp_path)
    forged = "backup-03\n  evil-host   -> hosts\n    9 dismissal(s)"
    for i in range(4):
        _record(store, f"FP{i}", host=forged, ips=[])
    _spread_days(tmp_path, 0, 1, 2, 3)
    for i in range(4):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")

    result = propose_entries(store)
    assert result.eligible == []
    assert "evil-host" not in render_proposals(result)


def test_a_title_or_note_cannot_forge_a_row_of_the_report(tmp_path):
    """Third occurrence of this class in this repo — see textsafe.py."""
    store = _store(tmp_path)
    for i in range(4):
        _record(store, f"FP{i}", title="Routine noise\n\n  evil-host   -> hosts")
    _spread_days(tmp_path, 0, 1, 2, 3)
    for i in range(4):
        store.record_disposition(f"FP{i}", "false_positive", "thehive",
                                 'note\n    analyst note: "sanctioned by infra"')

    import re

    rendered = render_proposals(propose_entries(store))
    lines = rendered.split("\n")
    # The forged text survives as CONTENT, on one line, inside the row it
    # belongs to. What it can no longer do is start a row of its own.
    assert not any(ln.strip().startswith("evil-host") for ln in lines)
    assert "sanctioned by infra" in rendered          # quoted, not obeyed
    headers = [ln for ln in lines if re.match(r"^  \S+   -> \w+$", ln)]
    assert len(headers) == 2                          # the host and its IP
    assert all("evil-host" not in h for h in headers)


def test_an_inventoried_entity_the_desk_was_wrong_about_is_not_reassuring(tmp_path):
    """The inventory's own header names this the dangerous case: an entry
    that blesses an asset the desk has since confirmed. Reporting it as
    'already in the inventory' read as reassurance."""
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=4)
    for i in range(4):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")
    _record(store, "REAL")
    store.record_disposition("REAL", "true_positive", "thehive:case-9")

    result = propose_entries(
        store, {"hosts": {"qualys-scanner-02": {"role": "scanner"}}}
    )
    assert [p.entity for p in result.stale] == ["qualys-scanner-02"]
    assert result.already_known == []
    rendered = render_proposals(result)
    assert "STALE ENTRIES" in rendered
    assert "attacker's best friend" not in rendered   # we say it in our words
    assert "wrong about" in rendered


def test_a_forged_alert_id_cannot_forge_a_refusal_line(tmp_path):
    """The one untrusted value that reaches a rendered line without being
    flattened when it is collected: alert ids, quoted in the REFUSED
    section. This is what the emit-point guard is actually load-bearing
    for here."""
    store = _store(tmp_path)
    _recurring(store, tmp_path, n=4)
    for i in range(4):
        store.record_disposition(f"FP{i}", "false_positive", "thehive")
    forged = "A-9\n  qualys-scanner-02   -> hosts\n    9 dismissal(s)"
    _record(store, forged)
    store.record_disposition(forged, "true_positive", "thehive:case-9")

    lines = render_proposals(propose_entries(store)).split("\n")
    assert not any(ln.strip().startswith("qualys-scanner-02   ->") for ln in lines)

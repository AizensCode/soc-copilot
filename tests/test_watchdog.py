"""The watch loop's dead-man's switch (no API, no network, no sleep).

The failure this exists for: an expired API key makes every alert raise
inside _work_alert, the per-alert catch prints FAILED per cycle forever,
and nobody is ever told. The watchdog turns that into one page and,
if it persists, a non-zero exit a supervisor can act on.

    uv run pytest tests/test_watchdog.py -v
"""
import pytest

from soc_copilot.main import _act_on_watch_health, _watch_once
from soc_copilot.watchdog import CycleReport, Watchdog

# --- what counts as sick -----------------------------------------------------


def test_a_quiet_queue_is_healthy():
    assert CycleReport(worked=0, failed=0).sick is False


def test_partial_progress_is_healthy():
    """One poisoned alert must not page anyone while the rest of the
    queue is being worked — it is retried, visibly, every cycle."""
    assert CycleReport(worked=3, failed=1).sick is False


def test_every_alert_failing_is_sick():
    assert CycleReport(worked=0, failed=2).sick is True


def test_a_crashed_cycle_is_sick():
    assert CycleReport(crashed=True).sick is True


# --- the escalation ladder ---------------------------------------------------


_N = 0


def _sick() -> CycleReport:
    """A systemic-looking sick cycle: a fresh alert id fails each time,
    so the streak accumulates >1 distinct failing id and stays
    exit-eligible. The lone-repeating-id shape has its own tests."""
    global _N
    _N += 1
    return CycleReport(worked=0, failed=1, failed_ids={f"A-{_N}"})


def _stuck(alert_id: str = "POISONED") -> CycleReport:
    """The same single alert failing, cycle after cycle."""
    return CycleReport(worked=0, failed=1, failed_ids={alert_id})


def _healthy() -> CycleReport:
    return CycleReport(worked=1, failed=0)


def test_pages_once_per_outage_never_per_cycle():
    dog = Watchdog(page_after=3, exit_after=30)
    actions = [dog.observe(_sick()) for _ in range(6)]
    assert actions == [None, None, "page", None, None, None]


def test_recovery_rearms_the_page_latch():
    """A second outage deserves its own page — the latch must reset on a
    genuinely healthy cycle, not stay spent forever."""
    dog = Watchdog(page_after=2, exit_after=30)
    assert [dog.observe(_sick()) for _ in range(2)] == [None, "page"]
    assert dog.observe(_healthy()) is None
    assert [dog.observe(_sick()) for _ in range(2)] == [None, "page"]


def test_exits_when_the_outage_outlives_the_budget():
    dog = Watchdog(page_after=1, exit_after=3)
    assert dog.observe(_sick()) == "page"
    assert dog.observe(_sick()) is None
    assert dog.observe(_sick()) == "exit"


def test_exit_outranks_page_when_thresholds_collide():
    dog = Watchdog(page_after=1, exit_after=1)
    assert dog.observe(CycleReport(crashed=True)) == "exit"


# --- systemic vs stuck-on-one-alert ------------------------------------------


def test_a_lone_poisoned_alert_pages_but_never_kills_the_process():
    """One malformed record on an otherwise-quiet night: every cycle is
    worked=0/failed=1 on the SAME id. The queue is stuck and a human
    should hear that once — but a restart cannot fix a poisoned record,
    and exiting would let a single bad alert take down a desk that could
    work everything else, inverting the per-alert containment promise
    (review catch)."""
    dog = Watchdog(page_after=3, exit_after=5)
    actions = [dog.observe(_stuck()) for _ in range(12)]
    assert actions.count("page") == 1
    assert "exit" not in actions


def test_a_second_failing_alert_makes_the_outage_systemic():
    """The lone-stuck-alert exemption must END the moment a DIFFERENT
    alert also fails — two distinct alerts failing with nothing working
    is the expired-key shape, and restart-with-fresh-config is back on
    the table."""
    dog = Watchdog(page_after=1, exit_after=4)
    for _ in range(6):
        dog.observe(_stuck("A-ONLY"))            # long stuck streak, no exit
    assert dog.observe(_stuck("A-OTHER")) == "exit"


def test_a_crashed_cycle_in_the_streak_makes_it_systemic():
    """Fetch failures are process-level by definition — the streak
    becomes exit-eligible even if later cycles are per-alert failures
    on one id."""
    dog = Watchdog(page_after=1, exit_after=3)
    dog.observe(CycleReport(crashed=True))
    dog.observe(_stuck())
    assert dog.observe(_stuck()) == "exit"


def test_recovery_clears_the_systemic_memory():
    """A healthy cycle ends the outage: the ids and crash flag from the
    old streak must not make a later, unrelated stuck-alert streak
    exit-eligible."""
    dog = Watchdog(page_after=1, exit_after=2)
    dog.observe(CycleReport(crashed=True))       # systemic streak begins...
    dog.observe(_healthy())                      # ...and ends
    actions = [dog.observe(_stuck()) for _ in range(6)]
    assert "exit" not in actions                 # new streak: lone id, holds


def test_recovery_forgets_the_old_streaks_failed_ids_too():
    """Both halves of the systemic memory reset on recovery. If the id
    set leaked across a healthy cycle, a stuck alert from LAST week's
    outage plus today's different stuck alert would union to >1 and
    exit the process over two unrelated lone records (mutation catch:
    only the crash-flag half was pinned)."""
    dog = Watchdog(page_after=1, exit_after=2)
    dog.observe(_stuck("A-OLD"))                 # streak one: lone id
    dog.observe(_healthy())                      # outage over
    actions = [dog.observe(_stuck("A-NEW")) for _ in range(6)]
    assert "exit" not in actions                 # still a lone id


def test_borrowed_conclusions_do_not_prove_the_pipeline_alive():
    """A dedup-suppressed duplicate completes WITHOUT a model call, so a
    repeating benign family must not mask a dead investigation pipeline:
    borrowed work neither sickens a cycle nor excuses one (review
    catch — this masked the exact expired-key outage the watchdog was
    built for, for as long as duplicates kept arriving)."""
    assert CycleReport(borrowed=2, failed=3).sick is True     # no real work
    assert CycleReport(borrowed=2, failed=0).sick is False    # quiet + dedup
    assert CycleReport(worked=1, borrowed=2, failed=3).sick is False


def test_resumed_conclusions_do_not_prove_the_pipeline_alive():
    """A cross-restart resume (soc_copilot/resume.py) delivers a verdict an
    EARLIER process paid for, so it proves the Elastic writes work and
    says nothing about the model pipeline. Counting it as real work would
    be worst exactly where resumes cluster — the first cycle after a
    crash-restart, when whatever killed the desk may still be killing it."""
    assert CycleReport(resumed=2, failed=3).sick is True      # no real work
    assert CycleReport(resumed=2, failed=0).sick is False     # quiet + resumes
    assert CycleReport(worked=1, resumed=2, failed=3).sick is False


def test_a_quiet_cycle_resets_the_exit_countdown():
    """Only CONSECUTIVE sickness escalates: an outage interrupted by a
    completed cycle is a flaky dependency, not a dead desk."""
    dog = Watchdog(page_after=2, exit_after=3)
    dog.observe(_sick())
    dog.observe(_sick())
    assert dog.observe(_healthy()) is None
    assert dog.consecutive_sick == 0
    assert dog.observe(_sick()) is None          # streak starts over


# --- the actions -------------------------------------------------------------


class _CapturingWebhook:
    posted: list[dict] = []

    def __init__(self, *a, **k):
        pass

    async def post(self, payload):
        _CapturingWebhook.posted.append(payload)


def _configure_webhook(monkeypatch, url="https://hook.test/page"):
    import dataclasses

    _CapturingWebhook.posted = []
    monkeypatch.setattr(
        "soc_copilot.notify.WebhookClient", _CapturingWebhook
    )
    import soc_copilot.config as config_mod

    # A REAL Settings with one field swapped, not a SimpleNamespace of the
    # fields this file happens to need. The stub version broke twice on
    # settings the watch path newly reads (CORRELATION_WINDOW_HOURS, then
    # RESUME_WINDOW_MINUTES), each time as a mystery "cycle crashed" that
    # made every heartbeat test read systemic. Built from the dataclass,
    # a new setting can never silently turn these tests into outage tests.
    monkeypatch.setattr(
        config_mod, "settings",
        dataclasses.replace(config_mod.Settings(), WEBHOOK_URL=url),
    )


async def test_page_action_posts_a_health_payload(monkeypatch):
    """Top-level `text` is the channel's rendering contract (notify.py):
    Slack/Mattermost 400-reject a payload without it, which would have
    made the health page page nobody — the first version shipped exactly
    that shape and this test pinned it as correct (review catch)."""
    _configure_webhook(monkeypatch)
    await _act_on_watch_health("page", 3)
    [payload] = _CapturingWebhook.posted
    assert "3 consecutive" in payload["text"]       # what Slack renders
    assert payload["kind"] == "copilot-health"
    assert "3 consecutive" in payload["summary"]


async def test_exit_goodbye_page_carries_text_too(monkeypatch):
    _configure_webhook(monkeypatch)
    with pytest.raises(SystemExit):
        await _act_on_watch_health("exit", 30)
    [payload] = _CapturingWebhook.posted
    assert "exiting" in payload["text"]


async def test_a_webhook_raising_a_non_runtimeerror_never_kills_the_loop(
    monkeypatch, caplog
):
    """httpx.InvalidURL subclasses Exception, not HTTPError, so it walked
    straight past a RuntimeError-only catch and crashed the entire watch
    loop at the exact moment it first tried to page — the dead-man's
    switch as the cause of death (review catch). The pager is
    best-effort by contract: NOTHING may escape it."""
    _configure_webhook(monkeypatch)

    async def invalid_url(self, payload):
        raise ValueError("Invalid port: 'notaport'")

    monkeypatch.setattr(_CapturingWebhook, "post", invalid_url)
    await _act_on_watch_health("page", 3)           # must not raise
    assert "could not page webhook" in caplog.text


async def test_exit_action_pages_then_raises_a_nonzero_systemexit(monkeypatch):
    _configure_webhook(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        await _act_on_watch_health("exit", 30)
    assert exc.value.code == 2
    [payload] = _CapturingWebhook.posted            # the goodbye page went out
    assert "exiting" in payload["summary"]


async def test_no_action_touches_nothing(monkeypatch):
    _configure_webhook(monkeypatch)
    await _act_on_watch_health(None, 0)
    assert _CapturingWebhook.posted == []


async def test_no_webhook_degrades_to_a_loud_line_never_a_crash(
    monkeypatch, caplog
):
    _configure_webhook(monkeypatch, url=None)
    await _act_on_watch_health("page", 3)
    assert "HEALTH:" in caplog.text and "cannot page" in caplog.text


async def test_a_failing_webhook_never_kills_the_loop(monkeypatch, caplog):
    _configure_webhook(monkeypatch)

    async def boom(self, payload):
        raise RuntimeError("Webhook returned HTTP 500")

    monkeypatch.setattr(_CapturingWebhook, "post", boom)
    await _act_on_watch_health("page", 3)           # must not raise
    assert "could not page webhook" in caplog.text


# --- the report the cycle actually files -------------------------------------


async def test_watch_once_reports_worked_and_failed_counts(tmp_path):
    from tests.test_watch import (
        _alert,
        _closing_inv,
        _FakeCopilot,
        _FakeSource,
    )

    copilot = _FakeCopilot(
        tmp_path,
        {"A1": _closing_inv("A1"), "A2": _closing_inv("A2")},
    )
    source = _FakeSource(
        hits=[("d1", _alert("A1")), ("d2", _alert("A2", ip="8.8.8.8"))]
    )
    source.fail_push_for.add("A1")

    report = await _watch_once(
        copilot, source, set(),
        agentic=False, tiered=False, auto_close=True,
        notify=False, case=False, dedup_window=None,
    )

    assert (report.worked, report.failed) == (1, 1)
    assert report.sick is False                     # partial progress


async def test_watch_once_with_every_alert_failing_reports_sick(tmp_path):
    """The expired-key shape end to end: fetch succeeds, every worked
    alert raises, the per-alert catch contains each one — and the report
    is the only place that state becomes visible."""
    from tests.test_watch import (
        _alert,
        _closing_inv,
        _FakeCopilot,
        _FakeSource,
    )

    copilot = _FakeCopilot(
        tmp_path,
        {"A1": _closing_inv("A1"), "A2": _closing_inv("A2")},
    )
    source = _FakeSource(
        hits=[("d1", _alert("A1")), ("d2", _alert("A2", ip="8.8.8.8"))]
    )
    source.fail_push_for.update({"A1", "A2"})

    report = await _watch_once(
        copilot, source, set(),
        agentic=False, tiered=False, auto_close=True,
        notify=False, case=False, dedup_window=None,
    )

    assert (report.worked, report.failed) == (0, 2)
    assert report.failed_ids == {"A1", "A2"}     # who failed feeds systemic
    assert report.sick is True


# --- the production constants ------------------------------------------------


def test_the_default_thresholds_are_the_documented_ones():
    """Production constructs Watchdog() bare, so the defaults ARE the
    operational contract — 3 cycles (~3 min) to a page, 30 (~30 min) to
    an exit. Every other test passes explicit values, so without this
    pin a mutant setting PAGE_AFTER=3000 would disable paging in
    production while the whole suite stayed green (review catch)."""
    from soc_copilot import watchdog as watchdog_mod

    dog = Watchdog()
    assert (dog.page_after, dog.exit_after) == (3, 30)
    assert (watchdog_mod.PAGE_AFTER, watchdog_mod.EXIT_AFTER) == (3, 30)


def test_more_failures_than_successes_is_still_progress():
    """Sickness is 'NO real work completed', not 'losing on points' — a
    cycle that worked one alert and failed three is degraded but alive,
    and must not feed the escalation ladder (kills the failed>worked
    mutant the original grid missed)."""
    assert CycleReport(worked=1, failed=3).sick is False


# --- the shell wiring (_run_watch_cycle) -------------------------------------


def _cycle_args():
    from types import SimpleNamespace

    return SimpleNamespace(
        agentic=False, tiered=False, auto_close=True, notify=False,
        case=False, dedup=None, interval=60,
    )


class _DeadSource:
    """Elastic is down: every fetch raises."""

    async def fetch_alert_hits(self, limit=10, status="open"):
        raise RuntimeError("connection refused")


async def test_a_failed_fetch_is_observed_as_a_crashed_cycle(
    tmp_path, monkeypatch, caplog
):
    """The wiring the infinite loop used to hide: a fetch failure must
    reach the watchdog as a CRASHED report — a mutant reporting it
    healthy silently disarmed the whole switch (review catch)."""
    from soc_copilot.main import _run_watch_cycle
    from tests.test_watch import _FakeCopilot

    _configure_webhook(monkeypatch)
    copilot = _FakeCopilot(tmp_path, {})
    dog = Watchdog(page_after=2, exit_after=30)

    for _ in range(2):
        await _run_watch_cycle(copilot, _DeadSource(), set(), dog, _cycle_args())

    assert dog.consecutive_sick == 2
    [payload] = _CapturingWebhook.posted            # the page actually fired
    assert "2 consecutive" in payload["summary"]
    assert "Poll cycle failed" in caplog.text


async def test_the_cycle_actually_acts_on_the_watchdogs_exit(
    tmp_path, monkeypatch
):
    """observe() deciding 'exit' is worthless if the shell discards it —
    the mutant that did exactly that survived before this seam existed
    (review catch)."""
    from soc_copilot.main import _run_watch_cycle
    from tests.test_watch import _FakeCopilot

    _configure_webhook(monkeypatch)
    copilot = _FakeCopilot(tmp_path, {})
    dog = Watchdog(page_after=1, exit_after=2)

    await _run_watch_cycle(copilot, _DeadSource(), set(), dog, _cycle_args())
    with pytest.raises(SystemExit) as exc:
        await _run_watch_cycle(copilot, _DeadSource(), set(), dog, _cycle_args())
    assert exc.value.code == 2


async def test_a_healthy_cycle_flows_through_with_no_action(
    tmp_path, monkeypatch
):
    from soc_copilot.main import _run_watch_cycle
    from tests.test_watch import _FakeCopilot, _FakeSource

    _configure_webhook(monkeypatch)
    copilot = _FakeCopilot(tmp_path, {})
    dog = Watchdog(page_after=1, exit_after=2)

    await _run_watch_cycle(copilot, _FakeSource(), set(), dog, _cycle_args())

    assert dog.consecutive_sick == 0
    assert _CapturingWebhook.posted == []


async def test_watch_once_reports_a_suppressed_alert_as_borrowed(
    tmp_path, monkeypatch
):
    """The report must keep dedup-borrowed completions OUT of `worked`,
    end to end — the CycleReport semantics alone can't catch a shell
    that files everything under worked (mutation catch)."""
    from tests.test_watch import _alert, _closing_inv, _FakeCopilot, _FakeSource

    def fake_suppress(store, alert, window):
        return _closing_inv("A1"), "near-duplicate of ANCHOR-1"

    monkeypatch.setattr("soc_copilot.dedup.try_suppress", fake_suppress)
    copilot = _FakeCopilot(tmp_path, {})           # a model call would KeyError
    source = _FakeSource(hits=[("d1", _alert("A1"))])

    report = await _watch_once(
        copilot, source, set(),
        agentic=False, tiered=False, auto_close=True,
        notify=False, case=False, dedup_window=24,
    )

    assert (report.worked, report.borrowed, report.failed) == (0, 1, 0)


# --- the systemic judgment, as the shell reads it ----------------------------


def test_systemic_property_tracks_distinct_failing_ids():
    dog = Watchdog()
    dog.observe(_stuck())
    assert dog.systemic is False                  # one id: confined
    dog.observe(_stuck())
    assert dog.systemic is False                  # SAME id again: still one
    dog.observe(_sick())                          # a second distinct id
    assert dog.systemic is True


def test_a_crash_makes_the_streak_systemic():
    dog = Watchdog()
    dog.observe(CycleReport(crashed=True))
    assert dog.systemic is True


def test_recovery_clears_the_systemic_judgment_and_the_ids():
    dog = Watchdog()
    dog.observe(CycleReport(crashed=True))
    dog.observe(_stuck())
    dog.observe(_healthy())
    assert dog.systemic is False
    assert dog.streak_failed_ids == frozenset()


# --- the heartbeat between the thresholds ------------------------------------
#
# The page (at page_after) and the exit (at exit_after) announce
# themselves; the cycles BETWEEN them used to pass in silence. Every
# sick cycle that takes no action must now say where the streak stands
# and which kind of sick the desk is.


async def test_heartbeat_speaks_on_actionless_sick_cycles(
    tmp_path, monkeypatch, caplog
):
    from soc_copilot.main import _run_watch_cycle
    from tests.test_watch import _FakeCopilot

    _configure_webhook(monkeypatch)
    copilot = _FakeCopilot(tmp_path, {})
    dog = Watchdog(page_after=2, exit_after=30)

    await _run_watch_cycle(copilot, _DeadSource(), set(), dog, _cycle_args())
    assert "sick streak at 1 consecutive cycle(s)" in caplog.text
    assert "pages at 2" in caplog.text            # the page is still ahead
    assert "systemic" in caplog.text              # a crash IS systemic
    assert "supervisor restart at 30" in caplog.text
    # The documented level contract is load-bearing (journalctl -p
    # warning): health lines are WARNING, not INFO (review catch: no
    # test pinned any main.py record's level).
    import logging as _logging

    assert all(
        r.levelno == _logging.WARNING
        for r in caplog.records if r.getMessage().startswith("HEALTH:")
    )

    caplog.clear()
    await _run_watch_cycle(copilot, _DeadSource(), set(), dog, _cycle_args())
    # The page cycle carries its own announcement — no heartbeat on top.
    assert len(_CapturingWebhook.posted) == 1
    assert "sick streak at 2" not in caplog.text

    caplog.clear()
    await _run_watch_cycle(copilot, _DeadSource(), set(), dog, _cycle_args())
    assert "sick streak at 3 consecutive cycle(s)" in caplog.text
    # After the threshold the page already fired: the heartbeat must not
    # phrase it as still pending (review catch).
    assert "paged at 2" in caplog.text
    assert "pages at 2" not in caplog.text


async def test_heartbeat_names_a_lone_poisoned_alert_and_promises_no_exit(
    tmp_path, monkeypatch, caplog
):
    """The operator reading the log mid-outage must be able to tell a
    countdown to a supervisor restart from a single stuck record that
    will page and hold forever."""
    from soc_copilot.main import _run_watch_cycle
    from tests.test_watch import _alert, _closing_inv, _FakeCopilot, _FakeSource

    _configure_webhook(monkeypatch)
    copilot = _FakeCopilot(tmp_path, {"A1": _closing_inv("A1")})
    source = _FakeSource(hits=[("d1", _alert("A1"))])
    source.fail_push_for.add("A1")                # only A1, every cycle
    dog = Watchdog(page_after=5, exit_after=30)

    await _run_watch_cycle(copilot, source, set(), dog, _cycle_args())
    assert "confined to A1" in caplog.text
    assert "never exits" in caplog.text
    assert "systemic" not in caplog.text


async def test_recovery_is_announced_with_the_streak_it_ended(
    tmp_path, monkeypatch, caplog
):
    from soc_copilot.main import _run_watch_cycle
    from tests.test_watch import _FakeCopilot, _FakeSource

    _configure_webhook(monkeypatch)
    copilot = _FakeCopilot(tmp_path, {})
    dog = Watchdog(page_after=10, exit_after=30)

    for _ in range(2):
        await _run_watch_cycle(copilot, _DeadSource(), set(), dog, _cycle_args())
    caplog.clear()
    # A quiet queue is a healthy cycle: the streak ends here.
    await _run_watch_cycle(copilot, _FakeSource(), set(), dog, _cycle_args())

    assert "recovered" in caplog.text
    assert "2 sick cycle(s)" in caplog.text
    assert dog.consecutive_sick == 0
    # Same WARNING level as the sickness it ends, so a level-filtered
    # view that saw the outage start also sees it end.
    import logging as _logging

    [rec] = [r for r in caplog.records if "recovered" in r.getMessage()]
    assert rec.levelno == _logging.WARNING


async def test_healthy_cycles_emit_no_health_lines(
    tmp_path, monkeypatch, caplog
):
    from soc_copilot.main import _run_watch_cycle
    from tests.test_watch import _FakeCopilot, _FakeSource

    _configure_webhook(monkeypatch)
    copilot = _FakeCopilot(tmp_path, {})
    dog = Watchdog()

    await _run_watch_cycle(copilot, _FakeSource(), set(), dog, _cycle_args())
    assert "HEALTH:" not in caplog.text


# --- the page tells the truth about what happens next ------------------------


async def test_confined_page_says_the_process_stays_up(monkeypatch):
    """The systemic page promises an exit and a supervisor restart; a
    confined (lone-poisoned-alert) streak NEVER exits by design, so its
    page asserting that promise would tell the one person acting on it
    to wait for a restart that never comes (review catch)."""
    _configure_webhook(monkeypatch)
    await _act_on_watch_health(
        "page", 3, systemic=False, stuck_ids=frozenset({"P1"})
    )
    [payload] = _CapturingWebhook.posted
    assert "stuck" in payload["text"]
    assert "P1" in payload["text"]                 # names the poisoned record
    assert "stays up" in payload["text"]
    assert "will exit for a supervisor restart" not in payload["text"]


async def test_systemic_page_keeps_the_exit_promise(monkeypatch):
    _configure_webhook(monkeypatch)
    await _act_on_watch_health(
        "page", 3, systemic=True, stuck_ids=frozenset()
    )
    [payload] = _CapturingWebhook.posted
    assert "will exit for a supervisor restart" in payload["text"]


async def test_the_cycle_wires_systemic_into_the_page_text(
    tmp_path, monkeypatch
):
    """End to end through _run_watch_cycle: a lone failing alert's page
    must arrive as the stays-up kind — the wiring passing
    watchdog.systemic into the action is exactly the sort of shell code
    a mutant can drop while every unit test stays green."""
    from soc_copilot.main import _run_watch_cycle
    from tests.test_watch import _alert, _closing_inv, _FakeCopilot, _FakeSource

    _configure_webhook(monkeypatch)
    copilot = _FakeCopilot(tmp_path, {"A1": _closing_inv("A1")})
    source = _FakeSource(hits=[("d1", _alert("A1"))])
    source.fail_push_for.add("A1")
    dog = Watchdog(page_after=1, exit_after=30)

    await _run_watch_cycle(copilot, source, set(), dog, _cycle_args())

    [payload] = _CapturingWebhook.posted
    assert "stuck" in payload["text"] and "A1" in payload["text"]
    assert "will exit for a supervisor restart" not in payload["text"]


async def test_a_drained_cycle_is_not_evidence_for_the_watchdog(
    tmp_path, monkeypatch, caplog
):
    """A shutdown drain cuts a cycle short on purpose. Feeding that
    cycle to the watchdog would fake a recovery mid-outage (a drained
    quiet cycle reads as healthy, resetting the sick streak under a
    'recovered' line while nothing recovered) — or worse, let a sick
    drained cycle page or raise the exit(2) during an operator stop
    that is about to exit 0. The drain bypasses the judgment entirely."""
    import asyncio

    from soc_copilot.main import _run_watch_cycle
    from tests.test_watch import _FakeCopilot, _FakeSource

    _configure_webhook(monkeypatch)
    copilot = _FakeCopilot(tmp_path, {})
    dog = Watchdog(page_after=10, exit_after=30)

    for _ in range(2):
        await _run_watch_cycle(copilot, _DeadSource(), set(), dog, _cycle_args())
    assert dog.consecutive_sick == 2

    stop = asyncio.Event()
    stop.set()
    caplog.clear()
    # A quiet (healthy-looking) cycle under drain: streak must survive.
    await _run_watch_cycle(
        copilot, _FakeSource(), set(), dog, _cycle_args(), stop=stop
    )
    assert dog.consecutive_sick == 2            # not reset by the drain
    assert "recovered" not in caplog.text
    # And a sick cycle under drain must not act either.
    await _run_watch_cycle(
        copilot, _DeadSource(), set(), dog, _cycle_args(), stop=stop
    )
    assert dog.consecutive_sick == 2            # not incremented
    assert _CapturingWebhook.posted == []


async def test_an_undrained_cycle_is_still_evidence_with_a_live_stop_event(
    tmp_path, monkeypatch
):
    """The production shape: _run_watch always passes a real (UNSET)
    Event, so the bypass must turn on `stop.is_set()`, not on the event
    merely existing. Mutating the guard to `if stop is not None: return`
    silently disarms the ENTIRE dead-man's switch — no heartbeat, no
    page, no exit(2) — and survived the whole suite, because every other
    wiring test passed stop=None, a shape production never runs (review
    catch)."""
    import asyncio

    from soc_copilot.main import _run_watch_cycle
    from tests.test_watch import _FakeCopilot

    _configure_webhook(monkeypatch)
    copilot = _FakeCopilot(tmp_path, {})
    dog = Watchdog(page_after=2, exit_after=30)
    stop = asyncio.Event()                      # live, but NOT set

    await _run_watch_cycle(
        copilot, _DeadSource(), set(), dog, _cycle_args(), stop=stop
    )
    assert dog.consecutive_sick == 1            # the switch still counts

    await _run_watch_cycle(
        copilot, _DeadSource(), set(), dog, _cycle_args(), stop=stop
    )
    assert dog.consecutive_sick == 2
    assert len(_CapturingWebhook.posted) == 1   # and still pages


async def test_a_drained_cycle_failure_promises_no_retry(
    tmp_path, monkeypatch, caplog
):
    """A fetch failure during the drain must not log 'retrying in 60s'
    one line before 'stopped cleanly' — the retry never comes (review
    catch). The reachable shape is a stop landing DURING the fetch: a
    stop already set on entry skips the fetch entirely."""
    import asyncio

    from soc_copilot.main import _run_watch_cycle
    from tests.test_watch import _FakeCopilot

    _configure_webhook(monkeypatch)
    stop = asyncio.Event()

    class _DyingSource:
        async def fetch_alert_hits(self, limit=10, status="open"):
            stop.set()                      # the operator stops mid-fetch
            raise RuntimeError("connection refused")

    await _run_watch_cycle(
        _FakeCopilot(tmp_path, {}), _DyingSource(), set(), Watchdog(),
        _cycle_args(), stop=stop,
    )
    assert "not retried" in caplog.text
    assert "retrying in" not in caplog.text


async def test_the_cycle_wires_the_configured_resume_window_into_the_loop(
    tmp_path, monkeypatch
):
    """The seam that joins RESUME_WINDOW_MINUTES to the loop. Everything
    else about resuming is tested by calling _work_alert/_watch_once with
    a hand-passed window, and config tests only prove Settings parses the
    env var — nothing joined the two ends. Both mutations of this line
    (reading 0 instead of the setting, or dropping the kwarg so
    _watch_once's default of 0 wins) left the entire free suite green
    while the feature was DEAD in production, re-investigating every
    crash-interrupted alert exactly as before and still logging ',
    resume window 30m' at startup (review catch — the same class of
    shell-wiring hole this test section exists for)."""
    import dataclasses

    import soc_copilot.config as config_mod
    from soc_copilot.main import _run_watch_cycle
    from tests.test_watch import (
        _alert,
        _closing_inv,
        _FakeSource,
        _interrupted,
    )

    _configure_webhook(monkeypatch)
    alert = _alert("A1")
    copilot = _interrupted(tmp_path, alert)          # crash-interrupted state
    source = _FakeSource(hits=[("d1", alert)])
    dog = Watchdog()

    await _run_watch_cycle(copilot, source, set(), dog, _cycle_args())

    assert copilot.investigated == []                # resumed, not re-bought
    assert source.status == {"d1": "closed"}
    assert dog.consecutive_sick == 0

    # ...and with the documented off switch, the SAME state is investigated.
    monkeypatch.setattr(
        config_mod, "settings",
        dataclasses.replace(config_mod.settings, RESUME_WINDOW_MINUTES=0),
    )
    alert2 = _alert("A2")
    copilot2 = _interrupted(tmp_path / "off", alert2)
    copilot2._invs = {"A2": _closing_inv("A2")}
    source2 = _FakeSource(hits=[("d2", alert2)])

    await _run_watch_cycle(copilot2, source2, set(), dog, _cycle_args())

    assert copilot2.investigated == ["A2"]           # paid for a fresh look

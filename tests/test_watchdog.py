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
    from types import SimpleNamespace

    _CapturingWebhook.posted = []
    monkeypatch.setattr(
        "soc_copilot.notify.WebhookClient", _CapturingWebhook
    )
    import soc_copilot.config as config_mod

    monkeypatch.setattr(
        config_mod, "settings",
        SimpleNamespace(WEBHOOK_URL=url),
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
    monkeypatch, capsys
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
    assert "could not page webhook" in capsys.readouterr().out


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
    monkeypatch, capsys
):
    _configure_webhook(monkeypatch, url=None)
    await _act_on_watch_health("page", 3)
    out = capsys.readouterr().out
    assert "HEALTH:" in out and "cannot page" in out


async def test_a_failing_webhook_never_kills_the_loop(monkeypatch, capsys):
    _configure_webhook(monkeypatch)

    async def boom(self, payload):
        raise RuntimeError("Webhook returned HTTP 500")

    monkeypatch.setattr(_CapturingWebhook, "post", boom)
    await _act_on_watch_health("page", 3)           # must not raise
    assert "could not page webhook" in capsys.readouterr().out


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
    tmp_path, monkeypatch, capsys
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
    assert "Poll cycle failed" in capsys.readouterr().out


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

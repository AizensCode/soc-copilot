"""Unit tests for the watch loop's seam (no API, no network, no sleep).

Until this file existed, --watch was only exercised live: the ordering
contract that keeps the closure log honest (push -> status -> record,
never record-then-fail) rested on review-verified reading of _run_watch.
These tests pin it against fakes — _work_alert and _watch_once are the
loop's entire behavior; the shell that remains untested is construction,
the infinite loop, and a sleep.

    uv run pytest tests/test_watch.py -v
"""
from datetime import datetime, timezone

import httpx
import pytest

import soc_copilot.main as main
from soc_copilot.history import AlertHistoryStore
from soc_copilot.main import _watch_once, _work_alert
from soc_copilot.models import Alert, Investigation

_T = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _alert(alert_id: str, ip: str = "9.9.9.9") -> Alert:
    return Alert(
        alert_id=alert_id, timestamp=_T, source="edr", severity="high",
        title=f"alert {alert_id}", raw_log={}, indicators={"ips": [ip]},
    )


def _closing_inv(alert_id: str) -> Investigation:
    """Passes every should_auto_close gate — the REAL policy runs in
    these tests; only the model call and Elastic are faked."""
    return Investigation(
        alert_id=alert_id, verdict="false_positive", confidence="high",
        hypothesis="benign, clearly", escalation_recommended=False,
    )


def _escalating_inv(alert_id: str) -> Investigation:
    return Investigation(
        alert_id=alert_id, verdict="true_positive", confidence="high",
        hypothesis="bad, clearly", escalation_recommended=True,
    )


class _FakeSource:
    """Records every Elastic side effect, in order, and fails on demand."""

    def __init__(self, hits=None):
        self.hits = hits or []
        self.calls: list[tuple] = []
        self.fail_push_for: set[str] = set()
        self.fail_status_for: set[str] = set()
        self.status: dict[str, str] = {}

    async def fetch_alert_hits(self, limit=10, status="open"):
        self.calls.append(("fetch", status))
        # The real source filters on kibana.alert.workflow_status, which is
        # WHY acknowledgement rather than the seen-set is what keeps a
        # worked alert out of the next cycle. An earlier version of this
        # fake returned every hit regardless of `status`, which made the
        # acknowledgement invisible and led a reviewer to conclude the loop
        # reworked alerts it does not — a fake that hides the semantic it
        # exists to model is worse than no fake.
        return [
            (doc_id, alert)
            for doc_id, alert in self.hits
            if self.status.get(doc_id, "open") == status
        ][:limit]

    async def push_investigation(
        self, alert, investigation, auto_closed=False, closure_reason=None
    ):
        if alert.alert_id in self.fail_push_for:
            raise RuntimeError("Elastic push blew up")
        self.calls.append(
            ("push", alert.alert_id, auto_closed, closure_reason)
        )
        return f"doc-{alert.alert_id}"

    async def set_alert_status(self, doc_id, status):
        if doc_id in self.fail_status_for:
            raise RuntimeError("Elastic status write blew up")
        self.status[doc_id] = status
        self.calls.append(("status", doc_id, status))


class _FakeCopilot:
    """A real history store; a canned verdict instead of a model call."""

    def __init__(self, tmp_path, invs: dict[str, Investigation]):
        self.history = AlertHistoryStore(tmp_path / "investigations.jsonl")
        self._invs = invs
        self.investigated: list[str] = []

    async def investigate(self, alert):
        self.investigated.append(alert.alert_id)
        return self._invs[alert.alert_id]


def _work(copilot, source, doc_id, alert, seen, **overrides):
    defaults = dict(
        agentic=False, tiered=False, auto_close=True,
        notify=False, case=False, dedup_window=None,
    )
    defaults.update(overrides)
    return _work_alert(copilot, source, doc_id, alert, seen, **defaults)


# --- the ordering contract -------------------------------------------------

async def test_auto_close_records_only_after_both_elastic_writes(tmp_path):
    """The happy path, in the pinned order: push -> status(closed) ->
    record_closure -> seen. The closure lands in the store with the
    policy's reason."""
    copilot = _FakeCopilot(tmp_path, {"A1": _closing_inv("A1")})
    source = _FakeSource()
    seen: set[str] = set()

    await _work(copilot, source, "d1", _alert("A1"), seen)

    assert [c[0] for c in source.calls] == ["push", "status"]
    assert source.calls[0][2] is True                  # pushed as auto-closed
    assert source.calls[1][2] == "closed"
    closures = copilot.history.closures()
    assert "A1" in closures
    assert "high-confidence false positive" in closures["A1"]["reason"]
    assert seen == {"d1"}


async def test_push_failure_leaves_no_phantom_closure(tmp_path):
    """The review catch this seam exists to pin: a failed push must leave
    NO closure record, no status write, and the alert unmarked — so the
    next cycle retries it."""
    copilot = _FakeCopilot(tmp_path, {"A1": _closing_inv("A1")})
    source = _FakeSource()
    source.fail_push_for.add("A1")
    seen: set[str] = set()

    with pytest.raises(RuntimeError):
        await _work(copilot, source, "d1", _alert("A1"), seen)

    assert source.calls == []                          # nothing reached Elastic
    assert copilot.history.closures() == {}            # no phantom closure
    assert seen == set()                               # retried next cycle


async def test_status_failure_undercounts_never_overcounts(tmp_path):
    """A crash between the status write and the record drops the closure
    record — automation is undercounted, the safe direction. It must
    never be recorded first."""
    copilot = _FakeCopilot(tmp_path, {"A1": _closing_inv("A1")})
    source = _FakeSource()
    source.fail_status_for.add("d1")
    seen: set[str] = set()

    with pytest.raises(RuntimeError):
        await _work(copilot, source, "d1", _alert("A1"), seen)

    assert [c[0] for c in source.calls] == ["push"]    # push happened
    assert copilot.history.closures() == {}            # record did NOT
    assert seen == set()


# --- disposition routing ---------------------------------------------------

async def test_without_auto_close_everything_is_acknowledged(tmp_path):
    """The same closing-qualified verdict without --auto-close: the
    policy is never consulted, the alert is acknowledged, and no closure
    is recorded."""
    copilot = _FakeCopilot(tmp_path, {"A1": _closing_inv("A1")})
    source = _FakeSource()

    await _work(copilot, source, "d1", _alert("A1"), set(), auto_close=False)

    assert ("status", "d1", "acknowledged") in source.calls
    assert copilot.history.closures() == {}


async def test_auto_closed_alert_generates_no_case_and_no_page(
    tmp_path, monkeypatch
):
    """An auto-closed alert needs no human owner — the case and notify
    policies must never even be offered it. An acknowledged alert IS
    offered to both, and the page carries the case id."""
    offered = []

    async def fake_case(alert, investigation, case, store=None):
        offered.append(("case", alert.alert_id))
        return "~thehive-1"

    async def fake_notify(alert, investigation, notify, case_id=None):
        offered.append(("notify", alert.alert_id, case_id))

    monkeypatch.setattr(main, "_maybe_open_case", fake_case)
    monkeypatch.setattr(main, "_maybe_notify", fake_notify)

    copilot = _FakeCopilot(
        tmp_path, {"A1": _closing_inv("A1"), "A2": _escalating_inv("A2")}
    )
    source = _FakeSource()

    await _work(copilot, source, "d1", _alert("A1"), set())
    assert offered == []                               # closed: no noise

    await _work(copilot, source, "d2", _alert("A2", ip="8.8.8.8"), set())
    assert offered == [("case", "A2"), ("notify", "A2", "~thehive-1")]


async def test_suppressed_duplicate_spends_no_model_call(
    tmp_path, monkeypatch
):
    """When dedup suppresses, the borrowed conclusion is pushed and the
    model is never called."""
    borrowed = _closing_inv("A1")

    def fake_suppress(store, alert, window):
        return borrowed, "near-duplicate of ANCHOR-1"

    monkeypatch.setattr(
        "soc_copilot.dedup.try_suppress", fake_suppress
    )
    copilot = _FakeCopilot(tmp_path, {})               # investigate would KeyError
    source = _FakeSource()

    await _work(copilot, source, "d1", _alert("A1"), set(), dedup_window=24)

    assert copilot.investigated == []                  # no model call spent
    [push] = [c for c in source.calls if c[0] == "push"]
    assert push[1] == "A1"
    assert push[2] is True                             # borrowed FP auto-closes


# --- the cycle -------------------------------------------------------------

async def test_one_failing_alert_does_not_kill_the_cycle(tmp_path, caplog):
    """Alert one's push fails; alert two must still be worked, and only
    alert two is marked seen."""
    copilot = _FakeCopilot(
        tmp_path,
        {"A1": _closing_inv("A1"), "A2": _closing_inv("A2")},
    )
    source = _FakeSource(
        hits=[("d1", _alert("A1")), ("d2", _alert("A2", ip="8.8.8.8"))]
    )
    source.fail_push_for.add("A1")
    seen: set[str] = set()

    await _watch_once(
        copilot, source, seen,
        agentic=False, tiered=False, auto_close=True,
        notify=False, case=False, dedup_window=None,
    )

    assert seen == {"d2"}
    assert "FAILED (will retry next cycle)" in caplog.text
    # A failed alert is ERROR — the level contract journalctl -p filters
    # on (review catch: no test pinned any main.py record's level).
    import logging

    [rec] = [r for r in caplog.records if "FAILED" in r.getMessage()]
    assert rec.levelno == logging.ERROR
    assert ("push", "A2", True,
            "high-confidence false positive with no escalation, injection, "
            "or campaign signals") in source.calls


async def test_thehive_outage_neither_aborts_the_alert_nor_eats_the_page(
    tmp_path, monkeypatch, caplog
):
    """--case is documented as never fatal, and an outage is a REFUSED
    CONNECTION, not a status code. Untranslated it escaped _maybe_open_case
    and aborted _work_alert at step 5 — after the alert was acknowledged
    and marked seen, so it could never come back — taking the escalation
    page down with it under a log line promising a retry (review catch).

    The whole real chain runs here: TheHiveClient.create_alert, its
    translation, and both never-fatal wrappers."""
    from types import SimpleNamespace

    from soc_copilot import casemgmt as casemgmt_mod

    monkeypatch.setattr(
        casemgmt_mod,
        "settings",
        SimpleNamespace(
            THEHIVE_URL="https://thehive.test:9000",
            THEHIVE_API_KEY="key123",
            THEHIVE_ORGANISATION=None,
        ),
    )

    async def dead_request(method, url, **kwargs):
        raise httpx.ConnectError("connection refused")

    paged: list[dict] = []

    class _FakeWebhook:
        def __init__(self, *a, **k):
            pass

        async def post(self, payload):
            paged.append(payload)

    monkeypatch.setattr("soc_copilot.httpio.request", dead_request)
    monkeypatch.setattr("soc_copilot.notify.WebhookClient", _FakeWebhook)

    copilot = _FakeCopilot(tmp_path, {"A1": _escalating_inv("A1")})
    source = _FakeSource()
    seen: set[str] = set()

    await _work(
        copilot, source, "d1", _alert("A1"), seen, case=True, notify=True
    )

    assert "Case creation failed" in caplog.text    # warned, not raised
    assert "unreachable" in caplog.text             # and says what happened
    assert len(paged) == 1                          # the page still went out
    assert seen == {"d1"}                           # the alert completed


async def test_acknowledgement_not_the_seen_set_ends_the_work(tmp_path):
    """Acknowledgement IS the dedupe: an alert worked in cycle one is gone
    from cycle two's fetch even with a FRESH seen-set each cycle, because
    the source filters on workflow_status. The seen-set is only the second
    guard for the window where a status write hasn't taken effect."""
    copilot = _FakeCopilot(tmp_path, {"A1": _escalating_inv("A1")})
    source = _FakeSource(hits=[("d1", _alert("A1"))])
    cycle = dict(
        agentic=False, tiered=False, auto_close=True,
        notify=False, case=False, dedup_window=None,
    )

    await _watch_once(copilot, source, set(), **cycle)
    await _watch_once(copilot, source, set(), **cycle)

    assert copilot.investigated == ["A1"]           # worked exactly once
    assert source.status == {"d1": "acknowledged"}


async def test_seen_alerts_are_not_reworked(tmp_path):
    """The second guard beside acknowledgement: a doc id already in
    `seen` is filtered before prioritization, so a status write whose
    effect lags a poll can't trigger a paid re-investigation."""
    copilot = _FakeCopilot(tmp_path, {"A1": _closing_inv("A1")})
    source = _FakeSource(hits=[("d1", _alert("A1"))])
    seen = {"d1"}

    await _watch_once(
        copilot, source, seen,
        agentic=False, tiered=False, auto_close=True,
        notify=False, case=False, dedup_window=None,
    )

    assert copilot.investigated == []
    assert [c[0] for c in source.calls] == ["fetch"]


# --- the correlation id, wired end to end -----------------------------------


async def test_narration_carries_the_alert_id_end_to_end(tmp_path, capsys):
    """The headline claim — 'everything logged while one alert is being
    worked carries that alert's id' — through the REAL pipeline:
    _watch_once's alert_context binding, the handler's filter, the JSON
    formatter. A mutant deleting the with-block in _watch_once survived
    the whole suite before this test (review catch): every other
    correlation test exercises alert_context directly, never the CLI
    wiring."""
    import json
    import logging

    from soc_copilot.logsetup import configure_logging

    logger = logging.getLogger("soc_copilot")
    saved_handlers, saved_level = list(logger.handlers), logger.level
    configure_logging("json", "INFO")
    try:
        copilot = _FakeCopilot(tmp_path, {"A1": _closing_inv("A1")})
        source = _FakeSource(hits=[("d1", _alert("A1"))])
        source.fail_push_for.add("A1")
        await _watch_once(
            copilot, source, set(),
            agentic=False, tiered=False, auto_close=True,
            notify=False, case=False, dedup_window=None,
        )
    finally:
        logger.handlers = saved_handlers
        logger.setLevel(saved_level)

    lines = [
        json.loads(ln)
        for ln in capsys.readouterr().err.splitlines() if ln
    ]
    failed = [d for d in lines if "FAILED" in d["msg"]]
    assert failed and failed[0]["alert_id"] == "A1"
    header = [d for d in lines if "priority:" in d["msg"]]
    assert header and header[0]["alert_id"] == "A1"


# --- graceful shutdown: the drain -------------------------------------------


async def test_drain_finishes_the_inflight_alert_and_leaves_the_rest(
    tmp_path, caplog
):
    """SIGTERM mid-alert: the alert being worked FINISHES (its model
    call is already paid for, and the write ordering completes it
    honestly — push, status, seen), everything queued behind it is left
    unstarted for the next start, and a drained cycle is a healthy one."""
    import asyncio

    copilot = _FakeCopilot(tmp_path, {
        "A1": _closing_inv("A1"), "A2": _closing_inv("A2"),
        "A3": _closing_inv("A3"),
    })
    source = _FakeSource(hits=[
        ("d1", _alert("A1")), ("d2", _alert("A2", ip="8.8.8.8")),
        ("d3", _alert("A3", ip="9.9.9.8")),
    ])
    stop = asyncio.Event()
    orig = copilot.investigate

    async def investigate_and_signal(alert):
        stop.set()                          # the signal lands MID-alert
        return await orig(alert)

    copilot.investigate = investigate_and_signal
    seen: set[str] = set()

    report = await _watch_once(
        copilot, source, seen,
        agentic=False, tiered=False, auto_close=True,
        notify=False, case=False, dedup_window=None, stop=stop,
    )

    assert seen == {"d1"}                   # the in-flight alert completed
    assert [c[0] for c in source.calls if c[0] != "fetch"] == [
        "push", "status",
    ]
    assert (report.worked, report.failed) == (1, 0)
    assert report.sick is False             # a drained cycle is healthy
    # Announced ONCE, with the true remaining count — a drain that fell
    # through the queue instead of breaking would repeat the line with a
    # different number each time (mutation catch).
    drain_lines = [
        r.getMessage() for r in caplog.records
        if "Draining for shutdown" in r.getMessage()
    ]
    assert len(drain_lines) == 1
    assert "2 fresh alert(s)" in drain_lines[0]


async def test_a_stop_before_the_cycle_touches_elastic_at_all(
    tmp_path, caplog
):
    """A stop that landed before the cycle (during the sleep or the
    feedback sync) must not even FETCH: that call can burn ~41s of the
    supervisor's grace — a 20s timeout plus a replayable retry — to
    build a queue about to be abandoned (review catch)."""
    import asyncio

    copilot = _FakeCopilot(tmp_path, {"A1": _closing_inv("A1")})
    source = _FakeSource(hits=[("d1", _alert("A1"))])
    stop = asyncio.Event()
    stop.set()

    report = await _watch_once(
        copilot, source, set(),
        agentic=False, tiered=False, auto_close=True,
        notify=False, case=False, dedup_window=None, stop=stop,
    )

    assert copilot.investigated == []
    assert source.calls == []                    # not even the fetch
    assert (report.worked, report.failed) == (0, 0)
    assert "skipping this poll cycle" in caplog.text


async def test_stop_handler_drains_first_then_dies_by_the_second_signal(
    monkeypatch, caplog
):
    """First signal: set the event, keep running (the drain). Second:
    die BY the signal — WIFSIGNALED, which a supervisor reads as a clean
    stop, where an exit CODE of 143 is a failure to systemd.

    The safety scaffolding is the point (review catch: the previous
    version claimed 'a bug can never kill the test runner' and was
    false). Everything fatal is neutralized BEFORE the first signal —
    the death seam is patched, and SIGUSR1 gets a benign disposition so
    a handler that never installs cannot terminate pytest either — so a
    branch-swap or missing-install mutant fails as an assertion, not as
    a dead runner."""
    import asyncio
    import signal

    import soc_copilot.main as main

    deaths: list[tuple] = []
    monkeypatch.setattr(
        main, "_die_by_signal", lambda loop, sig: deaths.append(("die", sig))
    )
    # A signal that would otherwise TERMINATE this process by default.
    previous = signal.signal(signal.SIGUSR1, lambda *a: None)

    stop = asyncio.Event()
    main._install_stop_handler(stop, sig=signal.SIGUSR1)
    try:
        signal.raise_signal(signal.SIGUSR1)
        await asyncio.wait_for(stop.wait(), timeout=2)
        assert deaths == []                  # the FIRST signal drains
        assert "finishing the alert in flight" in caplog.text

        signal.raise_signal(signal.SIGUSR1)
        for _ in range(200):                 # let the loop run the callback
            if deaths:
                break
            await asyncio.sleep(0.01)
        assert deaths == [("die", signal.SIGUSR1)]
        assert "Second stop signal" in caplog.text
    finally:
        try:
            asyncio.get_running_loop().remove_signal_handler(signal.SIGUSR1)
        finally:
            signal.signal(signal.SIGUSR1, previous)


def test_die_by_signal_restores_the_default_then_reraises(monkeypatch):
    """The death seam itself: the handler must be REMOVED before the
    re-raise (otherwise asyncio catches it again and the process never
    dies), and the process must be signalled, not exited."""
    import signal
    from types import SimpleNamespace

    import soc_copilot.main as main

    order: list[str] = []
    loop = SimpleNamespace(
        remove_signal_handler=lambda s: order.append(f"remove:{s}")
    )
    monkeypatch.setattr(
        main.os, "kill", lambda pid, s: order.append(f"kill:{s}")
    )
    main._die_by_signal(loop, signal.SIGTERM)
    assert order == [f"remove:{signal.SIGTERM}", f"kill:{signal.SIGTERM}"]


async def test_sleep_or_stop_is_a_real_sleep_until_the_signal():
    import asyncio
    import time

    from soc_copilot.main import _sleep_or_stop

    quiet = asyncio.Event()
    assert await _sleep_or_stop(quiet, 0.01) is True       # keep looping

    stopped = asyncio.Event()
    stopped.set()
    t0 = time.monotonic()
    assert await _sleep_or_stop(stopped, 60) is False      # no waiting-out
    assert time.monotonic() - t0 < 1

    mid = asyncio.Event()
    asyncio.get_running_loop().call_later(0.02, mid.set)
    t0 = time.monotonic()
    assert await _sleep_or_stop(mid, 60) is False          # woken mid-sleep
    assert time.monotonic() - t0 < 5


def test_should_sync_feedback_never_starts_a_sync_after_a_stop():
    """A full TheHive sync started after the stop signal spends the
    supervisor's grace on work nobody is waiting for. The clause lived
    inline in the loop shell, where no test executed it (review
    catch) — it is a predicate now, and this is the pin."""
    import asyncio

    from soc_copilot.main import FEEDBACK_SYNC_INTERVAL, _should_sync_feedback

    quiet = asyncio.Event()
    due = FEEDBACK_SYNC_INTERVAL + 1
    assert _should_sync_feedback(True, quiet, 0.0, due) is True
    assert _should_sync_feedback(True, quiet, 0.0, 1.0) is False   # not due
    assert _should_sync_feedback(False, quiet, 0.0, due) is False  # no TheHive

    stopping = asyncio.Event()
    stopping.set()
    assert _should_sync_feedback(True, stopping, 0.0, due) is False


def test_the_shipped_grace_periods_cover_the_drain():
    """The drain's operational half: both supervisors must give the
    in-flight alert real time. A revert to the old 10s (a plausible
    copy-paste) would silently reinstate SIGKILL-mid-alert with every
    test green — the same drift risk the watchdog thresholds are pinned
    against."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    unit = (root / "deploy" / "soc-copilot-watch.service").read_text()
    compose = (root / "docker-compose.yml").read_text()

    [systemd_secs] = re.findall(r"TimeoutStopSec=(\d+)", unit)
    [docker_secs] = re.findall(r"stop_grace_period:\s*(\d+)s", compose)
    assert int(systemd_secs) >= 120
    assert int(docker_secs) == int(systemd_secs)      # one promise, two files


async def test_a_loop_without_signal_support_says_so_plainly(monkeypatch):
    """NotImplementedError subclasses RuntimeError, so cli()'s
    configuration-error handler caught it and printed a bare
    'Configuration error:' with no message — blaming a config that was
    fine (review catch). The failure must name the real reason."""
    import asyncio
    import signal

    import soc_copilot.main as main

    loop = asyncio.get_running_loop()

    def unsupported(sig, handler):
        raise NotImplementedError

    monkeypatch.setattr(loop, "add_signal_handler", unsupported)
    with pytest.raises(RuntimeError, match="Unix event loop"):
        main._install_stop_handler(asyncio.Event(), sig=signal.SIGUSR1)


async def test_annotation_stops_chaining_writes_once_draining(
    monkeypatch, caplog
):
    """A stop landing mid-sync must not chain another ruling's write:
    each is a 20s-timeout call with a retry, so a long ruling list could
    outlast the supervisor's grace and turn the drain into a SIGKILL
    (review catch). The rulings are already safe in the history store."""
    import asyncio

    stamped: list[str] = []
    stop = asyncio.Event()

    class _FakeElastic:
        def __init__(self, *a, **k):
            pass

        async def annotate_disposition(self, alert_id, verdict, summary):
            stamped.append(alert_id)
            stop.set()                       # the operator stops mid-sync
            return 1

    monkeypatch.setattr("soc_copilot.elastic.ElasticAlertSource", _FakeElastic)
    changed = [
        {"alert_id": f"A{i}", "human_verdict": "true_positive", "summary": ""}
        for i in range(4)
    ]

    await main._annotate_elastic(changed, stop=stop)

    assert stamped == ["A0"]                 # the rest deferred, not chained
    assert "3 Elastic annotation(s) deferred" in caplog.text


def test_the_unit_start_limit_lives_where_systemd_reads_it():
    """systemd parses StartLimitIntervalSec only in [Unit] and silently
    ignores it in [Service] — where this unit had it. Ignored, the
    interval fell back to the 10s default, and with RestartSec=60 ten
    starts in ten seconds is impossible, so the documented 'ten failures
    in an hour stops the unit' protection could never trigger and a
    hard-broken config would flap forever (`systemd-analyze verify`
    catch)."""
    import configparser
    from pathlib import Path

    unit = Path(__file__).resolve().parent.parent / "deploy" / (
        "soc-copilot-watch.service"
    )
    cfg = configparser.ConfigParser(strict=False)
    cfg.read(unit)
    assert cfg["Unit"]["StartLimitIntervalSec"] == "3600"
    assert cfg["Unit"]["StartLimitBurst"] == "10"
    assert "StartLimitIntervalSec" not in cfg["Service"]

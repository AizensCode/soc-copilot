"""Unit tests for the shared outbound-HTTP policy (no network, no sleep).

The policy is small and load-bearing: ONE retry, connect failures always
retry (the request never reached the server), everything past that point
retries only when the call site declared the request replayable. These
tests pin each branch with a MockTransport that fails on demand.

    uv run pytest tests/test_httpio.py -v
"""
import httpx
import pytest

from soc_copilot import httpio


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    monkeypatch.setattr(httpio, "BACKOFF_SECONDS", 0)


class _Script:
    """Serve a scripted sequence of responses/exceptions, then count."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.attempts = 0

    def __call__(self, request):
        self.attempts += 1
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        return httpx.Response(step, json={"ok": True})


def _client(script):
    return httpx.AsyncClient(transport=httpx.MockTransport(script))


async def _get(script, **kwargs):
    async with _client(script) as client:
        return await httpio.request(
            "GET", "http://x.test/y", client=client, **kwargs
        )


async def test_success_spends_one_attempt():
    script = _Script(200)
    resp = await _get(script)
    assert resp.json() == {"ok": True}
    assert script.attempts == 1


async def test_connect_failure_retries_even_when_not_replayable():
    """A refused connection never reached the server — replaying cannot
    double-apply anything, so even create-shaped requests retry it."""
    script = _Script(httpx.ConnectError("refused"), 200)
    resp = await _get(script, replayable=False)
    assert resp.status_code == 200
    assert script.attempts == 2


async def test_retry_budget_is_one_then_the_error_propagates():
    script = _Script(httpx.ConnectError("down"), httpx.ConnectError("down"))
    with pytest.raises(httpx.ConnectError):
        await _get(script)
    assert script.attempts == 2                        # bounded: never a third


async def test_transient_status_retries_only_when_replayable():
    ok = _Script(503, 200)
    resp = await _get(ok, replayable=True)
    assert resp.status_code == 200
    assert ok.attempts == 2

    not_ok = _Script(503, 200)
    with pytest.raises(httpx.HTTPStatusError):
        await _get(not_ok, replayable=False)
    assert not_ok.attempts == 1                        # may have been applied


async def test_non_transient_status_never_retries():
    """A 400 will not get better by asking again — even replayable
    requests fail immediately."""
    script = _Script(400, 200)
    with pytest.raises(httpx.HTTPStatusError):
        await _get(script, replayable=True)
    assert script.attempts == 1


async def test_mid_request_failure_retries_only_when_replayable():
    """A read timeout is ambiguous — the server may have processed the
    request — so only replayable call sites try again."""
    ok = _Script(httpx.ReadTimeout("slow"), 200)
    resp = await _get(ok, replayable=True)
    assert resp.status_code == 200
    assert ok.attempts == 2

    not_ok = _Script(httpx.ReadTimeout("slow"), 200)
    with pytest.raises(httpx.ReadTimeout):
        await _get(not_ok, replayable=False)
    assert not_ok.attempts == 1


async def test_final_failure_raises_the_status_error():
    script = _Script(503, 503)
    with pytest.raises(httpx.HTTPStatusError) as exc:
        await _get(script, replayable=True)
    assert exc.value.response.status_code == 503
    assert script.attempts == 2

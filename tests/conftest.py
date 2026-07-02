"""Shared pytest configuration and fixtures for the SOC copilot eval harness."""
import inspect

import pytest
import pytest_asyncio

from src.copilot import SOCCopilot
from src.history import AlertHistoryStore


def pytest_collection_modifyitems(config, items):
    """Auto-apply the asyncio marker to coroutine tests only.

    The eval harness tests are async; the history unit tests are plain sync
    functions. Marking sync tests as asyncio is a no-op that pytest-asyncio
    warns about, so guard on the function actually being a coroutine.
    """
    for item in items:
        func = getattr(item, "obj", None)
        if inspect.iscoroutinefunction(func) and "asyncio" not in item.keywords:
            item.add_marker(pytest.mark.asyncio)


@pytest_asyncio.fixture(scope="session")
async def copilot(tmp_path_factory) -> SOCCopilot:
    """A single copilot instance shared across all tests in a session.

    Scope is 'session' so we only instantiate the Anthropic client once.
    Each test still makes its own API call — the fixture just avoids
    creating a new client per test.

    The history store points at an isolated temp file so the eval harness
    never touches (or is influenced by) the real case history. The sample
    alerts have distinct IOCs, so prior_sightings stays empty and the
    existing invariants remain deterministic.
    """
    store = AlertHistoryStore(
        tmp_path_factory.mktemp("history") / "investigations.jsonl"
    )
    return SOCCopilot(history_store=store)
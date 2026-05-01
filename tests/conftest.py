"""Shared pytest configuration and fixtures for the SOC copilot eval harness."""
import pytest
import pytest_asyncio

from src.copilot import SOCCopilot


def pytest_collection_modifyitems(config, items):
    """Apply asyncio marker to all test functions automatically."""
    for item in items:
        if "asyncio" not in item.keywords:
            item.add_marker(pytest.mark.asyncio)


@pytest_asyncio.fixture(scope="session")
async def copilot() -> SOCCopilot:
    """A single copilot instance shared across all tests in a session.

    Scope is 'session' so we only instantiate the Anthropic client once.
    Each test still makes its own API call — the fixture just avoids
    creating a new client per test.
    """
    return SOCCopilot()
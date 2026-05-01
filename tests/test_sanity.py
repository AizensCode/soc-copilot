"""Sanity check — pytest infrastructure works."""
import pytest


async def test_pytest_runs():
    assert 1 + 1 == 2


async def test_copilot_fixture_loads(copilot):
    assert copilot is not None
    assert copilot.ip_tool is not None
    assert copilot.hash_tool is not None
"""Unit tests for the tool registry's dispatch guardrails (API-free).

The model occasionally emits malformed tool_use blocks (an unknown name,
or an empty input dict — observed live on claude-sonnet-5). dispatch must
convert every such failure into a failed ToolResult so the agentic loop
can feed it back as an is_error tool_result instead of crashing the
investigation. All cases here fail before any network call is made.

    uv run pytest tests/test_tools.py -v
"""
from soc_copilot.tools.base import Tool, ToolResult
from soc_copilot.tools.registry import (
    all_tools,
    anthropic_tool_schemas,
    default_registry,
    dispatch,
)


async def test_unknown_tool_returns_failed_result():
    result = await dispatch("no_such_tool", {"ip": "192.0.2.1"})
    assert result.success is False
    assert "Unknown tool" in result.error


async def test_empty_input_returns_failed_result_not_typeerror():
    # The live failure mode: model emits check_ip_reputation with {}
    result = await dispatch("check_ip_reputation", {})
    assert result.success is False
    assert "Invalid arguments" in result.error
    assert "ip" in result.error  # tells the model what's missing


async def test_unexpected_keyword_returns_failed_result():
    result = await dispatch("check_ip_reputation", {"address": "192.0.2.1"})
    assert result.success is False
    assert "Invalid arguments" in result.error


def test_every_registered_tool_has_a_schema():
    schemas = anthropic_tool_schemas()
    assert len(schemas) == len(all_tools())
    for schema in schemas:
        assert schema["name"] and schema["input_schema"]


# --- substitution: which tools exist is an input, not a constant ------------


class _Stub(Tool):
    name = "search_internal_logs"
    description = "stub"
    input_schema = {"type": "object", "properties": {}}

    async def execute(self, **kwargs) -> ToolResult:
        return ToolResult(tool_name=self.name, success=True, data={"stub": True})


def test_without_drops_a_tool_from_the_schemas_the_model_sees():
    trimmed = default_registry().without("search_internal_logs")
    names = [s["name"] for s in trimmed.anthropic_schemas()]
    assert "search_internal_logs" not in names
    assert "check_ip_reputation" in names


async def test_replacing_swaps_the_implementation_but_keeps_the_count():
    swapped = default_registry().replacing(_Stub())
    assert len(swapped.all()) == len(default_registry().all())
    result = await swapped.dispatch("search_internal_logs", {})
    assert result.data == {"stub": True}


def test_replacing_substitutes_in_place_never_reordering_the_schemas():
    """The schema list is part of the prompt the model reads; substituting
    a tool's backend must not also move it."""
    names = lambda r: [s["name"] for s in r.anthropic_schemas()]  # noqa: E731
    assert names(default_registry().replacing(_Stub())) == names(default_registry())


def test_without_an_unknown_name_raises_instead_of_failing_open():
    """The harness quarantines search_internal_logs by name; a rename that
    made this a silent no-op would un-quarantine the SIEM without a red
    test, so an unknown name is an error."""
    import pytest

    with pytest.raises(ValueError, match="no_such_tool"):
        default_registry().without("no_such_tool")


async def test_substitution_never_mutates_the_default_registry():
    """One caller's controlled backend must not leak into another's — the
    eval harness and a production run share this process in --watch."""
    before = [t.name for t in default_registry().all()]
    default_registry().without("search_internal_logs").replacing(_Stub())
    assert [t.name for t in default_registry().all()] == before
    real = default_registry().get("search_internal_logs")
    assert not isinstance(real, _Stub)

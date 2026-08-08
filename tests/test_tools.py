"""Unit tests for the tool registry's dispatch guardrails (API-free).

The model occasionally emits malformed tool_use blocks (an unknown name,
or an empty input dict — observed live on claude-sonnet-5). dispatch must
convert every such failure into a failed ToolResult so the agentic loop
can feed it back as an is_error tool_result instead of crashing the
investigation. All cases here fail before any network call is made.

    uv run pytest tests/test_tools.py -v
"""
from soc_copilot.tools.registry import all_tools, anthropic_tool_schemas, dispatch


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

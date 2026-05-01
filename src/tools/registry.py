"""Tool registry — single source of truth for which tools the agent can use."""
from .abuseipdb import AbuseIPDBTool
from .base import Tool, ToolResult
from .virustotal import VirusTotalTool


# Instantiate once. These are stateless, so a single instance is fine.
_TOOLS: list[Tool] = [
    AbuseIPDBTool(),
    VirusTotalTool(),
]


# Lookup by name for fast dispatch in the agentic loop
_TOOLS_BY_NAME: dict[str, Tool] = {t.name: t for t in _TOOLS}


def all_tools() -> list[Tool]:
    """Return all registered tools (for iteration)."""
    return _TOOLS


def get_tool(name: str) -> Tool | None:
    """Look up a tool by its `name` attribute."""
    return _TOOLS_BY_NAME.get(name)


def anthropic_tool_schemas() -> list[dict]:
    """Return tool schemas in the format Anthropic's API expects.

    Pass this directly to client.messages.create(tools=...).
    """
    return [t.__class__.to_anthropic_schema() for t in _TOOLS]


async def dispatch(tool_name: str, tool_input: dict) -> ToolResult:
    """Execute a tool by name with the given input dict.

    The agentic loop calls this when the model emits a tool_use block.
    """
    tool = get_tool(tool_name)
    if tool is None:
        return ToolResult(
            tool_name=tool_name,
            success=False,
            data={},
            error=f"Unknown tool: {tool_name}",
        )
    return await tool.execute(**tool_input)
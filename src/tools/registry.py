"""Tool registry — single source of truth for which tools the agent can use."""
from .abuseipdb import AbuseIPDBTool
from .base import Tool, ToolResult
from .threat_actor import ThreatActorTool
from .urlscan import URLScanTool
from .virustotal import VirusTotalTool

# Instantiate once. These are stateless, so a single instance is fine.
_TOOLS: list[Tool] = [
    AbuseIPDBTool(),
    VirusTotalTool(),
    URLScanTool(),
    ThreatActorTool(),
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
    Any failure — unknown tool, malformed arguments (the model does
    occasionally emit an empty input dict), or an exception inside the
    tool — comes back as a failed ToolResult, which the loop returns to
    the model as an is_error tool_result so it can correct itself. A bad
    tool call must never crash the investigation.
    """
    tool = get_tool(tool_name)
    if tool is None:
        return ToolResult(
            tool_name=tool_name,
            success=False,
            data={},
            error=f"Unknown tool: {tool_name}",
        )
    try:
        return await tool.execute(**tool_input)
    except TypeError as e:
        return ToolResult(
            tool_name=tool_name,
            success=False,
            data={},
            error=(
                f"Invalid arguments for {tool_name}: {e}. "
                f"Got input keys: {sorted(tool_input)}. Re-issue the call "
                f"with the arguments the tool schema requires."
            ),
        )
    except Exception as e:
        return ToolResult(
            tool_name=tool_name,
            success=False,
            data={},
            error=f"{tool_name} raised {type(e).__name__}: {e}",
        )

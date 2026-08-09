"""Tool registry — which tools the agent can use, as an injectable object.

The default registry is the production set. It is a `ToolRegistry` value
rather than a module-level list because *which tools exist* is part of an
investigation's inputs: swap the internal-log-search backend and the same
alert can reach a different (correct) verdict. Tests that need controlled
ground truth — and deployments with a different log backend — construct a
registry instead of monkeypatching this module.

`without()` and `replacing()` return NEW registries; the default is never
mutated, so one caller's substitution can't leak into another's.
"""
from .abuseipdb import AbuseIPDBTool
from .base import Tool, ToolResult
from .logsearch import SearchLogsTool
from .threat_actor import ThreatActorTool
from .urlscan import URLScanTool
from .virustotal import VirusTotalTool


class ToolRegistry:
    """An immutable set of tools, addressable by name."""

    def __init__(self, tools: list[Tool]) -> None:
        self._tools = list(tools)
        self._by_name = {t.name: t for t in self._tools}

    def all(self) -> list[Tool]:
        return list(self._tools)

    def get(self, name: str) -> Tool | None:
        return self._by_name.get(name)

    def anthropic_schemas(self) -> list[dict]:
        """Tool schemas in the format Anthropic's API expects.

        Pass directly to client.messages.create(tools=...).
        """
        return [t.__class__.to_anthropic_schema() for t in self._tools]

    def without(self, *names: str) -> "ToolRegistry":
        """A copy with the named tools removed — e.g. an eval harness that
        pins 'this deployment has no internal telemetry'.

        An unknown name raises rather than failing open: the harness uses
        this as a quarantine, and a rename that silently un-quarantined a
        tool would poison expectations without a single red test."""
        unknown = [n for n in names if n not in self._by_name]
        if unknown:
            raise ValueError(f"no such tool(s) to remove: {unknown}")
        return ToolRegistry([t for t in self._tools if t.name not in names])

    def replacing(self, *tools: Tool) -> "ToolRegistry":
        """A copy with each tool substituted IN PLACE for the registered
        one of the same name (unknown names appended) — e.g. a log-search
        tool bound to a controlled backend. Position is preserved so a
        substitution never reorders the schema list the model reads."""
        by_name = {t.name: t for t in tools}
        swapped = [by_name.pop(t.name, t) for t in self._tools]
        return ToolRegistry(swapped + list(by_name.values()))

    async def dispatch(self, tool_name: str, tool_input: dict) -> ToolResult:
        """Execute a tool by name with the given input dict.

        The agentic loop calls this when the model emits a tool_use block.
        Any failure — unknown tool, malformed arguments (the model does
        occasionally emit an empty input dict), or an exception inside the
        tool — comes back as a failed ToolResult, which the loop returns to
        the model as an is_error tool_result so it can correct itself. A bad
        tool call must never crash the investigation.
        """
        tool = self.get(tool_name)
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


# The production set. Tools are stateless, so a single instance each is fine.
DEFAULT_REGISTRY = ToolRegistry(
    [
        AbuseIPDBTool(),
        VirusTotalTool(),
        URLScanTool(),
        ThreatActorTool(),
        SearchLogsTool(),
    ]
)


def default_registry() -> ToolRegistry:
    """The production tool set, used when no registry is injected."""
    return DEFAULT_REGISTRY


# --- module-level conveniences over the default registry ---------------------


def all_tools() -> list[Tool]:
    return DEFAULT_REGISTRY.all()


def get_tool(name: str) -> Tool | None:
    return DEFAULT_REGISTRY.get(name)


def anthropic_tool_schemas() -> list[dict]:
    return DEFAULT_REGISTRY.anthropic_schemas()


async def dispatch(tool_name: str, tool_input: dict) -> ToolResult:
    return await DEFAULT_REGISTRY.dispatch(tool_name, tool_input)

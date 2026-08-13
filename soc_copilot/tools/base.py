"""Abstract base class for all investigation tools."""
from abc import ABC, abstractmethod

from pydantic import BaseModel


class ToolResult(BaseModel):
    tool_name: str
    success: bool
    data: dict
    error: str | None = None
    # True when the call never reached a tool because the MODEL framed it
    # wrong (a name that does not exist, arguments that do not fit the
    # schema). The agentic loop hands these back so the model can correct
    # itself, and it routinely does — so they are not blind spots in the
    # evidence base the way a tool that ran and failed is, and the
    # autonomy gates must not treat them as such.
    model_error: bool = False


class Tool(ABC):
    """All tools implement this interface.

    The class-level attributes (name, description, input_schema) are what
    the LLM sees when deciding which tool to call. Write the description
    carefully — it's effectively a prompt.
    """

    name: str
    description: str
    input_schema: dict

    @abstractmethod
    async def execute(self, **kwargs) -> ToolResult:
        """Run the tool and return a structured result."""
        raise NotImplementedError

    @classmethod
    def to_anthropic_schema(cls) -> dict:
        """Render this tool in the format Anthropic's tool use API expects."""
        return {
            "name": cls.name,
            "description": cls.description,
            "input_schema": cls.input_schema,
        }

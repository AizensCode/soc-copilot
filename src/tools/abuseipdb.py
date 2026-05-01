"""AbuseIPDB reputation lookup."""
import httpx

from ..config import settings
from .base import Tool, ToolResult


class AbuseIPDBTool(Tool):
    name = "check_ip_reputation"
    description = (
        "Check an IPv4 or IPv6 address against AbuseIPDB for reported abuse "
        "over the past 90 days. Returns an abuse confidence score (0-100), "
        "the number of distinct reporters, recent report categories, and the "
        "IP's country and ISP. Use this whenever an alert contains a public "
        "source or destination IP that needs reputation context."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "ip": {
                "type": "string",
                "description": "IPv4 or IPv6 address to check",
            }
        },
        "required": ["ip"],
    }

    async def execute(self, ip: str) -> ToolResult:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                    headers={
                        "Key": settings.ABUSEIPDB_KEY,
                        "Accept": "application/json",
                    },
                )
                response.raise_for_status()
                return ToolResult(
                    tool_name=self.name,
                    success=True,
                    data=response.json().get("data", {}),
                )
        except httpx.HTTPStatusError as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                data={},
                error=f"HTTP {e.response.status_code}: {e.response.text[:200]}",
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                data={},
                error=str(e),
            )
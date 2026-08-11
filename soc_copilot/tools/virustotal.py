"""VirusTotal file hash lookup."""
import httpx

from ..config import settings
from .base import Tool, ToolResult


class VirusTotalTool(Tool):
    name = "check_file_hash"
    description = (
        "Look up a file hash (MD5, SHA1, or SHA256) in VirusTotal. Returns "
        "the number of antivirus engines that flagged the file as malicious, "
        "the detected malware family names, file metadata (type, size, first "
        "submission date), and common names the file has been seen under. "
        "Use this whenever an alert contains a file hash that needs "
        "reputation or classification context."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "file_hash": {
                "type": "string",
                "description": "MD5, SHA1, or SHA256 hash of the file",
            }
        },
        "required": ["file_hash"],
    }

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        # Injected client → the eval harness replays a recorded response
        # (tests/cassette.py); None → production builds its own per call.
        # The 404-and total==0 parsing below runs on the injected response
        # too, so a regression in that branch is still caught in replay.
        self._client = client

    async def execute(self, file_hash: str) -> ToolResult:
        try:
            async def do(client: httpx.AsyncClient) -> httpx.Response:
                return await client.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers={
                        # "" not None so a missing key still builds a valid
                        # request (httpx rejects a None header): replay is
                        # keyless, a real missing key just 404s/401s.
                        "x-apikey": settings.VIRUSTOTAL_KEY or "",
                        "Accept": "application/json",
                    },
                )

            if self._client is not None:
                response = await do(self._client)
            else:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    response = await do(client)

            if response.status_code == 404:
                return ToolResult(
                    tool_name=self.name,
                    success=True,
                    data={"found": False, "hash": file_hash},
                )

            response.raise_for_status()
            attrs = response.json().get("data", {}).get("attributes", {})

            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})

            # Extract the malware family names that engines detected
            detections = [
                {"engine": name, "result": info.get("result")}
                for name, info in results.items()
                if info.get("category") == "malicious" and info.get("result")
            ]

            return ToolResult(
                tool_name=self.name,
                success=True,
                data={
                    "found": True,
                    "hash": file_hash,
                    "malicious_count": stats.get("malicious", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                    "undetected_count": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "file_type": attrs.get("type_description"),
                    "file_size": attrs.get("size"),
                    "first_seen": attrs.get("first_submission_date"),
                    "last_seen": attrs.get("last_analysis_date"),
                    "common_names": attrs.get("names", [])[:10],
                    "reputation": attrs.get("reputation"),
                    "detections": detections[:15],  # Top 15 to keep context manageable
                },
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

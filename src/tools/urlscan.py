"""URLScan domain reputation lookup.

Uses URLScan's search API to find historical scans of a domain.
Returns aggregated verdicts across all known scans of that domain
(malicious score, related URLs, page metadata).

Search is preferred over submitting fresh scans because it's:
- Fast (no waiting for the scan to complete)
- Doesn't consume the daily scan quota
- Most malicious domains are already scanned by someone in the community
"""
import httpx

from ..config import settings
from .base import Tool, ToolResult


class URLScanTool(Tool):
    name = "check_domain_reputation"
    description = (
        "Check a domain or hostname against URLScan.io's database of past "
        "scans. Returns the count of historical scans, how many were flagged "
        "as malicious, the most recent verdict, related URLs and pages "
        "served on the domain, and metadata like the page title and favicon. "
        "Use this whenever an alert contains a domain that needs reputation "
        "context — typosquats, suspicious sender domains, possible C2 "
        "infrastructure, or unfamiliar URLs in user clicks."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": (
                    "Domain or hostname to look up (e.g. 'example.com'). "
                    "Do not include protocol or paths."
                ),
            }
        },
        "required": ["domain"],
    }

    async def execute(self, domain: str) -> ToolResult:
        # Normalize: strip protocol and trailing slashes if present
        domain = domain.replace("http://", "").replace("https://", "").rstrip("/")

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    "https://urlscan.io/api/v1/search/",
                    params={
                        "q": f"domain:{domain}",
                        "size": 20,  # Get last 20 scans of this domain
                    },
                    headers={
                        "API-Key": settings.URLSCAN_KEY,
                        "Accept": "application/json",
                    },
                )
                response.raise_for_status()
                data = response.json()

                results = data.get("results", [])
                total = data.get("total", 0)

                if total == 0:
                    return ToolResult(
                        tool_name=self.name,
                        success=True,
                        data={
                            "found": False,
                            "domain": domain,
                            "summary": (
                                f"Domain '{domain}' has no historical scans "
                                f"in URLScan. Either very new, very obscure, "
                                f"or never publicly browsed."
                            ),
                        },
                    )

                # Aggregate verdicts across all returned scans
                malicious_count = sum(
                    1 for r in results
                    if r.get("verdicts", {}).get("overall", {}).get("malicious")
                )

                # Pull useful metadata from the most recent scan
                most_recent = results[0] if results else {}
                page_info = most_recent.get("page", {})
                task_info = most_recent.get("task", {})

                # Surface a few related URLs that have been seen on this domain
                seen_urls = list({
                    r.get("page", {}).get("url")
                    for r in results[:10]
                    if r.get("page", {}).get("url")
                })[:5]

                return ToolResult(
                    tool_name=self.name,
                    success=True,
                    data={
                        "found": True,
                        "domain": domain,
                        "total_scans": total,
                        "scans_returned": len(results),
                        "malicious_scan_count": malicious_count,
                        "most_recent_scan_date": task_info.get("time"),
                        "most_recent_url": task_info.get("url"),
                        "most_recent_country": page_info.get("country"),
                        "most_recent_server": page_info.get("server"),
                        "most_recent_page_title": page_info.get("title"),
                        "seen_urls": seen_urls,
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
"""SOC Copilot — phase one (fixed pipeline) and phase two (agentic loop)."""
import json

from anthropic import AsyncAnthropic

from .config import settings
from .history import AlertHistoryStore
from .mitre_groups import match_groups
from .models import Alert, Evidence, Investigation, PriorSighting
from .prompts.agentic import AGENTIC_SYSTEM_PROMPT
from .prompts.system import SYSTEM_PROMPT
from .tools.abuseipdb import AbuseIPDBTool
from .tools.base import ToolResult
from .tools.registry import anthropic_tool_schemas, dispatch
from .tools.urlscan import URLScanTool
from .tools.virustotal import VirusTotalTool


class SOCCopilot:
    def __init__(self, history_store: AlertHistoryStore | None = None) -> None:
        self.client = AsyncAnthropic(api_key=settings.ANTHROPIC_KEY)
        self.ip_tool = AbuseIPDBTool()
        self.hash_tool = VirusTotalTool()
        self.domain_tool = URLScanTool()
        # Cross-alert memory. Injectable so tests can isolate it.
        self.history = history_store or AlertHistoryStore(settings.HISTORY_PATH)

    @staticmethod
    def _format_priors(priors: list[PriorSighting]) -> str:
        """Render prior sightings as a prompt context block.

        Returns "" when there are none, so an empty history leaves the prompt
        byte-for-byte unchanged (keeps investigations deterministic).
        """
        if not priors:
            return ""
        lines = [
            "# Prior investigation history (from the copilot's own case store)",
            "These past investigations share one or more indicators with this "
            "alert. Treat as grounded context — weigh it in your hypothesis, "
            "confidence, and escalation call:",
        ]
        for p in priors:
            lines.append(
                f"- {p.alert_id} ({p.timestamp:%Y-%m-%d}, verdict={p.verdict}, "
                f"confidence={p.confidence}): \"{p.title}\" "
                f"— shared indicators: {', '.join(p.matched_iocs)}"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Phase 1: fixed enrichment pipeline
    # ------------------------------------------------------------------

    async def enrich(self, alert: Alert) -> list[Evidence]:
        """Run fixed enrichment on all indicators in the alert."""
        evidence: list[Evidence] = []

        # Route IPs to AbuseIPDB
        for ip in alert.indicators.get("ips", []):
            result = await self.ip_tool.execute(ip=ip)
            evidence.append(self._ip_result_to_evidence(result, ip))

        # Route hashes to VirusTotal
        for file_hash in alert.indicators.get("hashes", []):
            result = await self.hash_tool.execute(file_hash=file_hash)
            evidence.append(self._hash_result_to_evidence(result, file_hash))

        # Route domains to URLScan
        for domain in alert.indicators.get("domains", []):
            result = await self.domain_tool.execute(domain=domain)
            evidence.append(self._domain_result_to_evidence(result, domain))

        return evidence

    def _ip_result_to_evidence(self, result: ToolResult, ip: str) -> Evidence:
        if not result.success:
            return Evidence(
                source_tool=result.tool_name,
                claim=f"Failed to retrieve reputation for {ip}: {result.error}",
                raw_data={"error": result.error},
                confidence="low",
            )

        score = result.data.get("abuseConfidenceScore", 0)
        country = result.data.get("country", "??")
        total_reports = result.data.get("totalReports", 0)
        usage_type = result.data.get("usageType", "unknown")

        if score >= 75:
            confidence = "high"
        elif score >= 25:
            confidence = "medium"
        else:
            confidence = "low"

        return Evidence(
            source_tool=result.tool_name,
            claim=(
                f"IP {ip} has abuse confidence {score}/100 "
                f"({total_reports} reports, country={country}, "
                f"usage={usage_type})"
            ),
            raw_data=result.data,
            confidence=confidence,
        )

    def _hash_result_to_evidence(
        self, result: ToolResult, file_hash: str
    ) -> Evidence:
        if not result.success:
            return Evidence(
                source_tool=result.tool_name,
                claim=f"Failed to look up hash {file_hash}: {result.error}",
                raw_data={"error": result.error},
                confidence="low",
            )

        if not result.data.get("found"):
            return Evidence(
                source_tool=result.tool_name,
                claim=f"Hash {file_hash} is not known to VirusTotal (no submissions)",
                raw_data=result.data,
                confidence="low",
            )

        mal = result.data.get("malicious_count", 0)
        total = result.data.get("total_engines", 0)
        ratio = mal / total if total else 0

        if ratio >= 0.5:
            confidence = "high"
        elif ratio >= 0.1:
            confidence = "medium"
        else:
            confidence = "low"

        return Evidence(
            source_tool=result.tool_name,
            claim=(
                f"Hash {file_hash} flagged malicious by {mal}/{total} engines; "
                f"file type: {result.data.get('file_type', 'unknown')}; "
                f"common names: {result.data.get('common_names', [])[:3]}"
            ),
            raw_data=result.data,
            confidence=confidence,
        )

    def _domain_result_to_evidence(
        self, result: ToolResult, domain: str
    ) -> Evidence:
        if not result.success:
            return Evidence(
                source_tool=result.tool_name,
                claim=f"Failed to check domain reputation for {domain}: {result.error}",
                raw_data={"error": result.error},
                confidence="low",
            )

        # No historical scans is ambiguous, not exculpatory: it fits a
        # newly-registered / not-yet-catalogued domain (possible fresh
        # attacker infrastructure) as much as an obscure-but-benign one.
        # Surface the ambiguity in the claim; let the LLM weigh it against
        # the rest of the alert rather than deciding here.
        if not result.data.get("found"):
            return Evidence(
                source_tool=result.tool_name,
                claim=(
                    f"Domain {domain} has no historical scans in URLScan — "
                    f"consistent with a newly-registered or not-yet-catalogued "
                    f"domain (possible fresh attacker infrastructure) or simply "
                    f"an obscure domain. Absence of scans is not evidence of safety."
                ),
                raw_data=result.data,
                confidence="medium",
            )

        malicious = result.data.get("malicious_scan_count", 0)
        total_scans = result.data.get("total_scans", 0)

        if malicious > 0:
            confidence = "high"
        else:
            confidence = "low"

        return Evidence(
            source_tool=result.tool_name,
            claim=(
                f"Domain {domain} has {total_scans} historical URLScan scans, "
                f"{malicious} flagged malicious; "
                f"most recent page title: {result.data.get('most_recent_page_title')!r}; "
                f"seen URLs: {result.data.get('seen_urls', [])[:3]}"
            ),
            raw_data=result.data,
            confidence=confidence,
        )

    async def investigate(self, alert: Alert) -> Investigation:
        """Phase 1 entrypoint: pre-enrich, then one LLM call to write the report."""
        evidence = await self.enrich(alert)
        priors = self.history.prior_sightings(alert)

        priors_block = self._format_priors(priors)
        priors_section = f"{priors_block}\n\n" if priors_block else ""
        user_message = (
            f"# Alert\n```json\n{alert.model_dump_json(indent=2)}\n```\n\n"
            f"# Enrichment evidence collected\n"
            f"```json\n{json.dumps([e.model_dump() for e in evidence], indent=2)}\n```\n\n"
            f"{priors_section}"
            f"Produce the final Investigation JSON now."
        )

        response = await self.client.messages.create(
            model=settings.MODEL,
            max_tokens=8192,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )

        if response.stop_reason == "max_tokens":
            raise RuntimeError(
                f"Model hit max_tokens ceiling "
                f"({response.usage.output_tokens} tokens generated). "
                f"Response was truncated and JSON is incomplete."
            )

        report_text = response.content[0].text
        report_json = self._extract_json(report_text)

        investigation = Investigation(**report_json, evidence=evidence)
        investigation.associated_groups = match_groups(
            investigation.attack_techniques
        )
        investigation.prior_sightings = priors
        self.history.record(alert, investigation)
        return investigation

    # ------------------------------------------------------------------
    # Phase 2: agentic investigation
    # ------------------------------------------------------------------

    async def investigate_agentic(
        self,
        alert: Alert,
        max_iterations: int = 15,
    ) -> Investigation:
        """Phase 2 entrypoint: model decides which tools to call.

        Loops until the model emits a final Investigation JSON
        (stop_reason='end_turn') or until max_iterations is reached
        as a safety stop against runaway loops.
        """
        priors = self.history.prior_sightings(alert)
        priors_block = self._format_priors(priors)
        priors_section = f"\n\n{priors_block}" if priors_block else ""
        messages: list[dict] = [
            {
                "role": "user",
                "content": (
                    f"Investigate this alert. Call tools as needed to gather "
                    f"evidence, then produce the final Investigation JSON.\n\n"
                    f"```json\n{alert.model_dump_json(indent=2)}\n```"
                    f"{priors_section}"
                ),
            }
        ]

        tool_schemas = anthropic_tool_schemas()
        evidence_collected: list[Evidence] = []

        for iteration in range(max_iterations):
            response = await self.client.messages.create(
                model=settings.MODEL,
                max_tokens=8192,
                system=AGENTIC_SYSTEM_PROMPT,
                tools=tool_schemas,
                messages=messages,
            )

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                investigation = self._parse_agentic_final(
                    response, evidence_collected
                )
                investigation.prior_sightings = priors
                self.history.record(alert, investigation)
                return investigation

            if response.stop_reason == "max_tokens":
                raise RuntimeError(
                    f"Model hit max_tokens at iteration {iteration}. "
                    f"Output was truncated."
                )

            if response.stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type != "tool_use":
                        continue

                    result = await dispatch(block.name, block.input)
                    evidence_collected.append(
                        self._tool_result_to_evidence(result)
                    )

                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps(result.data)[:6000],
                            "is_error": not result.success,
                        }
                    )

                messages.append({"role": "user", "content": tool_results})
                continue

            raise RuntimeError(
                f"Unexpected stop_reason '{response.stop_reason}' at "
                f"iteration {iteration}"
            )

        raise RuntimeError(
            f"Investigation exceeded {max_iterations} iterations without "
            f"concluding. The model may be stuck in a loop."
        )

    def _parse_agentic_final(
        self,
        response,
        evidence_collected: list[Evidence],
    ) -> Investigation:
        """Extract the final Investigation JSON from the model's last turn."""
        text_blocks = [b.text for b in response.content if b.type == "text"]
        if not text_blocks:
            raise RuntimeError("Final agent turn had no text content")

        final_text = text_blocks[-1]

        # DEBUG: write the final turn text so we can inspect it on failure
        from pathlib import Path
        Path("last_agentic_final_turn.txt").write_text(final_text)

        report_json = self._extract_json(final_text)
        investigation = Investigation(**report_json, evidence=evidence_collected)
        investigation.associated_groups = match_groups(
            investigation.attack_techniques
        )
        return investigation

    def _tool_result_to_evidence(self, result: ToolResult) -> Evidence:
        """Convert a ToolResult into an Evidence entry.

        Used by the agentic loop. Unlike phase one's typed converters,
        this is generic — the agent works with whatever tools call back.
        """
        if not result.success:
            return Evidence(
                source_tool=result.tool_name,
                claim=f"Tool {result.tool_name} failed: {result.error}",
                raw_data={"error": result.error},
                confidence="low",
            )

        return Evidence(
            source_tool=result.tool_name,
            claim=f"Result from {result.tool_name} (see raw_data)",
            raw_data=result.data,
            confidence="medium",
        )

    # ------------------------------------------------------------------
    # Shared utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_json(text: str) -> dict:
        """Extract a JSON object from arbitrary text.

        Handles:
        1. Pure JSON (phase one's typical output)
        2. JSON wrapped in ```json ... ``` markdown fences
        3. JSON embedded in prose, possibly with OTHER json-shaped
        fragments quoted earlier in the text (agentic mode)

        Strategy: try direct parse first. If that fails, find the LAST
        balanced top-level JSON object in the text — the model's final
        answer comes after any reasoning prose, and reasoning prose may
        quote alert fragments that look like JSON.
        """
        cleaned = text.strip()

        if not cleaned:
            raise ValueError("Cannot extract JSON from empty text")

        # Strip markdown fences if present
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            if lines[-1].startswith("```"):
                cleaned = "\n".join(lines[1:-1])
            else:
                cleaned = "\n".join(lines[1:])
            cleaned = cleaned.strip()

        # Fast path: the whole thing is clean JSON
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Find ALL balanced top-level JSON objects in the text, return the last.
        candidates = []
        depth = 0
        in_string = False
        escape_next = False
        start_idx = None

        for i, char in enumerate(cleaned):
            if escape_next:
                escape_next = False
                continue
            if char == "\\":
                escape_next = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if in_string:
                continue

            if char == "{":
                if depth == 0:
                    start_idx = i
                depth += 1
            elif char == "}":
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start_idx is not None:
                        candidates.append(cleaned[start_idx : i + 1])
                        start_idx = None

        if not candidates:
            raise ValueError(
                f"No JSON object found in text. First 500 chars: {cleaned[:500]}"
            )

        # Try candidates from last to first — the real Investigation is the
        # final top-level object; earlier ones may be quoted alert fragments.
        for candidate in reversed(candidates):
            try:
                parsed = json.loads(candidate)
                # Sanity check: the Investigation must have an alert_id.
                # If this candidate doesn't, it's probably a quoted fragment;
                # keep looking.
                if isinstance(parsed, dict) and "alert_id" in parsed:
                    return parsed
            except json.JSONDecodeError:
                continue

        # Fallback: if no candidate had alert_id, return the last parseable one
        # and let Pydantic produce a clear error.
        for candidate in reversed(candidates):
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue

        raise ValueError(
            f"Found {len(candidates)} JSON-like objects but none parsed. "
            f"First 500 chars: {cleaned[:500]}"
        )
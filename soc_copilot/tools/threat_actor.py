"""Threat-actor context from MITRE ATT&CK Groups.

Unlike the IOC tools, this one operates on the investigation's *output* — the
observed technique IDs — rather than on an alert indicator. Given a technique
list, it returns known groups whose documented TTPs overlap, ranked by overlap.

Local lookup only (no network, no API key). Every group name traces back to the
official MITRE ATT&CK data, so this adds attribution CONTEXT without letting the
model invent threat-actor names.
"""
from ..mitre_groups import match_groups
from .base import Tool, ToolResult


class ThreatActorTool(Tool):
    name = "lookup_threat_actors"
    description = (
        "Given a list of observed MITRE ATT&CK technique IDs, return known "
        "threat groups (from MITRE ATT&CK) whose documented TTPs overlap, "
        "ranked by how many of the observed techniques each group uses. Call "
        "this AFTER you have formed your technique mapping, to add threat-intel "
        "context to your hypothesis and escalation reasoning. This tool takes "
        "techniques, not an indicator — do not call it before you have a "
        "technique hypothesis. IMPORTANT: technique overlap is suggestive "
        "context, NOT attribution. A match does not mean a specific group is "
        "responsible; use it to note that the observed TTPs are consistent "
        "with known tradecraft."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "techniques": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Observed MITRE ATT&CK technique IDs, e.g. "
                    "['T1566.001', 'T1204.002']. Sub-techniques also match "
                    "groups documented for the parent technique."
                ),
            }
        },
        "required": ["techniques"],
    }

    async def execute(self, techniques: list[str]) -> ToolResult:
        matches = match_groups(techniques)

        if not matches:
            return ToolResult(
                tool_name=self.name,
                success=True,
                data={
                    "input_techniques": techniques,
                    "groups": [],
                    "summary": (
                        "No MITRE ATT&CK groups have documented overlap with "
                        "these techniques. Absence of overlap is not "
                        "exculpatory — it may just be a common or generic TTP."
                    ),
                },
            )

        top = matches[0]
        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "input_techniques": techniques,
                "groups": [m.model_dump() for m in matches],
                "summary": (
                    f"{len(matches)} groups overlap these techniques; strongest "
                    f"is {top.group} ({top.overlap_count} of the observed "
                    f"techniques). Overlap is suggestive context, not attribution."
                ),
            },
        )

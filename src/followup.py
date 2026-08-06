"""Follow-up mode — interrogate a recorded investigation.

The copilot's verdicts were write-only: it handed the analyst a report
and could not be questioned about it. This module makes a recorded
investigation interrogable — "why did you call this a false positive?",
"what did AbuseIPDB actually say?", "did anything else touch this
host?" — grounded strictly in what the record contains.

Grounding is by construction, like everywhere else in this project: the
context handed to the model is the stored record itself (the alert as
investigated, the full investigation dump, the analyst's current ruling),
assembled deterministically by build_grounding(). No new tool calls
happen in follow-up mode; the model can cite the record or say the
record doesn't answer — it has nothing else to draw on.
"""
import json

from anthropic import AsyncAnthropic

from .config import settings
from .history import AlertHistoryStore
from .injection import scan_for_injection
from .models import Alert
from .prompts.followup import FOLLOWUP_SYSTEM_PROMPT

# Follow-up answers are short prose, but adaptive thinking spends output
# tokens before the text block — budget well above the visible answer.
MAX_ANSWER_TOKENS = 8000


def _format_ruling(record: dict) -> str:
    """Render the analyst's current ruling on THIS alert, loudly, or its
    explicit absence. Unlike investigation prompts (inert-when-absent to
    keep them deterministic), follow-up context states the absence: "has
    anyone ruled on this?" deserves a grounded no, not a guess."""
    ruling = record.get("ruling")
    if not ruling:
        return (
            "# Analyst ruling\n"
            "No analyst ruling recorded for this investigation."
        )
    agreement = (
        "confirming" if ruling["human_verdict"] == record["verdict"]
        else "OVERTURNING"
    )
    lines = [
        "# Analyst ruling",
        f"ANALYST RULED: {ruling['human_verdict']} "
        f"({agreement} the copilot's {record['verdict']}) "
        f"[{ruling.get('source', '?')}]",
    ]
    if ruling.get("summary"):
        lines.append(f'Analyst note: "{ruling["summary"]}"')
    return "\n".join(lines)


def build_grounding(store: AlertHistoryStore, alert_id: str) -> str | None:
    """Assemble the follow-up context for an investigated alert.

    Returns None when the store has no record of the alert. Records
    written before full-report storage existed get a degraded context:
    the summary fields plus an explicit caveat, so the model bounds its
    answers by what was actually kept instead of confabulating a report.
    """
    record = store.latest_record(alert_id)
    if record is None:
        return None

    sections: list[str] = []

    if "investigation" in record:
        # Injection scan runs on the stored alert with the CURRENT
        # scanner, and the warning precedes the alert content — same
        # discipline as investigation time.
        alert = Alert(**record["alert"])
        from .copilot import SOCCopilot  # late import: avoids a cycle

        warn = SOCCopilot._format_injection_warning(scan_for_injection(alert))
        if warn:
            sections.append(warn)
        sections.append(
            "# Alert (as investigated)\n"
            f"```json\n{json.dumps(record['alert'], indent=2)}\n```"
        )
        sections.append(
            "# Investigation record (the copilot's full recorded report — "
            "verdict, hypothesis, evidence, detection rules, inventory "
            "matches, prior sightings, reasoning)\n"
            f"```json\n{json.dumps(record['investigation'], indent=2)}\n```"
        )
    else:
        summary = {
            k: record[k]
            for k in (
                "alert_id", "timestamp", "title", "verdict", "confidence",
                "host", "iocs", "attack_techniques",
            )
            if k in record
        }
        sections.append(
            "# Investigation record (SUMMARY ONLY)\n"
            "This record predates full-report storage: only the summary "
            "below was kept — no raw alert, evidence, or reasoning "
            "transcript survives. Answer strictly from these fields, and "
            "when a question needs the full report, say so and suggest "
            "re-investigating the alert (which records a full report).\n"
            f"```json\n{json.dumps(summary, indent=2)}\n```"
        )

    sections.append(_format_ruling(record))
    return "\n\n".join(sections)


class FollowUpSession:
    """A multi-turn conversation about one recorded investigation.

    The grounding context is sent once, with the first question; later
    questions ride on the conversation. Raises KeyError at construction
    when the store has never investigated the alert — there is nothing
    to interrogate, and answering anyway would be pure confabulation.
    """

    def __init__(
        self,
        alert_id: str,
        history_store: AlertHistoryStore | None = None,
        client: AsyncAnthropic | None = None,
    ) -> None:
        self.alert_id = alert_id
        self.history = history_store or AlertHistoryStore(settings.HISTORY_PATH)
        self.client = client or AsyncAnthropic(api_key=settings.ANTHROPIC_KEY)
        grounding = build_grounding(self.history, alert_id)
        if grounding is None:
            raise KeyError(
                f"No investigation on record for alert {alert_id!r}"
            )
        self.grounding = grounding
        self.messages: list[dict] = []

    async def ask(self, question: str) -> str:
        """Ask one question; returns the answer and extends the conversation."""
        if self.messages:
            content = question
        else:
            content = (
                f"{self.grounding}\n\n"
                f"# Analyst question\n{question}"
            )
        self.messages.append({"role": "user", "content": content})

        response = await self.client.messages.create(
            model=settings.MODEL,
            max_tokens=MAX_ANSWER_TOKENS,
            system=FOLLOWUP_SYSTEM_PROMPT,
            messages=self.messages,
        )
        # content may lead with thinking blocks; take the text block.
        answer = next(
            (b.text for b in response.content if b.type == "text"), None
        )
        if answer is None:
            raise RuntimeError("Model response contained no text block")
        self.messages.append({"role": "assistant", "content": response.content})
        return answer

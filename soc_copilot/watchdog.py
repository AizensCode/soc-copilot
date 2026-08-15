"""The watch loop's dead-man's switch.

--watch is the mode that runs with nobody watching, which cuts both
ways: nobody is there to notice when the copilot ITSELF breaks. An
expired Anthropic key, a revoked Elastic token, a SIEM that starts
refusing queries — each turned into an endless per-cycle "FAILED (will
retry next cycle)" printed to a terminal nobody reads, while the queue
silently grew. The webhook channel existed for exactly this shape of
news ("something can't wait until morning") and was never told.

This module is the judgment, kept pure and deterministic so it can be
pinned by tests: the shell reports what each cycle did, and the watchdog
answers with the one action warranted now. Escalation is two-stage:

- PAGE after PAGE_AFTER consecutive sick cycles: one webhook page per
  outage, not one per cycle — a dead desk must not become a pager storm.
  The latch re-arms only after a healthy cycle, i.e. a real recovery.
- EXIT (non-zero) after EXIT_AFTER consecutive sick cycles, but ONLY
  when the sickness looks SYSTEMIC — the streak included a crashed
  cycle, or more than one distinct alert has failed. By then retrying in
  place has been tried for half an hour and a supervisor (systemd,
  docker restart policy) restarting the process — fresh construction,
  fresh clients, freshly-read config — is more likely to help than
  another identical cycle. A streak that is one lone alert failing
  identically every cycle is NOT systemic: a restart cannot fix a
  poisoned record, and exiting over it would let a single malformed
  alert take down a desk that is otherwise fully capable — inverting
  the containment promise the per-alert catch makes (review catch).
  That state pages (the queue is stuck and a human should ack the
  record) and then holds.

A cycle is SICK when it crashed outright (the fetch raised), or when it
attempted alerts and every one of them failed — the expired-key shape,
where the loop looks alive but no work completes. A quiet queue is
healthy (nothing to do is not a failure), and partial progress is
healthy (one poisoned alert must not page anyone while the rest of the
queue is being worked; it is retried, visibly, every cycle). Progress
means MODEL-BACKED work: a dedup-suppressed duplicate borrows a
pre-outage conclusion without spending a model call, so counting it as
`worked` would let a repeating benign family mask a dead investigation
pipeline for as long as duplicates kept arriving (review catch) — the
shell counts those separately as `borrowed`, and they neither sicken a
cycle nor excuse one.
"""
from dataclasses import dataclass, field

# Three sick cycles before paging: one blip is the retry policy's job
# (httpio), two could be an unlucky pair of cycles, three in a row is an
# outage. At the default 60s interval the page arrives ~3 minutes in.
PAGE_AFTER = 3
# Thirty sick cycles (~30 minutes at the default interval) before giving
# up the process. Long enough that a routine SIEM restart never trips
# it; short enough that a supervisor gets to restart the desk while the
# night is still young.
EXIT_AFTER = 30


@dataclass
class CycleReport:
    """What one poll cycle actually accomplished, reported by the shell."""

    worked: int = 0        # alerts completed with a real investigation
    borrowed: int = 0      # dedup-suppressed: completed WITHOUT a model call
    failed: int = 0        # alerts whose _work_alert raised
    crashed: bool = False  # the cycle itself died before working alerts
    failed_ids: set[str] = field(default_factory=set)

    @property
    def sick(self) -> bool:
        return self.crashed or (self.failed > 0 and self.worked == 0)


class Watchdog:
    """Consecutive-sickness counter with a one-page-per-outage latch."""

    def __init__(
        self, page_after: int = PAGE_AFTER, exit_after: int = EXIT_AFTER
    ) -> None:
        self.page_after = page_after
        self.exit_after = exit_after
        self.consecutive_sick = 0
        self._paged = False
        self._streak_crashed = False
        self._streak_failed_ids: set[str] = set()

    @property
    def systemic(self) -> bool:
        """Whether the CURRENT streak looks systemic: it included a
        crashed cycle, or more than one distinct alert has failed. This
        is the exit gate's judgment, exposed so the shell's heartbeat
        can tell the operator which kind of sick the desk is — one that
        will end in a supervisor restart, or one lone poisoned alert
        that will page and hold forever."""
        return self._streak_crashed or len(self._streak_failed_ids) > 1

    @property
    def streak_failed_ids(self) -> frozenset[str]:
        """The distinct alert ids that failed during the current streak
        (empty when healthy). Frozen: the streak is the watchdog's to
        mutate, the shell's to read."""
        return frozenset(self._streak_failed_ids)

    def observe(self, report: CycleReport) -> str | None:
        """Record one cycle; return the action it warrants.

        Returns "page" exactly once per outage, "exit" once a SYSTEMIC
        outage outlives EXIT_AFTER cycles, and None otherwise. Exit
        outranks page when both thresholds are crossed in the same
        observation (possible when page_after == exit_after): the
        process is about to say a louder thing.
        """
        if not report.sick:
            self.consecutive_sick = 0
            self._paged = False
            self._streak_crashed = False
            self._streak_failed_ids = set()
            return None
        self.consecutive_sick += 1
        self._streak_crashed = self._streak_crashed or report.crashed
        self._streak_failed_ids |= report.failed_ids
        if self.consecutive_sick >= self.exit_after and self.systemic:
            return "exit"
        if self.consecutive_sick >= self.page_after and not self._paged:
            self._paged = True
            return "page"
        return None

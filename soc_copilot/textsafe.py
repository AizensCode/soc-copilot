"""One rule for putting untrusted strings into operator-facing text.

Every report this project prints interpolates values that came from
alert content: detection names, IOCs, hostnames, usernames, sender
addresses, alert ids. Alert content is attacker-influenced — that is the
threat model the whole codebase is written against — and a plain-text
report joined with newlines will happily let one of those values emit
lines of its own.

The failure is not theoretical and it is not once. The tuning report
shipped with it: one alert title carrying newlines forged a complete
`NOISY DETECTIONS` section, with a fabricated count and a fabricated
recommendation to except the attacker's address. The very next feature —
response actions — reintroduced it in a new module, where a username
could forge a `block_ip` line that read exactly like the desk's own
recommendation.

Twice is a class of bug, not an accident, so it gets one shared answer
rather than a fix per renderer:

- `one_line` for a VALUE about to be interpolated: collapse it to one
  tidy line, whitespace runs and all.
- `sanitize_lines` at the single point a renderer EMITS its lines, so a
  field added later cannot reopen the hole by forgetting to escape
  itself.

The two do deliberately different things, and the difference is not
cosmetic. The security property is that content cannot BREAK the line or
drive the terminal — not that spacing is tidy. `sanitize_lines`
therefore neutralizes line breaks and control characters while leaving
the layout alone, because a renderer's internal padding is structure it
chose: applying `one_line` to whole lines collapsed the scorecard's
aligned columns the moment it was adopted there.

C1 controls and DEL are handled along with C0, so an escape sequence in
an indicator cannot drive the reader's terminal, and the two Unicode
line separators are covered too — they are not in the C0/C1 ranges but
they do end a line. This is not HTML escaping: `report.py` escapes for
its own context, and a browser collapses whitespace anyway.
"""
import re

# C0, DEL and C1. ESC (0x1b) is in here, which is the point: an ANSI
# sequence in an IOC would otherwise reach the operator's terminal. NEL
# (0x85) falls in the C1 range and is covered with them.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# Line breaks that are not control characters. Missing these would leave
# a renderer that only strips C0/C1 still forgeable.
_SEPARATORS = re.compile(r"[\u2028\u2029]")
_RUNS = re.compile(r"\s+")


def _flatten(value: str) -> str:
    """Replace everything that could end a line, or drive a terminal,
    with a space. Layout is left exactly as it was."""
    return _SEPARATORS.sub(" ", _CONTROL.sub(" ", value))


def one_line(value: str) -> str:
    """Collapse a string to a single printable line."""
    return _RUNS.sub(" ", _flatten(value)).strip()


def sanitize_lines(lines: list[str]) -> list[str]:
    """Make every emitted line unbreakable, without touching layout.

    Whitespace runs are preserved: a report that aligns columns with
    padding must survive its own safety net.
    """
    return [_flatten(line).rstrip() for line in lines]

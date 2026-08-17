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

- `one_line` for a value that is about to be interpolated,
- `sanitize_lines` at the single point a renderer emits its lines, so a
  field added later cannot reopen the hole by forgetting to escape
  itself.

C1 controls and DEL are stripped along with C0, so an escape sequence in
an indicator cannot drive the reader's terminal. This is not HTML
escaping: `report.py` escapes for its own context, and a browser
collapses whitespace anyway.
"""
import re

# C0, DEL and C1. ESC (0x1b) is in here, which is the point: an ANSI
# sequence in an IOC would otherwise reach the operator's terminal.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_RUNS = re.compile(r"\s+")


def one_line(value: str) -> str:
    """Collapse a string to a single printable line."""
    return _RUNS.sub(" ", _CONTROL.sub(" ", value)).strip()


def sanitize_lines(lines: list[str]) -> list[str]:
    """Apply `one_line` to every emitted line, preserving indentation.

    Indentation is structure the renderer chose; everything after it is
    content that may not have been.
    """
    out = []
    for line in lines:
        indent = len(line) - len(line.lstrip(" "))
        out.append(" " * indent + one_line(line))
    return out

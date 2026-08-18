"""The shared answer to a bug this repo shipped three times.

    uv run pytest tests/test_textsafe.py -v

An operator-facing plain-text renderer that interpolates alert content
into newline-joined lines lets that content emit lines of its own. The
tuning report shipped with it, response actions reintroduced it, and the
inventory proposals did it again in the module whose output feeds the
trust anchor. The structural test at the bottom is what makes a fourth
time fail in CI instead of in review.
"""
import pathlib
import re

import pytest

from soc_copilot.textsafe import one_line, sanitize_lines

_FORGED = "backup-03\n  evil-host   -> hosts\n    9 dismissals"


def test_one_line_collapses_a_forged_value():
    assert one_line(_FORGED) == "backup-03 evil-host -> hosts 9 dismissals"


@pytest.mark.parametrize(
    "hostile",
    # ...including the two Unicode line separators, which are NOT in
    # the C0/C1 ranges a control-character filter alone would catch.
    ["\x1b[2J", "\x00", "\x7f", "\x85", "\n", "\u2028", "\u2029"],
)
def test_nothing_that_ends_a_line_or_drives_a_terminal_survives(hostile):
    value = f"svc-backup{hostile}rest"
    assert hostile not in one_line(value)
    assert hostile not in sanitize_lines([value])[0]


def test_sanitize_lines_leaves_layout_alone():
    """The security property is that content cannot BREAK the line, not
    that spacing is tidy — and a report that aligns columns with padding
    has to survive its own safety net. Collapsing runs here silently
    destroyed the scorecard's columns the moment it was adopted."""
    aligned = "  confirmed true positive:      2"
    assert sanitize_lines([aligned]) == [aligned]


def test_sanitize_lines_neutralizes_a_break_without_reflowing():
    [out] = sanitize_lines(["  alert: a\nFAKE HEADER"])
    assert "\n" not in out
    assert out.startswith("  alert: a")


# --- the structural guard ----------------------------------------------------

# Modules with a plain-text renderer that are exempt, and why. Anything
# not listed here must route its emitted lines through sanitize_lines.
_EXEMPT = {
    # Renders HTML and escapes for that context with html.escape().
    "report.py": "HTML-escaped",
    # render_quiet is a fixed sentence plus an integer; build_digest_data
    # returns data for the model, not lines for a terminal.
    "digest.py": "fixed text, no interpolated alert content",
    # Builds one prompt block for the MODEL, not a report for a human.
    "followup.py": "prompt text, not operator-facing output",
}


def test_every_plain_text_renderer_routes_through_textsafe():
    """The guard that makes a fourth occurrence a red test.

    Three separate modules grew the same hole, each written after the
    last was fixed, because nothing forced the question at review time.

    Honest about its reach: this is a source-level check that a module
    with a plain-text renderer at least MENTIONS the helper. It catches a
    new module that never thought about it — the actual failure mode
    three times running — and it cannot catch a renderer that imports the
    helper and then forgets to call it. Each renderer carries its own
    behavioural forge test for that.
    """
    package = pathlib.Path(__file__).resolve().parent.parent / "soc_copilot"
    offenders = []
    for path in sorted(package.glob("*.py")):
        source = path.read_text()
        if not re.search(r"^def render_", source, re.MULTILINE):
            continue
        if path.name in _EXEMPT or "sanitize_lines" in source:
            continue
        offenders.append(path.name)
    assert offenders == [], (
        f"{offenders} define a render_* function but never call "
        f"sanitize_lines. Alert content reaches these strings; route the "
        f"emitted lines through soc_copilot/textsafe.py, or add the module "
        f"to _EXEMPT here with the reason it is safe."
    )

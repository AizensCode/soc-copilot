"""How the desk speaks: logging, configured at the CLI shell only.

The library modules never log — they compute, raise, or return, and the
CLI shell (soc_copilot/main.py) is the single narrator. That was already
true when the narration was 60-odd print() calls; this module keeps the
single-narrator property and gives the narration what print() could not:

- a LEVEL, so `journalctl -p warning` shows an unattended --watch's
  problems without its progress. That filter works because the level is
  actually DELIVERED to journald: a Python log level is otherwise an
  in-process fact, and journald stamps every captured stream line at its
  default priority (info) — the filter would show nothing (review
  catch). When stderr IS the journal socket (systemd sets
  $JOURNAL_STREAM to that socket's dev:inode), every line is prefixed
  with the sd-daemon `<N>` priority token, which journald strips and
  records as the real per-line priority (SyslogLevelPrefix= defaults
  on). Anywhere else — a terminal, docker, a pipe — no prefix, no
  garbage;
- an optional JSON line format (LOG_FORMAT=json), so a log shipper gets
  `{"ts", "level", "msg", "alert_id"}` per line instead of prose — and a
  multi-line message (the telemetry block) can never tear the stream,
  because json.dumps escapes the newlines;
- a per-alert correlation id: everything logged while one alert is being
  worked carries that alert's id, so `jq 'select(.alert_id=="X")'` (or a
  Kibana filter) replays one alert's whole story from an interleaved
  night. The id rides a ContextVar, not a function argument, so the
  deepest helper doesn't need its signature threaded.

Configuration happens in exactly one place — cli() calls
configure_logging() before dispatching — and attaches one handler to the
"soc_copilot" logger. Two deliberate choices:

- The handler writes to the CURRENT sys.stderr, late-bound per record
  (the stdlib's own lastResort handler works this way). Narration goes
  to stderr so a command's PRODUCT on stdout stays pipeable
  (`soc-copilot alert.json | jq .verdict`); journald and docker capture
  both streams the same.
- Propagation to the root logger stays ON. In this process nothing
  configures the root logger, so nothing double-prints — and anything
  that captures at the root (pytest's caplog) sees the records without
  ceremony. configure_logging() is idempotent: it replaces its own
  handler rather than stacking a second, so a re-entrant call (tests,
  a future in-process restart) never doubles the output.
"""
import json
import logging
import os
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Iterator

FORMATS = ("text", "json")
LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

# Python level -> syslog priority, for the sd-daemon `<N>` line prefix.
_SD_PRIORITY = {"DEBUG": 7, "INFO": 6, "WARNING": 4, "ERROR": 3, "CRITICAL": 2}


def _stderr_is_journal() -> bool:
    """Whether this process's stderr is the systemd journal socket.

    systemd exports $JOURNAL_STREAM as `dev:inode` of the stream it
    connected to the service's stdout/stderr; comparing against fstat of
    our actual stderr proves the prefix will be read by journald and not
    printed as garbage to a terminal, a pipe, or docker logs. Evaluated
    once at configure time: under systemd the stream never changes, and
    everywhere else the answer is a stable no."""
    spec = os.environ.get("JOURNAL_STREAM", "")
    if ":" not in spec:
        return False
    try:
        dev, ino = spec.split(":", 1)
        st = os.fstat(sys.stderr.fileno())
        return (st.st_dev, st.st_ino) == (int(dev), int(ino))
    except (ValueError, OSError, AttributeError):
        # No usable fileno (captured/redirected stderr), malformed spec:
        # then stderr is not the journal socket.
        return False

# The correlation id: which alert the current (async) context is working.
# A ContextVar, not a global — watch mode is async, and a context var
# follows the task even if concurrent work ever appears.
_current_alert_id: ContextVar[str | None] = ContextVar(
    "soc_copilot_alert_id", default=None
)


@contextmanager
def alert_context(alert_id: str) -> Iterator[None]:
    """Tag every log record emitted inside the block with this alert id."""
    token = _current_alert_id.set(alert_id)
    try:
        yield
    finally:
        _current_alert_id.reset(token)


class _AlertIdFilter(logging.Filter):
    """Stamp the current alert id onto each record (None outside any
    alert), so formatters read one attribute instead of the ContextVar."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.alert_id = _current_alert_id.get()
        return True


class _JsonFormatter(logging.Formatter):
    """One JSON object per line: ts (UTC, from the record's own clock),
    level, msg, and alert_id when the record was born inside an alert.
    ensure_ascii=False keeps the health page's 🤒 readable in the log."""

    def format(self, record: logging.LogRecord) -> str:
        doc: dict[str, object] = {
            "ts": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "msg": record.getMessage(),
        }
        alert_id = getattr(record, "alert_id", None)
        if alert_id:
            doc["alert_id"] = alert_id
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, ensure_ascii=False)


class _SdPriorityFormatter(logging.Formatter):
    """Wrap the chosen formatter with sd-daemon `<N>` priority prefixes.

    This is what makes `journalctl -p warning` TRUE rather than
    documented: without it every captured line lands in the journal at
    the unit's default priority (info, 6) and the level-filtered view is
    empty (review catch). journald strips the token and stamps the real
    priority per line (SyslogLevelPrefix= defaults on), so the stored
    MESSAGE stays clean — JSON mode's objects survive intact. Every line
    of a multi-line message is prefixed, because journald treats each
    line as its own record and unprefixed continuations would fall back
    to info."""

    def __init__(self, inner: logging.Formatter) -> None:
        super().__init__()
        self._inner = inner

    def format(self, record: logging.LogRecord) -> str:
        pri = _SD_PRIORITY.get(record.levelname, 6)
        return "\n".join(
            f"<{pri}>{line}"
            for line in self._inner.format(record).split("\n")
        )


class _CurrentStderrHandler(logging.StreamHandler):
    """A StreamHandler bound to whatever sys.stderr IS at emit time.

    StreamHandler captures the stream object at construction, which
    would pin the handler to a stderr that pytest's capture (or any
    redirection) has since replaced — output would silently go to a
    dead buffer. Late-binding via a property is the stdlib's own
    pattern for this (logging._StderrHandler)."""

    def __init__(self) -> None:
        # Skip StreamHandler.__init__: it assigns self.stream, which the
        # read-only property below forbids — Handler.__init__ is enough.
        logging.Handler.__init__(self)

    @property
    def stream(self):  # noqa: ANN201 - matches the stdlib's untyped attr
        return sys.stderr


def configure_logging(fmt: str = "text", level: str = "INFO") -> None:
    """Install the one handler the CLI speaks through. Called by cli()
    only. Invalid values raise RuntimeError naming the valid ones, which
    cli() renders as a one-line configuration error — the same loudly-
    at-startup contract as a malformed WEBHOOK_URL.

    In text mode the output is exactly what print() produced before:
    the bare message, no timestamp prefix — journald and docker already
    stamp every line, and double timestamps are how log lines become
    unreadable. The level and timestamp live in the JSON format for
    consumers that want fields.
    """
    fmt = fmt.lower()
    level = level.upper()
    if fmt not in FORMATS:
        raise RuntimeError(
            f"LOG_FORMAT must be one of {', '.join(FORMATS)}, got {fmt!r}"
        )
    if level not in LEVELS:
        raise RuntimeError(
            f"LOG_LEVEL must be one of {', '.join(LEVELS)}, got {level!r}"
        )
    logger = logging.getLogger("soc_copilot")
    logger.setLevel(level)
    for old in list(logger.handlers):
        logger.removeHandler(old)
    handler = _CurrentStderrHandler()
    formatter: logging.Formatter = (
        _JsonFormatter() if fmt == "json" else logging.Formatter("%(message)s")
    )
    if _stderr_is_journal():
        formatter = _SdPriorityFormatter(formatter)
    handler.setFormatter(formatter)
    handler.addFilter(_AlertIdFilter())
    logger.addHandler(handler)

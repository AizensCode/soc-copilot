"""Recorded external reputation for the eval harness — reputation as data.

The three reputation tools (AbuseIPDB, VirusTotal, URLScan) make the
copilot's verdict depend on what the live internet says about an
indicator right now. That is correct in production and an eval problem in
the harness: a pinned expectation was calibrated against whatever those
services returned that day, and their answers DRIFT. A Tor exit node
gets de-listed and re-listed; a hash's detection count climbs; a domain
picks up its first scan. When a pinned verdict then moves, there is no
way to tell whether the MODEL regressed or the reputation did — the two
are entangled, and the eval is measuring both at once.

So the harness brings its own reputation. `ReputationCassette` holds the
recorded raw responses (data/evals/cassettes/reputation.json) and replays
them through an httpx MockTransport, so the model still runs LIVE while
its reputation inputs are frozen. A moved verdict is now unambiguously a
model change — which is the whole point. Refresh the recordings with
`python -m tests.record_cassette` (needs the three API keys); the diff is
reviewed like any other recorded shape in this repo.

Two properties make it trustworthy enough to pin on, both copied from
FakeEventsIndex:

1. It REPLAYS THE RAW RESPONSE, not a cooked ToolResult, so each tool's
   own parsing still runs in replay — VirusTotal's 404 -> {found: false}
   branch and URLScan's total==0 branch included. A regression in that
   parsing is still caught.
2. It FAILS LOUD on an unrecorded indicator. A miss is not an empty
   answer (which would let an evidence-count assertion pass on a fiction)
   — it is recorded in `.misses` and raised as `CassetteMiss`, a
   BaseException that escapes the tools' broad `except Exception`, so a
   new fixture indicator with no recording is a red test, not a silent
   skip.

What it is NOT: a reputation service. It models exact-indicator lookup
against a frozen snapshot — nothing about how AbuseIPDB scores or how
VirusTotal aggregates. Fidelity to the real services comes from the
record-mode run against them; this replays what that run captured.
"""
import json
from pathlib import Path

import httpx

from soc_copilot.tools.abuseipdb import AbuseIPDBTool
from soc_copilot.tools.urlscan import URLScanTool
from soc_copilot.tools.virustotal import VirusTotalTool

CASSETTE_PATH = (
    Path(__file__).resolve().parents[1]
    / "data" / "evals" / "cassettes" / "reputation.json"
)

# Host -> the namespace its recordings live under. The set of hosts is
# also the allowlist: a request to any other host is a tool this cassette
# does not model, and must fail loudly rather than be replayed as nothing.
_HOST_NAMESPACE = {
    "api.abuseipdb.com": "abuseipdb",
    "www.virustotal.com": "virustotal",
    "urlscan.io": "urlscan",
}


class CassetteMiss(BaseException):
    """An indicator with no recording was requested. A BaseException, not
    an Exception, on purpose: the reputation tools wrap execute() in a
    broad `except Exception`, and a miss must escape it to fail the test
    naming the missing indicator instead of degrading to a failed
    ToolResult the harness would quietly average in."""


def normalize_domain(domain: str) -> str:
    """The form URLScanTool queries a domain under — scheme and trailing
    slash stripped, exactly as the tool does before building its request.
    Applied to declared indicators so the recorded, declared, and replayed
    keys agree by construction rather than by fixture hygiene."""
    return domain.replace("http://", "").replace("https://", "").rstrip("/")


def _indicator_of(request: httpx.Request) -> tuple[str, str]:
    """(namespace, indicator key) for a reputation request — the same key
    the recorder wrote. Keyed on the indicator ALONE, never on volatile
    params like maxAgeInDays or size, which are constants of the call. The
    urlscan key is already normalized because the tool normalized the
    domain before building `q`."""
    host = request.url.host
    namespace = _HOST_NAMESPACE.get(host)
    if namespace is None:
        raise CassetteMiss(f"unmodeled reputation host: {host}")
    if namespace == "abuseipdb":
        return namespace, request.url.params.get("ipAddress", "")
    if namespace == "virustotal":
        return namespace, request.url.path.rsplit("/", 1)[-1]
    # urlscan: q="domain:<domain>"
    q = request.url.params.get("q", "")
    return namespace, q[len("domain:"):] if q.startswith("domain:") else q


class ReputationCassette:
    """Recorded reputation responses, replayed through an httpx transport."""

    def __init__(self, recordings: dict[str, dict[str, dict]]) -> None:
        self._recordings = recordings
        self.requests: list[tuple[str, str]] = []  # every (namespace, key) seen
        self.misses: list[tuple[str, str]] = []     # those with no recording

    @classmethod
    def load(cls, path: str | Path = CASSETTE_PATH) -> "ReputationCassette":
        data = json.loads(Path(path).read_text())
        return cls(data)

    # --- injection: the client and the tools bound to it --------------------

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport())

    def tools(self) -> tuple[AbuseIPDBTool, VirusTotalTool, URLScanTool]:
        """The three reputation tools bound to this cassette's client, ready
        for `registry.replacing(*cassette.tools())`. One client serves all
        three hosts; the transport routes by host."""
        client = self.client()
        return (
            AbuseIPDBTool(client=client),
            VirusTotalTool(client=client),
            URLScanTool(client=client),
        )

    # --- the transport handler ----------------------------------------------

    def _handle(self, request: httpx.Request) -> httpx.Response:
        namespace, key = _indicator_of(request)
        self.requests.append((namespace, key))
        recorded = self._recordings.get(namespace, {}).get(key)
        if recorded is None:
            self.misses.append((namespace, key))
            raise CassetteMiss(
                f"no recorded {namespace} response for {key!r} — record it "
                f"with `python -m tests.record_cassette` before pinning on it"
            )
        return httpx.Response(
            status_code=recorded.get("status_code", 200),
            json=recorded.get("json", {}),
            request=request,
        )

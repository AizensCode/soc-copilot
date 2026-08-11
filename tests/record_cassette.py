"""Refresh the recorded reputation cassette from the live services.

    ABUSEIPDB_API_KEY=... VIRUSTOTAL_API_KEY=... URLSCAN_API_KEY=... \
        uv run python -m tests.record_cassette

This is the ONLY path that touches the real reputation APIs. It drives
the actual tools (so their exact request shape is what gets recorded)
through a transport that captures each RAW upstream response — status
code and body, VERBATIM and in the provider's native key order — and
writes them to data/evals/cassettes/reputation.json, keyed by the same
(namespace, indicator) the cassette replays on.

Two properties the recording must hold, both learned from an adversarial
review of the first version:

- FAITHFUL. The stored body is the wire body, in wire order, untrimmed.
  Replay then reproduces json.dumps(result.data) byte-for-byte, so a
  frozen snapshot is exactly what a live call returned at record time —
  which is what makes it reproduce the calibrated verdicts. (The first
  version trimmed AbuseIPDB's verbose `reports` tail and sorted the keys
  to keep the file small; both changed the bytes the model actually sees —
  the sorted order pushed summary fields past the 6000-char agentic window,
  and the trim shortened the untruncated phase-1 prompt. Fidelity beats
  compactness for an eval ground truth.)
- AUTHORITATIVE. A 200 is recorded only if its body has the shape the tool
  depends on. A transient degenerate 200 (empty body, error envelope)
  would otherwise be frozen in as a benign/unseen verdict.

Every indicator any pinned fixture could reach is recorded — the declared
`indicators`, plus IPs, hashes, and URL hosts harvested from the alert
body, because the agentic model looks up indicators it extracts from the
text, not only the declared ones. A lookup with no recording is still a
loud CassetteMiss (the backstop), but the harvest keeps that rare.

The written file is committed and reviewed on change, like every other
recorded shape in this repo. Review the SUMMARY fields (scores, found
flags) — the verbose detail arrays are expected to churn between records.
"""
import asyncio
import glob
import json
import re
import sys
from pathlib import Path

import httpx

from soc_copilot.config import settings
from soc_copilot.tools.abuseipdb import AbuseIPDBTool
from soc_copilot.tools.urlscan import URLScanTool
from soc_copilot.tools.virustotal import VirusTotalTool

from .cassette import CASSETTE_PATH, _indicator_of, normalize_domain

# Every fixture corpus whose indicators reach the live reputation tools.
_CORPORA = (
    "data/sample_alerts/*.json",
    "data/scenarios/campaign_ci_compromise/*.json",
    "data/evals/cases/*.json",
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
_URL_HOST_RE = re.compile(r"https?://([^/\s\"'<>)\]]+)", re.IGNORECASE)


def _gather_indicators() -> dict[str, list[str]]:
    """Deduplicated ips/hashes/domains across every pinned corpus.

    Beyond the declared `indicators` dict (what phase-1 enrich() reads),
    this also harvests IPs, hashes, and URL hosts from the whole alert
    body, because the AGENTIC model dispatches lookups on indicators it
    extracts from free text — not only the declared ones (review catch).
    Domains are stored under the tool's normalized form so the recorded,
    declared, and replayed keys agree by construction. Case files wrap the
    alert under 'alert'; sample and scenario files are the alert itself.
    """
    found: dict[str, set[str]] = {"ips": set(), "hashes": set(), "domains": set()}
    for pattern in _CORPORA:
        for path in glob.glob(pattern):
            doc = json.loads(Path(path).read_text())
            alert = doc.get("alert", doc)
            indicators = alert.get("indicators") or {}
            found["ips"].update(
                v for v in (indicators.get("ips") or []) if isinstance(v, str)
            )
            found["hashes"].update(
                v for v in (indicators.get("hashes") or []) if isinstance(v, str)
            )
            found["domains"].update(
                normalize_domain(v)
                for v in (indicators.get("domains") or [])
                if isinstance(v, str)
            )
            _harvest(json.dumps(alert), found)
    # The differential SIEM eval (tests/test_logsearch_eval.py) seeds worlds
    # whose events carry an indicator no alert file declares — the payload
    # host the compromised world's `wget` reaches — which the agentic model
    # discovers via log search and looks up. Harvest those too, or that
    # lookup is a live CassetteMiss (review catch, caught live by exactly
    # this harness's fail-loud guard).
    from .fake_siem import compromised_index, contained_index
    for world in (compromised_index(), contained_index()):
        _harvest(json.dumps(world.events), found)
    return {kind: sorted(values) for kind, values in found.items()}


def _harvest(text: str, found: dict[str, set[str]]) -> None:
    """Add every IP, hash, and URL host in `text` — the indicators the
    agentic model can extract from free text, beyond the declared ones."""
    found["ips"].update(_IPV4_RE.findall(text))
    found["hashes"].update(h.lower() for h in _HASH_RE.findall(text))
    found["domains"].update(normalize_domain(h) for h in _URL_HOST_RE.findall(text))


def _is_authoritative(namespace: str, status: int, body: dict) -> bool:
    """Whether a recorded response carries the shape the tool depends on.

    Guards against freezing in a transient degenerate 200 — an empty body,
    an AbuseIPDB error envelope, a URLScan response missing its result
    keys — as if it were an authoritative benign/unseen verdict."""
    if namespace == "abuseipdb":
        return (
            status == 200
            and isinstance(body.get("data"), dict)
            and "abuseConfidenceScore" in body["data"]
        )
    if namespace == "virustotal":
        return status == 404 or (
            status == 200 and isinstance(body.get("data", {}).get("attributes"), dict)
        )
    if namespace == "urlscan":
        return status == 200 and "total" in body and "results" in body
    return False


class _RecordingTransport(httpx.AsyncBaseTransport):
    """Passes each request to the real network, then captures the raw
    response body — verbatim, native key order — keyed the way the cassette
    will look it up."""

    def __init__(self) -> None:
        self._inner = httpx.AsyncHTTPTransport()
        self.recordings: dict[str, dict[str, dict]] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        await response.aread()  # buffer the body so we (and the tool) can read it
        namespace, key = _indicator_of(request)
        try:
            body = json.loads(response.content) if response.content else {}
        except json.JSONDecodeError:
            body = {}
        self.recordings.setdefault(namespace, {})[key] = {
            "status_code": response.status_code,
            "json": body,
        }
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


def _canonical(recordings: dict[str, dict[str, dict]]) -> dict:
    """Sort the namespace and indicator keys (so diffs are organized) while
    leaving each response body in its native wire order (so replay stays
    byte-identical to the live call)."""
    return {
        ns: {ind: recordings[ns][ind] for ind in sorted(recordings[ns])}
        for ns in sorted(recordings)
    }


async def _record() -> int:
    missing = [
        name
        for name, value in (
            ("ABUSEIPDB_API_KEY", settings.ABUSEIPDB_KEY),
            ("VIRUSTOTAL_API_KEY", settings.VIRUSTOTAL_KEY),
            ("URLSCAN_API_KEY", settings.URLSCAN_KEY),
        )
        if not value
    ]
    if missing:
        # Fail loud rather than write a cassette full of 401s that would
        # then replay as ground truth (review risk).
        print(f"ERROR: missing API key(s): {', '.join(missing)}", file=sys.stderr)
        return 1

    indicators = _gather_indicators()
    transport = _RecordingTransport()
    client = httpx.AsyncClient(transport=transport, timeout=20.0)
    ip_tool = AbuseIPDBTool(client=client)
    hash_tool = VirusTotalTool(client=client)
    domain_tool = URLScanTool(client=client)

    failures: list[str] = []

    async def run(namespace: str, key: str, label: str, make_coro) -> None:
        # Retry on transient failure: the reputation services return the
        # occasional 5xx (URLScan's search sits on a shared ES cluster that
        # is periodically "over capacity"), and a refresh should not abort
        # over one blip. "Success" here is BOTH a tool-level success AND an
        # authoritative body — a degenerate 200 must not be frozen in as
        # truth. A persistent failure still aborts the write.
        for attempt in range(4):
            result = await make_coro()
            recorded = transport.recordings.get(namespace, {}).get(key, {})
            ok = result.success and _is_authoritative(
                namespace, recorded.get("status_code", 0), recorded.get("json", {})
            )
            if ok:
                print(f"  {label:52} ok")
                break
            if attempt < 3:
                await asyncio.sleep(1.5 * (attempt + 1))
        else:
            reason = result.error or "non-authoritative body"
            failures.append(f"{label}: {reason}")
            print(f"  {label:52} FAILED: {reason[:60]}")
        await asyncio.sleep(0.3)  # be polite to rate limits

    print(f"Recording {len(indicators['ips'])} IPs, "
          f"{len(indicators['hashes'])} hashes, "
          f"{len(indicators['domains'])} domains...")
    for ip in indicators["ips"]:
        await run("abuseipdb", ip, f"abuseipdb {ip}", lambda ip=ip: ip_tool.execute(ip=ip))
    for file_hash in indicators["hashes"]:
        await run(
            "virustotal", file_hash, f"virustotal {file_hash[:16]}…",
            lambda h=file_hash: hash_tool.execute(file_hash=h),
        )
    for domain in indicators["domains"]:
        await run(
            "urlscan", domain, f"urlscan {domain}",
            lambda d=domain: domain_tool.execute(domain=d),
        )

    await client.aclose()
    await transport.aclose()

    if failures:
        print(f"\nERROR: {len(failures)} lookup(s) failed; not overwriting the "
              f"cassette:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 1

    CASSETTE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CASSETTE_PATH.write_text(json.dumps(_canonical(transport.recordings), indent=2) + "\n")
    total = sum(len(v) for v in transport.recordings.values())
    print(f"\nWrote {total} recordings to {CASSETTE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_record()))

"""Tests for the reputation cassette — the double the harness pins on.

A double that expectations rest on is load-bearing: if it drifts, the
eval measures a fiction. So the cassette gets the same scrutiny fake_siem
does, plus the one property that justifies its existence — that with
reputation frozen, a MODEL regression still moves the verdict (otherwise
the cassette would be masking the thing the eval is supposed to catch).

All of this is API-free and network-free.

    uv run pytest tests/test_cassette.py -v
"""
import json
from types import SimpleNamespace

import pytest

from soc_copilot.history import AlertHistoryStore

from .alert_loading import SAMPLE_ALERTS_DIR, load_alert_fixture
from .cassette import CASSETTE_PATH, CassetteMiss, ReputationCassette
from .harness import make_copilot
from .record_cassette import _gather_indicators

# A tiny hand-authored cassette so the double's own behavior is tested in
# isolation from whatever the committed recording currently holds.
_MINI = {
    "abuseipdb": {
        "185.220.101.47": {
            "status_code": 200,
            "json": {"data": {
                "abuseConfidenceScore": 81, "totalReports": 96,
                "countryCode": "DE", "isTor": True, "usageType": "Data Center",
            }},
        },
    },
    "virustotal": {
        "badhash": {"status_code": 200, "json": {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 60, "undetected": 10},
            "last_analysis_results": {
                "EngineA": {"category": "malicious", "result": "Trojan.X"},
                "EngineB": {"category": "undetected", "result": None},
            },
            "type_description": "Text", "names": ["evil.txt"],
        }}}},
        "goodhash": {"status_code": 404, "json": {}},
    },
    "urlscan": {
        "unseen.example": {"status_code": 200, "json": {"total": 0, "results": []}},
    },
}


def _cassette() -> ReputationCassette:
    return ReputationCassette(json.loads(json.dumps(_MINI)))


# --- replay fidelity: the tool's own parsing runs on recorded bytes --------


async def test_replay_is_deterministic_and_matches_the_recording():
    cassette = _cassette()
    ip_tool, _, _ = cassette.tools()
    seen = [
        (await ip_tool.execute(ip="185.220.101.47")).data["abuseConfidenceScore"]
        for _ in range(5)
    ]
    assert seen == [81] * 5  # identical every call, equal to the recording


async def test_virustotal_404_branch_runs_in_replay():
    """The 404 -> {found: False} path is the tool's, not the cassette's —
    it must still execute on a replayed 404."""
    cassette = _cassette()
    _, hash_tool, _ = cassette.tools()
    miss = await hash_tool.execute(file_hash="goodhash")
    assert miss.success and miss.data == {"found": False, "hash": "goodhash"}
    hit = await hash_tool.execute(file_hash="badhash")
    assert hit.data["found"] is True and hit.data["malicious_count"] == 60
    # the detections list is derived by filtering last_analysis_results
    assert [d["result"] for d in hit.data["detections"]] == ["Trojan.X"]


async def test_urlscan_total_zero_branch_runs_in_replay():
    cassette = _cassette()
    _, _, domain_tool = cassette.tools()
    result = await domain_tool.execute(domain="unseen.example")
    assert result.success and result.data["found"] is False


# --- fail loud on an unrecorded indicator ----------------------------------


async def test_a_miss_raises_and_is_recorded_not_swallowed():
    """A missing recording escapes the tool's broad `except Exception` (so
    the test fails naming the indicator) AND lands in `.misses` (so a
    session-teardown guard can catch it even if a caller swallowed it)."""
    cassette = _cassette()
    ip_tool, _, _ = cassette.tools()
    with pytest.raises(CassetteMiss, match="9.9.9.9"):
        await ip_tool.execute(ip="9.9.9.9")
    assert cassette.misses == [("abuseipdb", "9.9.9.9")]


async def test_requests_are_recorded_for_introspection():
    cassette = _cassette()
    ip_tool, _, domain_tool = cassette.tools()
    await ip_tool.execute(ip="185.220.101.47")
    await domain_tool.execute(domain="unseen.example")
    assert cassette.requests == [
        ("abuseipdb", "185.220.101.47"), ("urlscan", "unseen.example"),
    ]


# --- the committed cassette is stored faithfully, in native order ----------


def test_committed_abuseipdb_bodies_keep_native_order_not_sorted():
    """A re-record must NOT sort the response keys. Live AbuseIPDB returns
    the verbose `reports` array last, so the summary fields sit early; the
    agentic path feeds the model only json.dumps(result.data)[:6000], so
    sorted order (reports before totalReports/usageType) would strand those
    summary fields past the window the model sees (review catch)."""
    cassette = ReputationCassette.load()
    checked = 0
    for ip, rec in cassette._recordings.get("abuseipdb", {}).items():
        data = rec["json"].get("data")
        if not isinstance(data, dict) or not data.get("reports"):
            continue
        dump = json.dumps(data)
        assert "totalReports" in dump and dump.index("totalReports") < 6000, ip
        assert dump.index("totalReports") < dump.index('"reports"'), ip
        checked += 1
    assert checked, "expected at least one AbuseIPDB entry with reports to guard"


# --- the committed cassette actually covers the pinned corpus --------------


def test_committed_cassette_covers_every_pinned_indicator():
    """Every indicator any pinned fixture carries has a recording, so the
    fail-loud guard never trips in a normal live run — and adding a fixture
    with a new indicator is a red test until it is recorded."""
    cassette = ReputationCassette.load()
    indicators = _gather_indicators()
    missing = []
    for ip in indicators["ips"]:
        if ip not in cassette._recordings.get("abuseipdb", {}):
            missing.append(("abuseipdb", ip))
    for h in indicators["hashes"]:
        if h not in cassette._recordings.get("virustotal", {}):
            missing.append(("virustotal", h))
    for d in indicators["domains"]:
        if d not in cassette._recordings.get("urlscan", {}):
            missing.append(("urlscan", d))
    assert not missing, f"uncovered indicators (run tests/record_cassette): {missing}"


# --- both call paths read the one seam -------------------------------------


async def test_phase1_and_agentic_dispatch_share_the_cassette_seam(tmp_path):
    """The __init__ unification: phase-1's ip_tool and the agentic
    registry's check_ip_reputation are the SAME cassette-backed instance,
    so one injected cassette covers both paths."""
    copilot = make_copilot(
        store=AlertHistoryStore(tmp_path / "h.jsonl"), cassette=ReputationCassette.load()
    )
    assert copilot.ip_tool is copilot.tools.get("check_ip_reputation")
    direct = await copilot.ip_tool.execute(ip="185.220.101.47")
    dispatched = await copilot.tools.dispatch("check_ip_reputation", {"ip": "185.220.101.47"})
    assert direct.data == dispatched.data
    # Both paths replay whatever the cassette holds for this IP — asserted
    # against the file, not a hardcoded number, so a re-recording (the Tor
    # exit's score has drifted 100 -> 81 -> 88 across recordings, which is
    # the whole point of freezing it) doesn't turn a fidelity check into a
    # brittle magic-number check.
    recorded = json.loads(CASSETTE_PATH.read_text())["abuseipdb"]["185.220.101.47"]
    expected_score = recorded["json"]["data"]["abuseConfidenceScore"]
    assert direct.data["abuseConfidenceScore"] == expected_score


# --- the property that justifies the whole thing ---------------------------


def _scripted_client(verdict: str, confidence: str) -> SimpleNamespace:
    """A fake Anthropic client that emits a fixed final Investigation, so
    the ONLY thing varying between runs is the model's verdict."""
    final = json.dumps({
        "alert_id": "BF-1", "verdict": verdict, "confidence": confidence,
        "hypothesis": "h", "attack_techniques": [], "suggested_pivots": [],
        "escalation_recommended": verdict == "true_positive",
        "escalation_draft": None, "reasoning_transcript": "r",
        "duplicate_of": None, "sigma_matches": [], "phishing": None,
    })

    class _Messages:
        async def create(self, **kwargs):
            return SimpleNamespace(
                content=[SimpleNamespace(type="text", text=final)],
                stop_reason="end_turn",
                usage=SimpleNamespace(input_tokens=10, output_tokens=10),
            )

    return SimpleNamespace(messages=_Messages())


async def test_a_model_regression_still_moves_the_verdict(tmp_path):
    """The point of the cassette: reputation is frozen, so the verdict is a
    function of the MODEL. Feeding the harness two different scripted model
    outputs against the SAME recorded reputation must produce two different
    verdicts — proving the cassette pins evidence, never the verdict, and
    cannot mask a model regression."""
    cassette = ReputationCassette.load()
    alert = load_alert_fixture(SAMPLE_ALERTS_DIR / "brute_force_ssh.json")
    verdicts = {}
    for verdict, confidence in (("true_positive", "high"), ("false_positive", "low")):
        copilot = make_copilot(
            store=AlertHistoryStore(tmp_path / f"{verdict}.jsonl"), cassette=cassette
        )
        copilot.client = _scripted_client(verdict, confidence)
        inv = await copilot.investigate(alert, record=False)
        verdicts[verdict] = inv.verdict
    assert verdicts == {"true_positive": "true_positive", "false_positive": "false_positive"}


async def test_non_mail_alert_still_replays_ip_reputation(tmp_path):
    """A sanity check that the cassette client is actually exercised in a
    real investigate() — the recorded score reaches enrichment evidence."""
    cassette = ReputationCassette.load()
    alert = load_alert_fixture(SAMPLE_ALERTS_DIR / "brute_force_ssh.json")
    copilot = make_copilot(
        store=AlertHistoryStore(tmp_path / "h.jsonl"), cassette=cassette
    )
    evidence = await copilot.enrich(alert)
    blob = json.dumps([e.model_dump() for e in evidence])
    assert "185.220.101.47" in blob and "81" in blob
    assert ("abuseipdb", "185.220.101.47") in cassette.requests

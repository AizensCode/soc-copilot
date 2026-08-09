"""Eval: the verdict shift internal log search exists to produce
(API-backed — makes real Anthropic calls; the SIEM is the harness's own).

The live demo showed the copilot pivoting into the SIEM and escalating a
brute force from *attempted* to *confirmed*. A demo is one run against
one seeded index; this pins it as a differential expectation the harness
owns end-to-end: the SAME alert investigated against two controlled
worlds (tests/fake_siem.py) that differ in exactly one fact — whether any
of the 847 attempts landed — must produce investigations that differ in
exactly the ways that fact justifies.

The discriminators were calibrated before pinning (12 live runs, 6 per
world, all 12/12 unless noted):

- Both worlds: true_positive / high / escalate. A sustained brute force
  from a Tor exit against a production host is real and worth a human's
  attention even when it failed — "contained" is not "benign".
- Both worlds: the copilot composes the canonical pivot ITSELF —
  source.ip=<attacker> AND event.outcome=success — without being told
  log search exists for that. Asserted on the fake index's query log,
  not on prose.
- Compromised only: T1078 (Valid Accounts) joins the technique map. This
  mirrors the base harness exactly: brute_force_ssh.json FORBIDS T1078
  because no successful auth is observed there, with a comment saying to
  lift the forbid "if the fixture ever gains a successful auth". This
  world is that fixture, and the model makes the same distinction ATT&CK
  does — T1078 requires authenticating WITH the credentials.
- Compromised only: the response plan changes kind — an isolation/
  containment pivot appears (6/6 vs 0/6). Pinned only on the compromised
  side; absence in the contained world is observed but a "consider
  isolating as a precaution" would be defensible, so it is not forbidden.

Not pinned, deliberately: T1105 for the wget payload pull (5/6 — real
runs sometimes fold it into prose), and any phrasing of the hypothesis.

    uv run pytest tests/test_logsearch_eval.py -v
"""
import pytest

from soc_copilot.copilot import SOCCopilot
from soc_copilot.history import AlertHistoryStore
from soc_copilot.models import Investigation
from soc_copilot.tools.logsearch import SearchLogsTool
from soc_copilot.tools.registry import default_registry

from .alert_loading import SAMPLE_ALERTS_DIR, load_alert_fixture
from .fake_siem import ATTACKER_IP, FakeEventsIndex, compromised_index, contained_index

pytestmark = pytest.mark.live

WORLDS = ["compromised", "contained"]

CANONICAL_PIVOT = {"source.ip": ATTACKER_IP, "event.outcome": "success"}


def _composed_canonical_pivot(queries: list[list[tuple[str, str]]]) -> bool:
    """True iff some received query contains the canonical pivot AND is
    internally coherent. A query that repeats a field with two values
    (outcome=failure AND outcome=success) matches nothing under AND
    semantics, so it cannot count as having asked the discriminating
    question — even though its pairs superficially include the pivot."""
    for pairs in queries:
        fields = [f for f, _ in pairs]
        if len(set(fields)) != len(fields):
            continue
        if CANONICAL_PIVOT.items() <= dict(pairs).items():
            return True
    return False


@pytest.fixture(scope="module")
async def runs(tmp_path_factory) -> dict[str, tuple[Investigation, FakeEventsIndex]]:
    """One agentic investigation per world, cached for the module.

    Each world gets its own copilot: an isolated history store and a tool
    set whose log-search tool is bound to that world's index — so the only
    thing that varies between the two runs is the telemetry itself.
    """
    results: dict[str, tuple[Investigation, FakeEventsIndex]] = {}
    alert = load_alert_fixture(SAMPLE_ALERTS_DIR / "brute_force_ssh.json")
    for world, make_index in (
        ("compromised", compromised_index),
        ("contained", contained_index),
    ):
        index = make_index()
        tool = SearchLogsTool(
            url="https://fake-siem.test:9200",
            api_key="k",
            index="soc-events-demo",
            client=index.client(),
        )
        copilot = SOCCopilot(
            history_store=AlertHistoryStore(
                tmp_path_factory.mktemp(world) / "investigations.jsonl"
            ),
            tools=default_registry().replacing(tool),
        )
        results[world] = (await copilot.investigate_agentic(alert), index)
    return results


# --- invariants shared by both worlds ----------------------------------------


@pytest.mark.parametrize("world", WORLDS)
async def test_the_attack_is_real_in_both_worlds(world, runs):
    """847 attempts from a Tor exit is a true positive whether or not it
    landed — a failed attack is not a false alarm."""
    inv, _ = runs[world]
    assert inv.verdict == "true_positive", (
        f"[{world}] expected true_positive, got {inv.verdict}. "
        f"Hypothesis: {inv.hypothesis[:200]}"
    )
    assert inv.confidence == "high"
    assert inv.escalation_recommended is True


@pytest.mark.parametrize("world", WORLDS)
async def test_the_copilot_composes_the_canonical_pivot_itself(world, runs):
    """The tool's reason for existing, asserted at the query layer: without
    being told which query answers 'did it land?', the model must join the
    attacker IP with a success outcome. Checked against the queries the
    fake index actually received, not against prose about them."""
    _, index = runs[world]
    assert _composed_canonical_pivot(index.filters_used()), (
        f"[{world}] no coherent query joined source.ip={ATTACKER_IP} with "
        f"event.outcome=success; queries run: {index.filters_used()}"
    )


@pytest.mark.parametrize("world", WORLDS)
async def test_log_search_results_are_cited_as_evidence(world, runs):
    """Whatever the index answered — a smoking gun or a clean zero — the
    investigation must carry it as evidence. A zero-match answer is how
    the contained world's confidence is earned, not a nothing."""
    inv, _ = runs[world]
    cited = [e for e in inv.evidence if e.source_tool == "search_internal_logs"]
    assert cited, f"[{world}] no search_internal_logs evidence recorded"


# --- the differential: what the one changed fact must change -----------------


async def test_compromised_world_maps_valid_accounts(runs):
    """The successful root login is valid-account USE: T1078 must join the
    technique map. This is the same line the base harness draws from the
    other side — it forbids T1078 on this alert precisely because no
    success is observed there."""
    inv, _ = runs["compromised"]
    blob = " ".join(inv.attack_techniques)
    assert "T1078" in blob, (
        f"the accepted root login did not surface as T1078. "
        f"Techniques: {inv.attack_techniques}"
    )


async def test_contained_world_does_not_invent_the_success(runs):
    """Zero successes means brute force only: mapping T1078 here would be
    claiming an outcome the telemetry explicitly refutes — the exact
    hallucination the base harness's forbid was written against."""
    inv, _ = runs["contained"]
    blob = " ".join(inv.attack_techniques)
    assert "T1078" not in blob, (
        f"T1078 mapped with zero successful auths in the index. "
        f"Techniques: {inv.attack_techniques}"
    )


async def test_compromised_world_recommends_containment(runs):
    """A confirmed interactive root session changes the response plan in
    kind, not degree: some pivot must call for isolating/containing the
    host, which hardening advice alone does not."""
    inv, _ = runs["compromised"]
    blob = " ".join(
        f"{p.action} {p.rationale}" for p in inv.suggested_pivots
    ).lower()
    # "isolat"/"containment"/"quarantin" — never bare "contain", which the
    # ordinary verb in "the log contains ..." would satisfy (review catch).
    assert any(kw in blob for kw in ("isolat", "containment", "quarantin")), (
        f"no containment pivot for a confirmed compromise. "
        f"Pivots: {[p.action for p in inv.suggested_pivots]}"
    )

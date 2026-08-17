"""Unit tests for typed response actions (no API, no network).

    uv run pytest tests/test_actions.py -v

This is the one output shaped like a command, so most of what is pinned
here is what it REFUSES to propose: on anything but a confident true
positive, on an address a perimeter cannot reach, on infrastructure
AbuseIPDB itself whitelists, and on any investigation where something
tried to steer the triager.
"""
from datetime import datetime, timezone

import pytest

from soc_copilot.actions import (
    ABUSE_CONFIDENCE_BAR,
    propose_actions,
    render_actions,
)
from soc_copilot.models import (
    Alert,
    AssetMatch,
    Evidence,
    InjectionFlag,
    Investigation,
    PhishingAnalysis,
    PhishingSignal,
)

_T = datetime(2026, 8, 2, 11, 0, tzinfo=timezone.utc)
_TOR = "185.220.101.47"


def _alert(ips=(_TOR,), users=(), hashes=(), domains=(), apps=(),
           host="fin-app-02"):
    return Alert(
        alert_id="A-1", timestamp=_T, source="elastic", severity="high",
        title="RDP brute force from external source",
        raw_log={"host": host},
        indicators={
            "ips": list(ips), "users": list(users), "hashes": list(hashes),
            "domains": list(domains), "apps": list(apps),
        },
    )


def _ev(tool="abuseipdb_check", success=True, **data):
    return Evidence(
        source_tool=tool, claim="c", raw_data=data,
        confidence="high", success=success,
    )


def _rep(ip=_TOR, score=88, **extra):
    return _ev(ipAddress=ip, abuseConfidenceScore=score, totalReports=412, **extra)


def _inv(verdict="true_positive", confidence="high", evidence=(), techniques=(),
         assets=(), injection=(), phishing=None):
    return Investigation(
        alert_id="A-1", verdict=verdict, confidence=confidence, hypothesis="h",
        escalation_recommended=True, evidence=list(evidence),
        attack_techniques=list(techniques), asset_matches=list(assets),
        injection_flags=list(injection), phishing=phishing,
    )


def _kinds(actions):
    return [(a.action, a.target, a.status) for a in actions]


# --------------------------------------------------------------------
# the verdict gate
# --------------------------------------------------------------------

@pytest.mark.parametrize("verdict", ["false_positive", "inconclusive"])
def test_only_a_true_positive_proposes_anything(verdict):
    """'I am not sure' is a reason to look, never a reason to act."""
    assert propose_actions(_alert(), _inv(verdict=verdict, evidence=[_rep()])) == []


def test_a_low_confidence_true_positive_proposes_nothing():
    """The same sentence said differently."""
    assert propose_actions(
        _alert(), _inv(confidence="low", evidence=[_rep()])
    ) == []


def test_a_medium_confidence_true_positive_still_proposes():
    """Proposing is not executing. The high bar belongs to the gates that
    act by themselves (closure.py); a to-do list for a human does not
    need it, or the feature is dead on every alert worth having."""
    actions = propose_actions(_alert(), _inv(confidence="medium", evidence=[_rep()]))
    assert _kinds(actions) == [("block_ip", _TOR, "proposed")]


# --------------------------------------------------------------------
# reputation-grounded blocking, and the two refusals that matter more
# --------------------------------------------------------------------

def test_a_scored_external_address_is_proposed_with_its_number():
    [action] = propose_actions(_alert(), _inv(evidence=[_rep()]))
    assert (action.action, action.target, action.status) == (
        "block_ip", _TOR, "proposed",
    )
    assert action.basis == "reputation"
    assert "88/100" in action.rationale and "412 reports" in action.rationale
    assert action.evidence == ["abuseipdb_check"]


def test_below_the_bar_nothing_is_proposed():
    assert propose_actions(
        _alert(), _inv(evidence=[_rep(score=ABUSE_CONFIDENCE_BAR - 1)])
    ) == []


@pytest.mark.parametrize(
    "ip", ["10.0.0.5", "192.168.1.10", "172.16.4.4", "127.0.0.1", "169.254.1.1"]
)
def test_an_address_a_perimeter_cannot_reach_is_withheld(ip):
    """An RFC1918 entry in a blocklist either does nothing or takes out an
    internal range. Either way it is not the containment it looks like."""
    [action] = propose_actions(_alert(ips=[ip]), _inv(evidence=[_rep(ip=ip, score=90)]))
    assert action.status == "withheld"
    assert "not globally routable" in action.rationale
    assert "contain the host instead" in action.rationale


def test_whitelisted_infrastructure_is_withheld_however_high_it_scores():
    """AbuseIPDB whitelists the infrastructure that gets reported
    constantly and must never be blocked — public resolvers, CDN edges. A
    high score on one of those is the exact shape of a self-inflicted
    outage."""
    [action] = propose_actions(
        _alert(ips=["1.1.1.1"]),
        _inv(evidence=[_rep(ip="1.1.1.1", score=100, isWhitelisted=True)]),
    )
    assert action.status == "withheld"
    assert "whitelist" in action.rationale
    assert "outage of your own" in action.rationale


def test_a_target_the_alert_never_named_is_not_aimed_at():
    """On the agentic path the model chooses what to look up, and it can
    reach an entity it found inside a tool response. Untrusted content
    must not pick the target of a command."""
    assert propose_actions(
        _alert(ips=["203.0.113.9"]),          # what the alert is about
        _inv(evidence=[_rep(ip="8.8.8.8", score=95)]),   # what got looked up
    ) == []


def test_a_failed_lookup_grounds_nothing():
    """Evidence.success exists so the autonomous paths can tell 'I looked
    and found nothing' from 'I could not look'."""
    assert propose_actions(
        _alert(),
        _inv(evidence=[_ev(success=False, ipAddress=_TOR, abuseConfidenceScore=99)]),
    ) == []


def test_a_malicious_hash_and_domain_are_blocked_by_their_own_reputation():
    actions = propose_actions(
        _alert(ips=[], hashes=["abc123"], domains=["evil.test"]),
        _inv(evidence=[
            _ev(tool="virustotal_lookup", hash="abc123", found=True,
                malicious_count=44, total_engines=70),
            _ev(tool="urlscan_check", domain="evil.test", found=True,
                malicious_scan_count=3, scans_returned=4, total_scans=4),
        ]),
    )
    assert _kinds(actions) == [
        ("block_domain", "evil.test", "proposed"),
        ("block_hash", "abc123", "proposed"),
    ]


def test_a_hash_below_the_detection_ratio_is_not_blocked():
    assert propose_actions(
        _alert(ips=[], hashes=["abc123"]),
        _inv(evidence=[_ev(tool="virustotal_lookup", hash="abc123", found=True,
                           malicious_count=2, total_engines=70)]),
    ) == []


def test_an_unknown_hash_is_not_blocked():
    """`found: False` is a real answer — 'VirusTotal has never seen it' —
    and it is not grounds for a block."""
    assert propose_actions(
        _alert(ips=[], hashes=["abc123"]),
        _inv(evidence=[_ev(tool="virustotal_lookup", hash="abc123", found=False)]),
    ) == []


def _converted(tmp_path):
    """Evidence built by the REAL phase-one converters, so the action bar
    is tested against payloads the desk itself graded."""
    from soc_copilot.copilot import SOCCopilot
    from soc_copilot.history import AlertHistoryStore
    from soc_copilot.tools.base import ToolResult
    from soc_copilot.tools.registry import ToolRegistry

    c = SOCCopilot(
        history_store=AlertHistoryStore(tmp_path / "h.jsonl"), tools=ToolRegistry([]),
    )
    return (
        c._ip_result_to_evidence(
            ToolResult(tool_name="abuseipdb_check", success=True,
                       data={"ipAddress": _TOR, "abuseConfidenceScore": 75}), _TOR),
        c._hash_result_to_evidence(
            ToolResult(tool_name="virustotal_lookup", success=True,
                       data={"hash": "h1", "found": True, "malicious_count": 35,
                             "total_engines": 70}), "h1"),
        c._domain_result_to_evidence(
            ToolResult(tool_name="urlscan_check", success=True,
                       data={"domain": "d.test", "found": True,
                             "malicious_scan_count": 1, "scans_returned": 20,
                             "total_scans": 4000}), "d.test"),
    )


def test_the_ip_and_hash_bars_agree_with_the_desks_own_high_grade(tmp_path):
    """The thresholds here are read from the tool PAYLOAD, not from
    Evidence.confidence — the agentic path's generic converter hardcodes
    `medium`, so gating on the grade would make containment structurally
    impossible in one mode. That decoupling is only safe while the two
    agree, so this holds them together."""
    ip, file_hash, _ = _converted(tmp_path)
    assert ip.confidence == "high" and file_hash.confidence == "high"

    actions = propose_actions(
        _alert(ips=[_TOR], hashes=["h1"]), _inv(evidence=[ip, file_hash]))
    assert {a.action for a in actions} == {"block_ip", "block_hash"}
    assert all(a.status == "proposed" for a in actions)


def test_the_domain_bar_is_deliberately_stricter_than_that_grade(tmp_path):
    """One flagged page in a sample of twenty is a fine thing to show an
    analyst and a bad thing to aim a block with. The converter grades any
    non-zero count `high`; blocking needs a ratio, and this repo's own
    cassette is the argument — bit.ly and lucidchart.com both sit at
    10,000 scans, and lucidchart is the SANCTIONED app in the benign
    OAuth fixture."""
    _, _, domain = _converted(tmp_path)
    assert domain.confidence == "high"          # the desk still says high

    assert propose_actions(
        _alert(ips=[], domains=["d.test"]), _inv(evidence=[domain])
    ) == []


def test_a_widely_scanned_domain_needs_a_human_even_at_a_high_ratio():
    """The role isWhitelisted plays for addresses, from a weaker signal —
    so a caution rather than a refusal."""
    [action] = propose_actions(
        _alert(ips=[], domains=["bit.ly"]),
        _inv(evidence=[_ev(tool="urlscan_check", domain="bit.ly", found=True,
                           malicious_scan_count=18, scans_returned=20,
                           total_scans=10000)]),
    )
    assert action.status == "needs_approval"
    assert "shared infrastructure" in action.rationale
    assert "10000 scans" in action.rationale


def test_a_dedicated_domain_with_a_short_history_is_proposed():
    [action] = propose_actions(
        _alert(ips=[], domains=["evil.test"]),
        _inv(evidence=[_ev(tool="urlscan_check", domain="evil.test", found=True,
                           malicious_scan_count=2, scans_returned=3,
                           total_scans=3)]),
    )
    assert action.status == "proposed"


# --------------------------------------------------------------------
# technique-grounded actions
# --------------------------------------------------------------------

@pytest.mark.parametrize(
    "technique,expected",
    [
        ("T1486", "isolate_host"),
        ("T1059.001", "isolate_host"),      # matched on the parent
        ("T1053.005", "isolate_host"),
        ("T1078", "disable_account"),
        ("T1110.003", "reset_credentials"),
        ("T1003.001", "reset_credentials"),
    ],
)
def test_a_technique_family_implies_its_containment(technique, expected):
    actions = propose_actions(
        _alert(ips=[], users=["j.doe"]), _inv(techniques=[technique])
    )
    assert expected in {a.action for a in actions}
    assert all(a.basis == "technique" for a in actions)


def test_a_technique_action_names_the_technique_that_justified_it():
    [action] = propose_actions(_alert(ips=[]), _inv(techniques=["T1486"]))
    assert action.action == "isolate_host"
    assert action.target == "fin-app-02"
    assert "T1486" in action.rationale


def test_no_mapped_technique_proposes_no_technique_action():
    assert propose_actions(_alert(ips=[], users=["j.doe"]), _inv()) == []


def test_an_oauth_grant_is_revoked_on_the_app_not_the_user():
    [action] = propose_actions(
        _alert(ips=[], apps=["a1b2-app-guid"], host=None),
        _inv(techniques=["T1528"]),
    )
    assert (action.action, action.target) == ("revoke_oauth_grant", "a1b2-app-guid")


# --------------------------------------------------------------------
# the operator's inventory slows an action down; it never starts one
# --------------------------------------------------------------------

def test_an_inventoried_target_needs_its_owner_not_silence():
    """The scanner box is exactly the machine an attacker wants to be
    standing on, so an inventory hit must not delete the action. It
    attaches the owner and makes it a conversation."""
    [action] = propose_actions(
        _alert(ips=[], host="scanner-01"),
        _inv(techniques=["T1059"], assets=[AssetMatch(
            entity="10.0.0.5", entity_type="ip", name="scanner-01",
            role="authorized vulnerability scanner", owner="secops@corp",
        )]),
    )
    assert action.status == "needs_approval"
    assert action.owner == "secops@corp"
    assert action.inventory_role == "authorized vulnerability scanner"
    assert "authorized vulnerability scanner" in action.rationale


def test_the_inventory_is_matched_on_the_observed_entity_too():
    [action] = propose_actions(
        _alert(ips=["10.0.0.5"]),
        _inv(evidence=[_rep(ip="10.0.0.5", score=90)], assets=[AssetMatch(
            entity="10.0.0.5", entity_type="ip", name="scanner-01", role="scanner",
        )]),
    )
    # Still withheld — a private address is unreachable whoever owns it,
    # and the harder refusal wins.
    assert action.status == "withheld"


def test_an_uninventoried_target_carries_no_owner():
    [action] = propose_actions(_alert(ips=[]), _inv(techniques=["T1486"]))
    assert action.status == "proposed"
    assert action.owner is None and action.inventory_role is None


# --------------------------------------------------------------------
# injection: the sharpest version of the attack
# --------------------------------------------------------------------

def test_injection_withholds_everything_and_says_what_it_withheld():
    """An attacker who can talk the desk into `block_ip` on a payment
    gateway has a denial-of-service primitive aimed at the defender and
    executed by the defender."""
    actions = propose_actions(
        _alert(users=["j.doe"]),
        _inv(evidence=[_rep()], techniques=["T1078"], injection=[
            InjectionFlag(location="raw_log.notes", pattern="p", excerpt="e")
        ]),
    )
    assert actions, "the suppression must be visible, not silent"
    assert all(a.status == "withheld" for a in actions)
    assert {a.action for a in actions} == {"block_ip", "disable_account"}
    for action in actions:
        assert "prompt-injection" in action.rationale
        assert "raw_log.notes" in action.rationale
        # ...and what it WOULD have been, so the operator can judge it.
        assert "would otherwise have been proposed" in action.rationale


def test_injection_on_an_alert_with_nothing_to_contain_invents_nothing():
    assert propose_actions(
        _alert(ips=[]),
        _inv(injection=[InjectionFlag(location="x", pattern="p", excerpt="e")]),
    ) == []


# --------------------------------------------------------------------
# analysis-grounded, dedupe, ordering, rendering
# --------------------------------------------------------------------

def _phish(*strengths):
    return PhishingAnalysis(
        header_from="no-reply@evil.example",
        signals=[
            PhishingSignal(name=f"s{i}", strength=s, fact="f")
            for i, s in enumerate(strengths)
        ],
    )


def test_a_strongly_graded_phish_proposes_quarantine():
    [action] = propose_actions(
        _alert(ips=[], host=None), _inv(phishing=_phish("strong", "weak"))
    )
    assert (action.action, action.target) == (
        "quarantine_email", "no-reply@evil.example",
    )
    assert action.basis == "analysis"


def test_weak_signals_alone_propose_nothing():
    """The channel is not the verdict — the same discipline the benign
    twin fixtures exist to enforce."""
    assert propose_actions(
        _alert(ips=[], host=None), _inv(phishing=_phish("weak", "moderate"))
    ) == []


def test_one_entry_per_action_and_target_with_the_live_one_winning():
    actions = propose_actions(
        _alert(), _inv(evidence=[_rep(), _rep(score=99)]),
    )
    assert len(actions) == 1 and actions[0].status == "proposed"


def test_the_order_is_stable_and_puts_live_actions_first():
    actions = propose_actions(
        _alert(ips=[_TOR, "10.0.0.5"], users=["j.doe"]),
        _inv(evidence=[_rep(), _rep(ip="10.0.0.5", score=90)],
             techniques=["T1078"]),
    )
    statuses = [a.status for a in actions]
    assert statuses == sorted(statuses, key=["proposed", "needs_approval",
                                             "withheld"].index)
    assert _kinds(actions) == _kinds(propose_actions(
        _alert(ips=[_TOR, "10.0.0.5"], users=["j.doe"]),
        _inv(evidence=[_rep(), _rep(ip="10.0.0.5", score=90)],
             techniques=["T1078"]),
    ))


def test_nothing_to_contain_renders_nothing_at_all():
    assert render_actions([]) == ""


def test_the_rendering_marks_approval_and_refusal():
    rendered = render_actions(propose_actions(
        _alert(ips=["10.0.0.5"], host="scanner-01"),
        _inv(evidence=[_rep(ip="10.0.0.5", score=90)], techniques=["T1059"],
             assets=[AssetMatch(entity="scanner-01", entity_type="host",
                                name="scanner-01", role="scanner",
                                owner="secops@corp")]),
    ))
    assert "nothing here is executed" in rendered
    assert "[NEEDS OWNER APPROVAL]" in rendered
    assert "owner: secops@corp" in rendered
    assert "WITHHELD block_ip 10.0.0.5" in rendered


# --------------------------------------------------------------------
# what the adversarial review found
# --------------------------------------------------------------------

def test_an_already_refused_action_keeps_its_own_reason_under_injection():
    """The inversion four lenses found — and it was introduced by the fix
    that added the injection branch. Rewriting EVERY entry meant a
    whitelisted CDN's refusal came back as "it would otherwise have been
    proposed because <the refusal text>": the desk's own veto read back
    to the operator as an endorsement."""
    actions = propose_actions(
        _alert(ips=["1.1.1.1"]),
        _inv(evidence=[_rep(ip="1.1.1.1", score=100, isWhitelisted=True)],
             injection=[InjectionFlag(location="raw_log.notes", pattern="p",
                                      excerpt="e")]),
    )
    [action] = actions
    assert action.status == "withheld"
    assert "would otherwise have been proposed" not in action.rationale
    assert "whitelist" in action.rationale       # its own reason survives


def test_injection_still_withholds_an_action_that_had_been_proposed():
    """...while the branch keeps doing its job on the entries that WERE
    going to stand."""
    [action] = propose_actions(
        _alert(),
        _inv(evidence=[_rep()], injection=[
            InjectionFlag(location="raw_log.notes", pattern="p", excerpt="e")]),
    )
    assert action.status == "withheld"
    assert "would otherwise have been proposed" in action.rationale


@pytest.mark.parametrize(
    "principal",
    ["SYSTEM", "system", "NT AUTHORITY\\SYSTEM", "LOCAL SERVICE",
     "NETWORK SERVICE", "ANONYMOUS LOGON"],
)
def test_a_local_system_authority_is_never_disabled(principal):
    """`user.name` on a Windows scheduled-task or service event is
    routinely SYSTEM — this is the ordinary content of an alert, not an
    edge case."""
    [action] = propose_actions(
        _alert(ips=[], users=[principal], host=None), _inv(techniques=["T1078"])
    )
    assert action.status == "withheld"
    assert "local system authority" in action.rationale


def test_a_machine_account_is_never_disabled():
    [action] = propose_actions(
        _alert(ips=[], users=["WIN-FIN-07$"], host=None),
        _inv(techniques=["T1078"]),
    )
    assert action.status == "withheld"
    assert "removes the computer from the domain" in action.rationale


def test_a_spray_is_not_aimed_at_every_account_it_named():
    """A password spray names every username it tried. Disabling all of
    them is precisely the outage the spray was hoping for, and the desk
    cannot tell which one actually authenticated."""
    users = [f"u{i}" for i in range(9)]
    actions = propose_actions(
        _alert(ips=[], users=users, host=None), _inv(techniques=["T1110"])
    )
    assert len(actions) == len(users)
    assert all(a.status == "withheld" for a in actions)
    assert "spray rather than a compromised identity" in actions[0].rationale


def test_a_handful_of_accounts_is_still_aimed_at():
    actions = propose_actions(
        _alert(ips=[], users=["a", "b"], host=None), _inv(techniques=["T1110"])
    )
    assert [a.status for a in actions] == ["proposed", "proposed"]


def _phish_auth(aligned: bool, header_from="finance@corp.example"):
    """A strongly-graded analysis where authentication either aligns with
    the From: address or does not."""
    return PhishingAnalysis(
        header_from=header_from,
        envelope_from="mail.relay.example",
        spf_result="pass" if aligned else "fail",
        spf_aligned=aligned,
        dmarc_result="pass" if aligned else "fail",
        signals=[PhishingSignal(name="dmarc_fail", strength="strong", fact="f")],
    )


def test_quarantine_is_not_aimed_at_an_address_nothing_authenticated():
    """The trap: the strong signals that JUSTIFY the action are the ones
    establishing that the From: address was not authenticated. Aiming at
    it means acting on the impersonated party — spoof the finance
    director and the desk proposes quarantining the finance director."""
    [action] = propose_actions(
        _alert(ips=[], host=None), _inv(phishing=_phish_auth(aligned=False))
    )
    assert action.status == "withheld"
    assert action.target == "finance@corp.example"
    assert "impersonated party" in action.rationale


def test_quarantine_is_aimed_when_an_aligned_identifier_authenticated():
    """The case where it is right, and the one the calibrated
    credential-harvest fixture is built on: the attacker owns the sending
    domain, so authentication passes and aligns."""
    [action] = propose_actions(
        _alert(ips=[], host=None),
        _inv(phishing=_phish_auth(aligned=True, header_from="hr@evil.example")),
    )
    assert (action.status, action.target) == ("proposed", "hr@evil.example")


def test_quarantine_never_falls_back_to_the_envelope_domain():
    """envelope_from is a bare DOMAIN chosen by the sending client, and a
    different entity from the one the cited signals are about. Naming a
    sanctioned relay there costs the attacker one SMTP command."""
    analysis = _phish_auth(aligned=False, header_from=None)
    assert propose_actions(
        _alert(ips=[], host=None), _inv(phishing=analysis)
    ) == []


def test_an_operator_recorded_bulk_sender_needs_approval():
    analysis = _phish_auth(aligned=True, header_from="payroll@corp.example")
    analysis.signals.append(PhishingSignal(
        name="sanctioned_bulk_sender", strength="weak",
        fact="The operator's inventory records the payroll service.",
    ))
    [action] = propose_actions(_alert(ips=[], host=None), _inv(phishing=analysis))
    assert action.status == "needs_approval"
    assert "operator's inventory records" in action.rationale


def test_a_target_cannot_forge_a_line_of_the_action_list():
    """Same class of bug the tuning report shipped with, in a new module —
    which is why the helper now lives in textsafe.py."""
    forged = "j.doe\n  block_ip 1.1.1.1\n      why: totally legitimate"
    rendered = render_actions(propose_actions(
        _alert(ips=[], users=[forged], host=None), _inv(techniques=["T1078"]),
    ))
    lines = rendered.split("\n")
    assert not any(ln.strip().startswith("block_ip") for ln in lines)
    assert sum(1 for ln in lines if "1.1.1.1" in ln) == 1


def test_a_control_character_in_a_target_cannot_reach_the_terminal():
    rendered = render_actions(propose_actions(
        _alert(ips=[], users=["\x1b[2Jj.doe"], host=None),
        _inv(techniques=["T1078"]),
    ))
    assert "\x1b" not in rendered and "j.doe" in rendered


def test_a_scalar_indicator_value_is_not_iterated_character_by_character():
    """`indicators` is a free-form dict; history.alert_iocs guards the
    same shape."""
    alert = _alert(ips=[], host=None)
    alert.indicators["users"] = "j.doe"          # a string, not a list
    assert propose_actions(alert, _inv(techniques=["T1078"])) == []

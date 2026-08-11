"""Unit tests for the deterministic phishing analyzer (API-free, no network).

The analyzer's value is that its facts are correct, so the semantics get
tested directly: alignment computed rather than echoed, dmarc=none kept
distinct from dmarc=fail, the real Authentication-Results shapes that
Microsoft 365 and Gmail actually emit, and — just as important — the
signals it deliberately does NOT raise, because a detection that fires on
every email service provider is one an analyst mutes.

    uv run pytest tests/test_phishing.py -v
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from soc_copilot.models import Alert
from soc_copilot.phishing import (
    analyze_phishing,
    org_domain,
    parse_authentication_results,
)

from .alert_loading import SAMPLE_ALERTS_DIR, load_alert_fixture

_T = datetime(2026, 5, 14, 8, 0, tzinfo=timezone.utc)

# Real Authentication-Results shapes, as the platforms actually emit them.
M365_AR = (
    "spf=pass (sender IP is 10.2.3.4) smtp.mailfrom=fabrikam.com; "
    "contoso.com; dkim=pass (signature was verified) header.d=fabrikam.com; "
    "contoso.com; dmarc=pass action=none header.from=fabrikam.com; "
    "compauth=pass reason=100"
)
GMAIL_AR = (
    "mx.google.com; dkim=pass header.i=@klaviyo.com header.s=s1 "
    "header.b=kBByyR4j; spf=pass (google.com: domain of "
    "bounces+27486840-770f-email=klaviyo.com@send.klaviyo.com designates "
    "198.51.100.7 as permitted sender) "
    'smtp.mailfrom="bounces+27486840-770f-email=klaviyo.com@send.klaviyo.com"; '
    "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=klaviyo.com"
)


def _alert(headers: dict, **raw_extra) -> Alert:
    return Alert(
        alert_id="P-1", timestamp=_T, source="email_gateway", severity="medium",
        title="mail", raw_log={"headers": headers, **raw_extra},
        indicators={"users": ["e.varga"]},
    )


def _signals(alert: Alert) -> dict[str, str]:
    result = analyze_phishing(alert)
    return {s.name: s.strength for s in result.signals}


# --- organizational domain (what alignment is computed over) -----------------


def test_org_domain_handles_subdomains_and_multi_label_suffixes():
    assert org_domain("send.klaviyo.com") == "klaviyo.com"
    assert org_domain("o3.em.sg-relay.example") == "sg-relay.example"
    assert org_domain("mail.example.co.uk") == "example.co.uk"
    assert org_domain("example.co.uk") == "example.co.uk"
    assert org_domain("brand.com") == "brand.com"


# --- Authentication-Results parsing -----------------------------------------


def test_parses_microsoft_repeated_authserv_id():
    """M365 repeats the authserv-id before each method, which violates the
    RFC 8601 ABNF — a naive split(';') turns those into junk results."""
    auth = parse_authentication_results(M365_AR)
    assert auth["spf"] == [{"result": "pass", "smtp.mailfrom": "fabrikam.com"}]
    assert auth["dkim"][0]["result"] == "pass"
    assert auth["dkim"][0]["header.d"] == "fabrikam.com"
    assert auth["dmarc"][0]["result"] == "pass"
    assert auth["dmarc"][0]["header.from"] == "fabrikam.com"
    assert auth["compauth"][0]["reason"] == "100"


def test_parses_gmail_quoted_values_and_parenthetical_comments():
    """Gmail quotes pvalues containing specials, puts policy in a comment,
    and reports DKIM via header.i rather than header.d."""
    auth = parse_authentication_results(GMAIL_AR)
    assert auth["dkim"][0]["result"] == "pass"
    assert auth["dkim"][0]["header.i"] == "@klaviyo.com"
    assert auth["spf"][0]["result"] == "pass"
    assert "send.klaviyo.com" in auth["spf"][0]["smtp.mailfrom"]
    assert auth["dmarc"][0]["result"] == "pass"


def test_each_dkim_signature_keeps_its_own_identifier():
    """Review catch, found independently by three reviewers: merging the
    signatures attached one signature's PASS to another signature's d=,
    which fabricates alignment in exactly the case that matters — where
    the signature that aligns is the one that failed."""
    auth = parse_authentication_results(
        "mx; dkim=pass header.d=esp.example; dkim=fail header.d=brand.example"
    )
    assert [(s["result"], s["header.d"]) for s in auth["dkim"]] == [
        ("pass", "esp.example"), ("fail", "brand.example")
    ]


def test_alignment_never_borrows_a_failing_signatures_domain():
    """The end-to-end consequence: an ESP-signed message whose brand
    signature FAILED must not report DKIM as aligned to the brand."""
    result = analyze_phishing(_alert({
        "From": "<billing@paypal.example>",
        "Authentication-Results": (
            "mx; dkim=pass header.i=@mailer-esp.example; "
            "dkim=fail header.i=@paypal.example; "
            "spf=pass smtp.mailfrom=bounce@mailer-esp.example; "
            "dmarc=fail header.from=paypal.example"
        ),
    }))
    assert result.dkim_aligned is not True
    # And the strong signal the merge used to suppress is present.
    assert "no_aligned_authentication" in {s.name for s in result.signals}


def test_clause_order_does_not_decide_alignment():
    """The same message with its signatures listed in either order must
    produce the same verdict — order-dependence was the tell that the
    merge was wrong."""
    def analyze(order):
        return analyze_phishing(_alert({
            "From": "<a@brand.example>",
            "Authentication-Results": "mx; " + "; ".join(order),
        })).dkim_aligned

    a = "dkim=pass header.d=esp.example"
    b = "dkim=fail header.d=brand.example"
    assert analyze([a, b]) == analyze([b, a])


# --- alignment is computed, not echoed --------------------------------------


def test_esp_envelope_is_unaligned_but_aligned_dkim_carries_dmarc():
    """The teaching case: a legitimate ESP bounces through its own domain
    (SPF unaligned) while signing with the customer's (DKIM aligned). DMARC
    needs only one aligned pass, so nothing here is wrong — and a tool that
    flagged the envelope mismatch would be wrong about every ESP."""
    result = analyze_phishing(_alert({
        "From": '"Payroll" <no-reply@corp-payroll.example>',
        "Authentication-Results": (
            "mx; spf=pass smtp.mailfrom=mail.sg-relay.example; "
            "dkim=pass header.d=corp-payroll.example; "
            "dmarc=pass header.from=corp-payroll.example"
        ),
    }))
    assert result.spf_aligned is False
    assert result.dkim_aligned is True
    assert "no_aligned_authentication" not in {s.name for s in result.signals}


def test_authenticated_but_unaligned_is_the_classic_spoof():
    """SPF and DKIM both pass — for the attacker's own domain. Nothing
    vouched for the From: the recipient sees."""
    signals = _signals(_alert({
        "From": '"CEO" <ceo@target.example>',
        "Authentication-Results": (
            "mx; spf=pass smtp.mailfrom=bounce@evil-mailer.example; "
            "dkim=pass header.d=evil-mailer.example; "
            "dmarc=fail header.from=target.example"
        ),
    }))
    assert signals["no_aligned_authentication"] == "strong"
    assert signals["dmarc_fail"] == "strong"


def test_alignment_is_relaxed_by_default_so_subdomains_align():
    result = analyze_phishing(_alert({
        "From": "<news@brand.example>",
        "Authentication-Results": (
            "mx; spf=pass smtp.mailfrom=bounces.brand.example; "
            "dkim=pass header.d=mail.brand.example; "
            "dmarc=pass header.from=brand.example"
        ),
    }))
    assert result.spf_aligned is True and result.dkim_aligned is True


# --- dmarc=none is not dmarc=fail -------------------------------------------


def test_dmarc_none_is_reported_as_absent_policy_not_a_failure():
    """Conflating 'publishes no policy' with 'authentication failed' is the
    most common amateur error in tools like this."""
    result = analyze_phishing(_alert({
        "From": "<a@nopolicy.example>",
        "Authentication-Results": (
            "mx; spf=pass smtp.mailfrom=nopolicy.example; "
            "dkim=pass header.d=nopolicy.example; "
            "dmarc=none header.from=nopolicy.example"
        ),
    }))
    names = {s.name: s for s in result.signals}
    assert "dmarc_fail" not in names
    assert names["dmarc_no_policy"].strength == "moderate"
    assert "NOT an authentication failure" in names["dmarc_no_policy"].fact


def test_bestguesspass_is_not_rendered_as_a_dmarc_pass():
    result = analyze_phishing(_alert({
        "From": "<a@nopolicy.example>",
        "Authentication-Results": (
            "mx; spf=pass smtp.mailfrom=nopolicy.example; "
            "dmarc=bestguesspass header.from=nopolicy.example"
        ),
    }))
    assert result.dmarc_result == "bestguesspass"
    assert "dmarc_best_guess" in {s.name for s in result.signals}


def test_arc_chain_is_surfaced_as_the_benign_explanation_of_a_failure():
    """Forwarding and mailing lists are the dominant benign cause of DMARC
    failure; flagging one without checking ARC false-positives on every
    forwarded message."""
    result = analyze_phishing(_alert({
        "From": "<a@brand.example>",
        "Authentication-Results": "mx; dmarc=fail header.from=brand.example",
        "ARC-Authentication-Results": "i=1; mx; arc=pass",
    }))
    assert result.arc_present is True
    fact = next(s.fact for s in result.signals if s.name == "dmarc_fail")
    # Reported as CLAIMED, not verified: this analyzer has neither the
    # sealer's key nor a trust list, and the header is attacker-writable.
    assert "CLAIMED" in fact and "unverified" in fact


# --- header signals ----------------------------------------------------------


def test_reply_to_on_free_mail_is_the_bec_tell():
    """MODERATE, not strong: contact-form relays, scheduling tools and
    recruiting mail legitimately route replies to a consumer mailbox, so
    this is decisive only in combination (review catch)."""
    signals = _signals(_alert({
        "From": '"Finance" <ap@supplier.example>',
        "Reply-To": "<supplier.invoices@gmail.com>",
    }))
    assert signals["reply_to_free_mail"] == "moderate"


def test_reply_to_elsewhere_in_the_same_org_is_not_a_signal():
    assert "reply_to_other_domain" not in _signals(_alert({
        "From": "<no-reply@corp-payroll.example>",
        "Reply-To": "<support@mail.corp-payroll.example>",
    }))


def test_display_name_hiding_a_different_address():
    """MODERATE: helpdesk and 'via' senders legitimately put another
    party's address in the display name (review catch)."""
    result = analyze_phishing(_alert({
        "From": '"billing@trusted.example" <attacker@evil.example>',
    }))
    sig = next(
        s for s in result.signals
        if s.name == "display_name_contains_other_address"
    )
    assert sig.strength == "moderate" and sig.benign_cause


def test_brand_display_name_from_an_authorized_domain_is_not_flagged():
    """'Alice via DocuSign' <dse@docusign.net> is legitimate mail, and a
    brand-name heuristic without an ownership map flags it."""
    assert "display_name_brand_mismatch" not in _signals(_alert({
        "From": '"Alice via DocuSign" <dse@docusign.net>',
    }))


def test_brand_display_name_from_an_unauthorized_domain_is_flagged():
    signals = _signals(_alert({
        "From": '"Microsoft 365 Security" <security@ms-verify.example>',
    }))
    assert signals["display_name_brand_mismatch"] == "moderate"


def test_multiple_from_headers_are_parser_differential_spoofing():
    signals = _signals(_alert({
        "From": ["<real@brand.example>", "<fake@evil.example>"],
    }))
    assert signals["multiple_from_headers"] == "strong"


# --- URL signals -------------------------------------------------------------


def test_brand_in_subdomain_names_the_domain_that_actually_owns_the_site():
    result = analyze_phishing(_alert(
        {"From": "<a@evil.example>"},
        links=[{"href": "https://login-microsoftonline.verify-session.app/auth"}],
    ))
    sig = next(s for s in result.signals if s.name == "brand_in_subdomain")
    assert sig.strength == "strong"
    assert "verify-session.app" in sig.fact


def test_userinfo_authority_trick_is_flagged():
    result = analyze_phishing(_alert(
        {"From": "<a@evil.example>"},
        links=[{"href": "https://microsoft.com@evil-host.example/login"}],
    ))
    names = {s.name for s in result.signals}
    assert "url_userinfo_authority" in names
    # The host is the part after '@' — the analyzer must not be fooled either.
    assert "evil-host.example" in next(
        s.fact for s in result.signals if s.name == "url_userinfo_authority"
    )


def test_punycode_host_is_flagged():
    result = analyze_phishing(_alert(
        {"From": "<a@evil.example>"},
        links=[{"href": "https://xn--micrsoft-9db.example/login"}],
    ))
    assert "punycode_domain" in {s.name for s in result.signals}


def test_recipient_address_in_the_fragment_is_kit_prefill():
    result = analyze_phishing(_alert(
        {"From": "<a@evil.example>"},
        links=[{"href": "https://x.example/login#e.varga@corp.example"}],
    ))
    assert "recipient_in_url_fragment" in {s.name for s in result.signals}


def test_a_link_to_another_domain_is_not_by_itself_a_signal():
    """Almost every legitimate bulk message links to a click tracker on a
    domain unrelated to the sender. Flagging that is how a phishing
    detection becomes noise."""
    names = _signals(_alert(
        {"From": "<news@brand.example>"},
        links=[{"href": "https://click.tracker.example/ls/click?upn=abc"}],
    ))
    assert names == {} or set(names) <= {"url_shortener", "credential_harvest_path"}


def test_shortener_is_weak_and_says_why():
    result = analyze_phishing(_alert(
        {"From": "<a@brand.example>"},
        links=[{"href": "https://bit.ly/3abcdef"}],
    ))
    sig = next(s for s in result.signals if s.name == "url_shortener")
    assert sig.strength == "weak"
    assert "not inspectable" in sig.fact


# --- received chain ----------------------------------------------------------


def test_non_monotonic_trace_is_flagged():
    signals = _signals(_alert({
        "From": "<a@brand.example>",
        "Received": [
            "from mx by mbx with SMTP id 1; Thu, 14 May 2026 08:26:39 +0000",
            "from evil by mx with SMTP id 2; Thu, 14 May 2026 09:10:00 +0000",
        ],
    }))
    assert signals["received_chain_non_monotonic"] == "strong"


def test_a_long_but_ordered_chain_is_not_flagged():
    """Hop count and private IPs are normal in real mail; only a genuine
    time inversion is evidence."""
    hops = [
        "from a (10.0.0.5) by b with SMTP id 5; Thu, 14 May 2026 08:26:39 +0000",
        "from c (10.0.0.4) by a with SMTP id 4; Thu, 14 May 2026 08:26:35 +0000",
        "from d (10.0.0.3) by c with SMTP id 3; Thu, 14 May 2026 08:26:30 +0000",
        "from e (203.0.113.9) by d with SMTP id 2; Thu, 14 May 2026 08:26:20 +0000",
    ]
    assert "received_chain_non_monotonic" not in _signals(_alert({
        "From": "<a@brand.example>", "Received": hops,
    }))


def test_timezone_offsets_are_normalized_before_comparison():
    """Comparing wall-clock strings across offsets invents inversions."""
    hops = [
        "from a by b with SMTP id 2; Thu, 14 May 2026 09:26:39 +0100",
        "from c by a with SMTP id 1; Thu, 14 May 2026 08:26:30 +0000",
    ]
    assert "received_chain_non_monotonic" not in _signals(_alert({
        "From": "<a@brand.example>", "Received": hops,
    }))


# --- grounding and blast radius ---------------------------------------------


def test_alerts_without_email_material_are_not_analyzed():
    """None means 'no email to analyze', which is different from 'clean'.
    It is also what keeps this enricher from perturbing every other alert
    family's prompt — and therefore their calibrated expectations."""
    plain = Alert(
        alert_id="X", timestamp=_T, source="edr", severity="high",
        title="t", raw_log={"process": "cmd.exe"}, indicators={},
    )
    assert analyze_phishing(plain) is None


def test_only_the_new_phishing_family_is_analyzed_across_the_corpus():
    """A hard guard on the property above: adding this analyzer must leave
    every previously-calibrated fixture's prompt byte-for-byte unchanged.
    phishing_attachment.json carries an 'email_sender' string but no
    headers, and must stay unanalyzed."""
    analyzed = {
        p.name for p in sorted(Path(SAMPLE_ALERTS_DIR).glob("*.json"))
        if analyze_phishing(load_alert_fixture(p)) is not None
    }
    assert analyzed == {
        "phishing_credential_harvest.json",
        "benign_payroll_bulk_mail.json",
    }


def test_every_signal_carries_a_fact_and_weak_ones_carry_a_benign_cause():
    """The contract that keeps the model honest: a fact with its identifier
    attached, and for anything short of decisive, the legitimate pattern
    that also produces it."""
    for fixture in ("phishing_credential_harvest.json",
                    "benign_payroll_bulk_mail.json"):
        result = analyze_phishing(load_alert_fixture(SAMPLE_ALERTS_DIR / fixture))
        assert result.signals, fixture
        for s in result.signals:
            assert s.fact.strip(), (fixture, s.name)
            if s.strength in ("weak", "moderate") and s.name != "sanctioned_bulk_sender":
                assert s.benign_cause, (fixture, s.name)


def test_missing_reference_data_degrades_instead_of_raising(tmp_path):
    """Reference data is operator-owned and may be absent; the
    authentication analysis is still worth having without it."""
    result = analyze_phishing(
        _alert({
            "From": '"Microsoft" <x@evil.example>',
            "Authentication-Results": "mx; dmarc=fail header.from=evil.example",
        }),
        brands_path=tmp_path / "missing.json",
    )
    assert result is not None
    assert "dmarc_fail" in {s.name for s in result.signals}
    # No brand data means no brand claim can be adjudicated.
    assert "display_name_brand_mismatch" not in {s.name for s in result.signals}


# --- the fixture pair discriminates -----------------------------------------


def test_the_attack_passes_authentication_yet_raises_strong_signals():
    """The point of the attack fixture: DMARC pass is not safety. The
    attacker owns the lookalike domain and configured it correctly."""
    result = analyze_phishing(
        load_alert_fixture(SAMPLE_ALERTS_DIR / "phishing_credential_harvest.json")
    )
    assert result.dmarc_result == "pass"
    assert result.spf_aligned is True and result.dkim_aligned is True
    strong = {s.name for s in result.signals if s.strength == "strong"}
    assert {"brand_in_subdomain", "recipient_in_url_fragment"} <= strong
    # ...plus the corroborating moderates that make the case.
    moderate = {s.name for s in result.signals if s.strength == "moderate"}
    assert {"reply_to_free_mail", "display_name_brand_mismatch"} <= moderate


def test_the_benign_twin_raises_nothing_stronger_than_weak():
    """It trips the same surface — unaligned envelope, foreign link domain,
    shortener, /login path — and every one resolves to weak."""
    result = analyze_phishing(
        load_alert_fixture(SAMPLE_ALERTS_DIR / "benign_payroll_bulk_mail.json")
    )
    assert result.spf_aligned is False   # the thing naive tools flag
    assert result.dkim_aligned is True   # and the thing that actually matters
    assert {s.strength for s in result.signals} == {"weak"}
    assert "sanctioned_bulk_sender" in {s.name for s in result.signals}


# --- review regressions: the analyzer must never crash an investigation --


def test_mixed_timezone_trace_does_not_raise():
    """RFC 5322 '-0000' means 'offset unknown' and CPython returns a NAIVE
    datetime for it while '+0000' returns an aware one. Comparing the two
    raised TypeError straight out of the analyzer and killed the whole
    investigation — for a chain shape qmail and several mail appliances
    produce routinely (review catch)."""
    for hops in (
        ["from a by b; Thu, 14 May 2026 08:26:39 +0000",
         "from c by a; Thu, 14 May 2026 08:26:30 -0000"],
        ["from a by b; Thu, 14 May 2026 08:26:39 -0000",
         "from c by a; Thu, 14 May 2026 08:26:30 +0000"],
        ["from a by b; Thu, 14 May 2026 08:26:39 +0000",
         "from c by a; Thu, 14 May 2026 08:26:30"],          # zoneless
    ):
        result = analyze_phishing(_alert({
            "From": "<a@brand.example>", "Received": hops,
        }))
        assert result is not None
        assert "received_chain_non_monotonic" not in {
            s.name for s in result.signals
        }


def test_seconds_of_clock_skew_is_not_a_forgery_signal():
    """One second of ordinary NTP drift raised a STRONG signal whose own
    benign_cause claimed that could not happen (review catch)."""
    hops = [
        "from a by b; Thu, 14 May 2026 08:26:30 +0000",
        "from c by a; Thu, 14 May 2026 08:26:31 +0000",   # 1s inversion
    ]
    assert "received_chain_non_monotonic" not in _signals(_alert({
        "From": "<a@brand.example>", "Received": hops,
    }))


def test_non_string_header_values_do_not_raise():
    """Header containers arrive from whatever the source system
    serialized; a dict or int where a string belongs must degrade, not
    raise (review catch: a nested-dict Authentication-Results crashed the
    investigation)."""
    for headers in (
        {"From": "<a@b.example>", "Authentication-Results": {"spf": "pass"}},
        {"From": "<a@b.example>", "Authentication-Results": 42},
        {"From": 7, "Authentication-Results": "mx; spf=pass"},
        {"From": "<a@b.example>", "Received": "not-a-list"},
        {"From": "<a@b.example>", "Received": [None, 5, {"x": 1}]},
        {"From": [], "Authentication-Results": None},
        {"From": {"nested": "dict"}, "Reply-To": ["<x@y.example>"]},
    ):
        result = analyze_phishing(_alert(headers))
        assert result is None or result.signals is not None


def test_enormous_header_does_not_hang():
    """A long run of word characters is quadratic for the address regex;
    headers are bounded so enrichment cannot hang an investigation."""
    import time

    start = time.monotonic()
    analyze_phishing(_alert({"From": '"' + "a" * 200_000 + '" <x@y.example>'}))
    assert time.monotonic() - start < 2.0


def test_many_urls_are_bounded():
    links = [{"href": f"https://h{i}.example/login"} for i in range(5000)]
    result = analyze_phishing(_alert({"From": "<a@b.example>"}, links=links))
    assert len(result.urls_examined) <= 200


# --- review regressions: false-positive surface --------------------------


def test_short_brand_tokens_do_not_match_inside_ordinary_words():
    """'ups' is inside 'groups', 'backups' and 'signups' — substring
    matching fired STRONG brand_in_subdomain on groups.google.com."""
    for host in ("groups.google.com", "backups.corp.example",
                 "signups.marketing.example"):
        names = {
            s.name for s in analyze_phishing(
                _alert({"From": "<a@corp.example>"},
                       links=[{"href": f"https://{host}/x"}])
            ).signals
        }
        assert "brand_in_subdomain" not in names, host


def test_long_brand_tokens_still_match_the_real_construction():
    """...while 'login-microsoftonline.evil.app' must still be caught."""
    names = {
        s.name for s in analyze_phishing(
            _alert({"From": "<a@corp.example>"},
                   links=[{"href": "https://login-microsoftonline.evil.app/a"}])
        ).signals
    }
    assert "brand_in_subdomain" in names


def test_bilingual_display_names_are_not_homoglyph_attacks():
    """Mixing scripts ACROSS a display name is how ordinary bilingual
    names are written; only one WORD built from two alphabets is the
    tell (review catch)."""
    for name in ("Zhang Wei (张伟)", "Ковалёв Ivan", "山田 太郎 (Taro Yamada)"):
        assert "display_name_mixed_script" not in _signals(_alert({
            "From": f'"{name}" <user@corp.example>',
        })), name


def test_a_single_word_mixing_alphabets_is_still_flagged():
    assert "display_name_mixed_script" in _signals(_alert({
        # Cyrillic 'о' inside a Latin word
        "From": '"Micrоsoft Support" <x@evil.example>',
    }))


def test_short_usernames_do_not_trip_the_fragment_signal():
    """An unbounded substring test made a two-character user id match
    ordinary anchor text (review catch)."""
    alert = Alert(
        alert_id="P-2", timestamp=_T, source="email_gateway", severity="low",
        title="mail", indicators={"users": ["jo"]},
        raw_log={
            "headers": {"From": "<a@b.example>"},
            "links": [{"href": "https://x.example/page#job-openings"}],
        },
    )
    assert "recipient_in_url_fragment" not in {
        s.name for s in analyze_phishing(alert).signals
    }


def test_unlisted_country_suffixes_do_not_collapse_organizations():
    """org_domain enumerated suffixes only, so 'co.th' collapsed
    acmebank.co.th and phisher.co.th into one organizational domain and
    reported them ALIGNED (review catch)."""
    assert org_domain("acmebank.co.th") == "acmebank.co.th"
    assert org_domain("mail.phisher.co.th") == "phisher.co.th"
    assert org_domain("acmebank.co.th") != org_domain("phisher.co.th")
    result = analyze_phishing(_alert({
        "From": "<security@acmebank.co.th>",
        "Authentication-Results": (
            "mx; spf=pass smtp.mailfrom=bounce@phisher.co.th; "
            "dkim=pass header.d=phisher.co.th; "
            "dmarc=fail header.from=acmebank.co.th"
        ),
    }))
    assert result.spf_aligned is False and result.dkim_aligned is False
    assert "no_aligned_authentication" in {s.name for s in result.signals}


def test_backslash_authority_names_the_browser_destination():
    """A browser terminates the authority at a backslash, so this link
    goes to evil.example — naming the brand host would report the
    opposite of the truth (review catch)."""
    from soc_copilot.phishing import _host_of

    assert _host_of("https://evil.example\\@login.microsoftonline.com/x") == (
        "evil.example"
    )


def test_single_script_internationalized_domain_is_not_strong():
    """Punycode alone is not an attack: a wholly non-Latin domain is a
    legitimate way to write a name (review catch)."""
    result = analyze_phishing(_alert(
        {"From": "<a@b.example>"},
        links=[{"href": "https://xn--80ak6aa92e.example/login"}],
    ))
    sig = next(s for s in result.signals if s.name == "punycode_domain")
    assert sig.strength in ("moderate", "strong")
    if sig.strength == "moderate":
        assert sig.benign_cause


# --- review regressions: fabricated grounding ----------------------------


def test_quoted_pvalue_cannot_inject_forged_method_clauses():
    """The MTA echoes the envelope address into Authentication-Results.
    Splitting on ';' without respecting quotes let an attacker close the
    quote and forge 'dkim=pass' into a header the gateway wrote (review
    catch)."""
    hostile = (
        'corp-mx.example; spf=fail '
        'smtp.mailfrom="x; dkim=pass header.d=bank.example; '
        'dmarc=pass header.from=bank.example"@evil.example; '
        'dmarc=fail header.from=bank.example'
    )
    result = analyze_phishing(_alert({
        "From": "<security@bank.example>",
        "Authentication-Results": hostile,
    }))
    assert result.dmarc_result == "fail"
    assert result.dkim_aligned is not True
    assert "no_aligned_authentication" in {s.name for s in result.signals}


def test_quoted_pvalue_with_spaces_cannot_forge_spf_alignment():
    """The ';' guard has a sibling the within-clause tokenizer must share.
    A quoted smtp.mailfrom containing SPACES (a quoted-string local-part,
    RFC 5321) split into phantom tokens under str.split(), and a second
    'smtp.mailfrom=' embedded in the attacker-controlled envelope address
    then overwrote the real one — reporting SPF aligned to the brand on a
    message that authenticated the attacker's domain (review catch: the
    injection just moves from ';' to ' ')."""
    hostile = (
        "corp-mx.example; "
        'spf=pass smtp.mailfrom="x smtp.mailfrom=x@brand.example z"@evil.example; '
        "dmarc=fail header.from=brand.example"
    )
    result = analyze_phishing(_alert({
        "From": "<security@brand.example>",
        "Authentication-Results": hostile,
    }))
    assert result.envelope_from != "brand.example"
    assert result.spf_aligned is not True
    assert "no_aligned_authentication" in {s.name for s in result.signals}


def test_dmarc_pass_is_not_reported_as_nothing_aligned():
    """A summarized Authentication-Results can report dmarc=pass without
    the spf/dkim mechanism lines it rested on. DMARC pass is definitionally
    an aligned authenticated identifier (RFC 9989), so the analyzer must
    not emit a STRONG 'nothing aligned' that contradicts its own reported
    dmarc=pass (review catch)."""
    result = analyze_phishing(_alert({
        "From": "<a@brand.example>",
        "Authentication-Results": (
            "mx.corp.example; dmarc=pass header.from=brand.example"
        ),
    }))
    assert result.dmarc_result == "pass"
    assert "no_aligned_authentication" not in {s.name for s in result.signals}


def test_list_valued_header_is_bounded_like_a_string():
    """MAX_HEADER_CHARS has to bound list items, not just strings. A
    multi-From spoof (a modeled shape) carrying a long no-match run slipped
    past a str-only guard and reintroduced the quadratic address-regex hang
    the bound exists to prevent (review catch)."""
    import time

    run = "a" * 200_000  # no '@', no angle brackets: the regex's worst case
    start = time.monotonic()
    result = analyze_phishing(_alert({
        "From": [run, "<x@y.example>"],
        "Authentication-Results": "mx; dmarc=pass header.from=y.example",
    }))
    assert time.monotonic() - start < 2.0
    assert "multiple_from_headers" in {s.name for s in result.signals}


def test_sanctioned_sender_requires_the_identifier_to_have_authenticated():
    """The inventory record is operator-owned, but the envelope and d= it
    is matched against are attacker-writable text. Matching them without
    requiring a PASS let a spoof claim the operator's own sanctioned
    arrangement as cover (review catch)."""
    spoof = analyze_phishing(load_alert_fixture(
        SAMPLE_ALERTS_DIR / "benign_payroll_bulk_mail.json"
    ))
    assert "sanctioned_bulk_sender" in {s.name for s in spoof.signals}

    failed = _alert({
        "From": '"Payroll" <no-reply@corp-payroll.example>',
        "Authentication-Results": (
            "mx; spf=fail smtp.mailfrom=bounce@mail.sg-relay.example; "
            "dkim=fail header.d=corp-payroll.example; "
            "dmarc=fail header.from=corp-payroll.example"
        ),
    })
    assert "sanctioned_bulk_sender" not in _signals(failed)


def test_null_return_path_is_not_reported_as_an_envelope_domain():
    """A null return-path ('<>', bounces/NDRs) authenticates nothing for
    DMARC — SPF may only have checked HELO, which RFC 9989 excludes from
    alignment (review catch)."""
    result = analyze_phishing(_alert({
        "From": "<a@brand.example>",
        "Authentication-Results": (
            "mx; spf=pass smtp.mailfrom=<> smtp.helo=mail.evil.example; "
            "dmarc=fail header.from=brand.example"
        ),
    }))
    assert result.envelope_from is None
    assert result.spf_aligned is None      # not computable, not "aligned"


def test_committed_brand_data_is_wellformed():
    from soc_copilot.phishing import BRANDS_PATH, load_brands

    raw = json.loads(Path(BRANDS_PATH).read_text())
    assert raw["brands"] and raw["url_shorteners"] and raw["free_mail"]
    brands = load_brands()
    for brand, owners in brands["brands"].items():
        assert brand == brand.lower(), brand
        assert owners, brand
        for owner in owners:
            assert "." in owner, (brand, owner)

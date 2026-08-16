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

import pytest

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


# --- the attachment channel (QR codes, embedded links, file types) ----------
#
# The channel is the point of this section. Every gateway rewrites and
# scans links in the message BODY; almost none rewrite a link printed as a
# QR code or buried inside an attachment. The URL's own anatomy is analyzed
# by the same machinery either way — what these signals add is how the link
# reached the user, which anatomy cannot show.

_ALIGNED_AR = (
    "mx; spf=pass smtp.mailfrom=corp.example; "
    "dkim=pass header.d=corp.example; dmarc=pass header.from=corp.example"
)


def _mail(attachments, from_addr="IT <it@corp.example>", **raw_extra) -> Alert:
    return _alert(
        {"From": from_addr, "Authentication-Results": _ALIGNED_AR},
        attachments=attachments, **raw_extra,
    )


def test_a_qr_destination_off_the_sending_domain_is_strong():
    """Quishing's whole trick: the destination is printed as pixels, so
    there is no href to rewrite, nothing to reputation-score, and nothing
    to hover over — and the click lands on a phone, off the managed
    endpoint."""
    result = analyze_phishing(_mail([{
        "filename": "enroll.png", "content_type": "image/png",
        "qr_codes": ["https://corp-example.mfa-reverify.top/enroll"],
    }]))
    qr = [s for s in result.signals if s.name == "attachment_qr_url"]
    assert len(qr) == 1
    assert qr[0].strength == "strong"
    assert "mfa-reverify.top" in qr[0].fact
    assert "corp.example" in qr[0].fact       # names BOTH sides of the compare


def test_a_qr_destination_on_the_sending_domain_is_weak_with_its_twin():
    """The discriminator is where the QR points, never that a QR exists.
    Event tickets, MFA enrollment and payment links are ordinary QR uses,
    and a detection that fires on the channel gets muted within a week."""
    result = analyze_phishing(_mail([{
        "filename": "enroll.png", "content_type": "image/png",
        "qr_codes": ["https://sso.corp.example/mfa/enroll"],
    }]))
    [qr] = [s for s in result.signals if s.name == "attachment_qr_url"]
    assert qr.strength == "weak"
    assert qr.benign_cause is not None
    assert "legitimate" in qr.benign_cause.lower()


def test_a_qr_url_is_analyzed_by_the_ordinary_url_machinery_too():
    """The channel signal does not replace the anatomy. A QR destination
    gets punycode, userinfo, brand-in-subdomain and recipient-in-fragment
    exactly as a body link would — otherwise moving a link into an image
    would be a way to evade every URL check this module has."""
    result = analyze_phishing(_mail(
        [{"filename": "q.png",
          "qr_codes": ["https://login.microsoftonline.com.evil.top/x#e.varga@corp.example"]}],
    ))
    names = {s.name for s in result.signals}
    assert "brand_in_subdomain" in names
    assert "recipient_in_url_fragment" in names
    assert "attachment_qr_url" in names


def test_attachment_urls_are_never_the_ones_truncated_away():
    """MAX_URLS bounds hostile input, and the bound must not drop the link
    that arrived through the channel the gateway does NOT rewrite. The
    attachment corpus goes first."""
    from soc_copilot.phishing import MAX_URLS

    body = "\n".join(f"https://filler{i}.example/x" for i in range(MAX_URLS + 50))
    result = analyze_phishing(_mail(
        [{"filename": "q.png", "qr_codes": ["https://the-qr-target.example/go"]}],
        body_text=body,
    ))
    assert len(result.urls_examined) == MAX_URLS
    assert result.urls_examined[0] == "https://the-qr-target.example/go"


def test_message_level_qr_records_take_the_same_path():
    """A QR usually rides in an inline image rather than a named
    attachment. That record becomes one synthetic attachment so there is a
    single code path and a single set of gates, not a parallel one that
    drifts."""
    result = analyze_phishing(_alert(
        {"From": "IT <it@corp.example>", "Authentication-Results": _ALIGNED_AR},
        qr_codes=["https://not-corp.example/go"],
    ))
    [qr] = [s for s in result.signals if s.name == "attachment_qr_url"]
    assert qr.strength == "strong"
    assert "inline image" in qr.fact


def test_a_right_to_left_override_filename_is_reported_with_both_forms():
    """`invoice<U+202E>gnp.js` displays as `invoicesj.png`. The extension
    that decides what runs is the RAW one, so the raw name is what the
    analyzer reasons over and both forms are shown to the analyst."""
    result = analyze_phishing(_mail([{"name": "invoice‮gnp.js"}]))
    [sig] = [s for s in result.signals if s.name == "attachment_bidi_filename"]
    assert sig.strength == "strong"
    assert "invoicesj.png" in sig.fact          # the rendered deception
    # NOT just `".js" in sig.fact`: repr() escapes U+202E to the ASCII
    # sequence \u202e, so the raw name's own repr contains ".js" whatever
    # the extension logic computed — the assertion passed even with
    # `_extension_of` reading the RENDERED name, the exact mistake its
    # docstring forbids (review catch). Pin the computed extension.
    assert "raw extension (.js)" in sig.fact


def test_ordinary_bidi_marks_in_a_filename_are_not_an_attack():
    """RLM and the embeddings are ordinary in Arabic and Hebrew filenames.
    Only the OVERRIDE reorders arbitrary text, and a tool that calls the
    others an attack is wrong far more often than right — the same
    discipline the lookalike scoring already follows."""
    for control in ("‏", "‫", "⁧"):
        result = analyze_phishing(_mail([{"name": f"فاتورة{control}.pdf"}]))
        assert "attachment_bidi_filename" not in {s.name for s in result.signals}


def test_a_double_extension_is_reported_against_the_claimed_type():
    result = analyze_phishing(_mail([{"name": "statement.pdf.exe"}]))
    names = {s.name for s in result.signals}
    assert "attachment_double_extension" in names
    assert "attachment_executable_type" in names


def test_an_ordinary_dotted_filename_is_not_a_double_extension():
    """`Q2.2026.report.pdf` has three dots and is a PDF. The tell is a
    document extension followed by an EXECUTABLE one, not dot-counting."""
    result = analyze_phishing(_mail([{"name": "Q2.2026.report.pdf"}]))
    assert not {s.name for s in result.signals} & {
        "attachment_double_extension", "attachment_executable_type",
    }


def test_html_attachments_are_strong_because_there_is_no_link_to_scan():
    result = analyze_phishing(_mail([{
        "name": "voicemail.html", "content_type": "text/html",
        "extracted_urls": ["https://collect.example/post"],
    }]))
    signals = {s.name: s for s in result.signals}
    assert signals["attachment_html_document"].strength == "strong"
    assert signals["attachment_embedded_url"].strength == "moderate"
    assert "not rewritten" in signals["attachment_embedded_url"].fact


def test_container_and_macro_and_encrypted_types_are_graded_not_binary():
    """Each of these has a real benign population, so each carries its
    legitimate pattern rather than being reported as a verdict."""
    result = analyze_phishing(_mail([
        {"name": "delivery.iso"},
        {"name": "budget.xlsm"},
        {"name": "docs.zip", "password_protected": True},
    ]))
    by_name = {s.name: s for s in result.signals}
    for name in ("attachment_mark_of_the_web_container",
                 "attachment_macro_enabled_document",
                 "attachment_encrypted_archive"):
        assert by_name[name].strength == "moderate", name
        assert by_name[name].benign_cause, name


def test_a_declared_type_that_contradicts_the_extension_is_reported():
    result = analyze_phishing(_mail([
        {"name": "report.exe", "content_type": "application/pdf"},
    ]))
    assert "attachment_type_mismatch" in {s.name for s in result.signals}


def test_an_incomplete_mime_mapping_never_invents_a_mismatch():
    """The mapping lists only unambiguous families. An unlisted type must
    stay silent rather than report a contradiction it cannot establish —
    the fail-open direction is the safe one for a *discrepancy* signal."""
    result = analyze_phishing(_mail([
        {"name": "design.psd", "content_type": "image/vnd.adobe.photoshop"},
    ]))
    assert "attachment_type_mismatch" not in {s.name for s in result.signals}


def test_attachment_reading_is_total_over_hostile_shapes():
    """Header values arrive from whatever the source system serialized,
    and the analyzer has a standing review catch about a nested dict
    raising TypeError straight out of enrichment. Attachments get the same
    treatment: anything unparseable is ignored, never fatal."""
    result = analyze_phishing(_mail([
        {"filename": {"nested": "dict"}, "content_type": 7},
        {"name": None, "urls": {"deep": {"deeper": ["https://x.example/a"]}}},
        ["not", "a", "record"],
        "bare-filename.exe",
        42,
    ]))
    assert result is not None
    names = {s.name for s in result.signals}
    assert "attachment_executable_type" in names       # the bare string parsed
    # NOT `in result.urls_examined`: _urls_in walks the whole raw_log and
    # would find that URL even if _urls_under never recursed at all. The
    # signal is the only thing that proves the ATTACHMENT walker reached it
    # (review catch — the depth mutation survived the first version).
    embedded = [s for s in analyze_phishing(_mail([
        {"name": None, "urls": {"deep": {"deeper": ["https://x.example/a"]}}},
    ])).signals if s.name == "attachment_embedded_url"]
    assert len(embedded) == 1
    assert "https://x.example/a" in embedded[0].fact


def test_an_alert_with_no_attachments_reports_none_and_says_nothing():
    """The threshold that keeps this enricher from perturbing every
    previously-calibrated fixture: no attachment records, no attachment
    prose in the summary, no attachment signals."""
    result = analyze_phishing(_alert(
        {"From": "a@corp.example", "Authentication-Results": _ALIGNED_AR}
    ))
    assert result.attachments_examined == []
    assert "attachment" not in result.summary.lower()
    assert not [s for s in result.signals if s.name.startswith("attachment_")]


def test_the_summary_refuses_to_imply_detonation():
    """The module opens nothing and decodes no images. A summary that let
    a reader believe otherwise would be the worst kind of security-tool
    dishonesty: implied coverage."""
    result = analyze_phishing(_mail([{"name": "x.pdf"}]))
    assert "NOT opened" in result.summary
    assert "mail gateway recorded" in result.summary


def test_the_macro_signal_never_names_a_file_format_that_does_not_exist():
    """Every fact string here is read by an analyst and cited by the model,
    so naming a nonexistent file type is the worst defect this module can
    have. Deriving the plain-format counterpart by stripping the 'm' and
    appending 'x' invents .xlax, .ppax and .xlx — the map is explicit, and
    add-in formats drop the clause instead of guessing."""
    from soc_copilot.phishing import (
        _MACRO_OFFICE_EXTS,
        _MACRO_PLAIN_COUNTERPART,
    )

    real_formats = {
        "docx", "dotx", "xlsx", "xltx", "pptx", "potx", "ppsx", "xlam",
    }
    for ext in _MACRO_OFFICE_EXTS:
        plain = _MACRO_PLAIN_COUNTERPART.get(ext)
        if plain is not None:
            assert plain in real_formats, f"{ext} -> invented .{plain}"
        result = analyze_phishing(_mail([{"name": f"budget.{ext}"}]))
        [sig] = [
            s for s in result.signals
            if s.name == "attachment_macro_enabled_document"
        ]
        if plain is None:
            assert "no macro-free counterpart" in sig.fact
        else:
            assert f".{plain} format cannot" in sig.fact


def test_a_native_code_office_addin_is_graded_as_an_executable():
    """.xll is an Excel add-in written as a native DLL — Excel loads and
    runs compiled code. Filing it with the macro documents would understate
    it (there is no macro prompt and no protected view in its path)."""
    result = analyze_phishing(_mail([{"name": "helper.xll"}]))
    by_name = {s.name: s for s in result.signals}
    assert by_name["attachment_executable_type"].strength == "strong"
    assert "attachment_macro_enabled_document" not in by_name


def test_filenames_are_classified_as_the_os_resolves_them():
    """Three cheap tricks hide an extension from a literal-string matcher
    while the file still opens as an executable. Win32 strips trailing
    dots and spaces, so `invoice.exe.` runs as invoice.exe; an NTFS '::'
    suffix names the file's own stream; zero-width characters are
    invisible in a mail client. Each defeated the executable signal
    entirely before normalization (self-caught while probing the analyzer
    the way an attacker would)."""
    for name in ("invoice.exe.", "invoice.exe::$DATA", "invoice.exe​"):
        names = {s.name for s in analyze_phishing(_mail([{"name": name}])).signals}
        assert "attachment_executable_type" in names, name
        assert "attachment_filename_obscured" in names, name


def test_the_obscured_name_signal_shows_both_forms():
    [sig] = [
        s for s in analyze_phishing(_mail([{"name": "invoice.exe."}])).signals
        if s.name == "attachment_filename_obscured"
    ]
    assert "invoice.exe." in sig.fact          # what was recorded
    assert "invoice.exe'" in sig.fact          # what actually opens
    assert sig.benign_cause                    # stray spaces are real


def test_an_ordinary_filename_is_not_reported_as_obscured():
    """The signal must not fire on every attachment: an unremarkable name
    resolves to itself."""
    for name in ("report.pdf", "Q2 budget.xlsx", "INVOICE.PDF"):
        names = {s.name for s in analyze_phishing(_mail([{"name": name}])).signals}
        assert "attachment_filename_obscured" not in names, name


def test_a_trailing_dot_double_extension_is_still_a_double_extension():
    """The double-extension split runs on the resolved name too, or
    `statement.pdf.exe.` would split into ['statement','pdf','exe',''] and
    miss."""
    names = {
        s.name for s in
        analyze_phishing(_mail([{"name": "statement.pdf.exe."}])).signals
    }
    assert "attachment_double_extension" in names


def test_the_container_claim_does_not_promise_the_marker_is_missing():
    """Windows and current archivers propagate mark-of-the-web now. The
    fact may say this is the technique the format is chosen for; it may
    not tell an analyst the marker is absent on their endpoint."""
    [sig] = [
        s for s in analyze_phishing(_mail([{"name": "delivery.iso"}])).signals
        if s.name == "attachment_mark_of_the_web_container"
    ]
    assert "historically" in sig.fact
    assert "not as a guarantee" in sig.fact


# --- the review's confirmed findings, each with its oracle ------------------

def test_an_unknown_sender_makes_the_qr_comparison_unknown_not_wrong():
    """THREE states, not two. The first version collapsed "the sender's
    domain could not be determined" into "does not align" and emitted a
    STRONG signal whose fact asserted a comparison against `the sender
    unknown` — a claim about a comparison that was never made. Three
    review lenses found it independently, and it is reachable on ordinary
    mail: a gateway that records only Authentication-Results, or a
    display-name-only From:, gets there."""
    result = analyze_phishing(_alert(
        {"Authentication-Results": "mx; spf=pass smtp.mailfrom=corp.example"},
        attachments=[{"name": "q.png", "qr_codes": ["https://x.example/go"]}],
    ))
    [qr] = [s for s in result.signals if s.name == "attachment_qr_url"]
    assert qr.strength == "moderate"
    assert "UNKNOWN" in qr.fact
    assert "unknown)" not in qr.fact       # never asserts against a non-domain
    assert qr.benign_cause


def test_the_strong_qr_branch_still_carries_its_benign_cause():
    """Off-domain QR destinations are how ticketing, payment processors and
    outsourced enrollment work. 'Not the sender's domain' is a reason to
    look, never a verdict — and a strong signal with no benign cause is
    how this module's own docstring says a detection gets muted."""
    result = analyze_phishing(_mail([
        {"name": "q.png", "qr_codes": ["https://random-host.example/go"]},
    ]))
    [qr] = [s for s in result.signals if s.name == "attachment_qr_url"]
    assert qr.strength == "strong"
    assert qr.benign_cause and "brands.json" in qr.benign_cause


def test_a_qr_to_an_operator_authorized_brand_domain_grades_down():
    """The operator's curated brand list is the checkable middle ground:
    a destination that is not the sender's domain but IS recorded as
    authorized for a brand is a delegated flow, not an unknown host."""
    result = analyze_phishing(_mail([
        {"name": "q.png", "qr_codes": ["https://login.microsoftonline.com/e"]},
    ]))
    [qr] = [s for s in result.signals if s.name == "attachment_qr_url"]
    assert qr.strength == "moderate"
    assert "microsoft" in qr.fact


def test_channel_urls_are_deduped_and_capped_with_the_count_disclosed():
    """625 records x 25 URLs each all landed in the signal list AND in the
    summary's strong/moderate tally, so an attacker could bury the real
    findings under their own and inflate the counts the model reads as a
    severity proxy (review catch, two lenses)."""
    from soc_copilot.phishing import MAX_ATTACHMENT_URLS, MAX_REPORTED_CHANNEL_URLS

    # DISTINCT urls per record, so "deduped across attachments" is actually
    # under test. Each record's list is separately bounded by
    # MAX_ATTACHMENT_URLS, so the distinct total is records x that bound.
    records = 10
    result = analyze_phishing(_mail([
        {"name": f"a{r}.pdf",
         "urls": [f"https://h{r}-{i}.example/p" for i in range(40)]}
        for r in range(records)
    ]))
    embedded = [s for s in result.signals if s.name == "attachment_embedded_url"]
    assert len(embedded) == MAX_REPORTED_CHANNEL_URLS
    assert len({s.fact.split("link to ")[1] for s in embedded}) == len(embedded)
    [trunc] = [
        s for s in result.signals if s.name == "attachment_embedded_urls_truncated"
    ]
    assert f"{records * MAX_ATTACHMENT_URLS} distinct" in trunc.fact


def test_attachment_urls_cannot_evict_every_body_link():
    """The ordering that protects the un-rewritten channel must not become
    a way to hide the body: attachment links get a reserved share of the
    MAX_URLS budget, not all of it (review catch)."""
    from soc_copilot.phishing import ATTACHMENT_URL_BUDGET, MAX_URLS

    # DISTINCT urls per attachment: 25 records x 25 each = 625 candidates,
    # which is what the eviction scenario actually needs (a repeated list
    # dedupes down to 25 and proves nothing).
    result = analyze_phishing(_mail(
        [
            {"name": f"a{r}.pdf",
             "urls": [f"https://att{r}-{i}.example/p" for i in range(25)]}
            for r in range(25)
        ],
        body_text="https://the-body-link.example/important",
    ))
    assert result.urls_examined[0].startswith("https://att")   # channel first
    # The whole point: 625 attacker-supplied attachment links do not push
    # the body link out of analysis.
    assert "https://the-body-link.example/important" in result.urls_examined
    attachment_share = sum(
        1 for u in result.urls_examined if u.startswith("https://att")
    )
    assert attachment_share == ATTACHMENT_URL_BUDGET < MAX_URLS


def test_truncated_attachment_lists_are_disclosed_not_reported_as_complete():
    """Padding a message with inline images to push the payload past the
    cap is a total bypass of this channel. The cap stays, but the summary
    may not report a capped count as though it were the whole message —
    'implied coverage' is what this module's docstring calls the worst
    thing a security tool can offer (review catch)."""
    from soc_copilot.phishing import MAX_ATTACHMENTS

    padding = [{"name": f"img{i}.png", "content_type": "image/png"}
               for i in range(MAX_ATTACHMENTS)]
    result = analyze_phishing(_mail(padding + [{"name": "Invoice.pdf.exe"}]))
    assert f"read of {MAX_ATTACHMENTS + 1} delivered" in result.summary.replace(
        f"{MAX_ATTACHMENTS} attachment record(s) read", "read"
    )
    assert "were NOT analyzed" in result.summary


def test_a_cabinet_is_not_described_as_mounted():
    """CAB is extracted by expand.exe / the shell handler, never mounted.
    It belongs to the same mark-of-the-web family and gets the same signal,
    but the fact may not tell an analyst it is mounted — a container family
    and a mount mechanism are different claims (review catch)."""
    cab = [s for s in analyze_phishing(_mail([{"name": "update.cab"}])).signals
           if s.name == "attachment_mark_of_the_web_container"][0]
    assert "cabinet archive" in cab.fact
    assert "mount" not in cab.fact

    iso = [s for s in analyze_phishing(_mail([{"name": "setup.iso"}])).signals
           if s.name == "attachment_mark_of_the_web_container"][0]
    assert "mountable disk image" in iso.fact


def test_plain_text_attachments_never_report_a_type_mismatch():
    """text/plain is the catch-all gateways apply to anything textual, so
    it cannot establish a contradiction. Listing {txt, log, csv} made every
    .yaml, .md, .json and .xml attachment assert that its declared type and
    name 'disagree about what this file is' — false, and precisely the
    fires-on-normal-mail behavior that gets a detection muted."""
    for name in ("deploy.yaml", "notes.md", "config.json", "report.xml",
                 "query.sql", "settings.ini", "server.log", "data.csv"):
        result = analyze_phishing(_mail([
            {"name": name, "content_type": "text/plain"},
        ]))
        assert "attachment_type_mismatch" not in {
            s.name for s in result.signals
        }, name


@pytest.mark.parametrize("raw_log_key", ["attachments", "email_attachments", "files"])
@pytest.mark.parametrize("name_key", ["name", "filename", "file_name", "fileName", "file"])
def test_every_tolerant_container_and_name_spelling_is_read(raw_log_key, name_key):
    """The tolerant key tuples are the whole reason _attachments_of exists,
    and narrowing any of them to a single spelling left the suite green
    (review catch — raised as a coverage gap rather than a defect, and it
    is exactly the kind of gap that turns into one on the next edit)."""
    result = analyze_phishing(_alert(
        {"From": "IT <it@corp.example>", "Authentication-Results": _ALIGNED_AR},
        **{raw_log_key: [{name_key: "payload.lnk"}]},
    ))
    assert result.attachments_examined == ["payload.lnk"]
    assert "attachment_shortcut_type" in {s.name for s in result.signals}


def test_the_double_extension_split_uses_the_resolved_name():
    """`parts` must come from the OS-resolved name, not the recorded one.
    A trailing dot alone does not prove it (the comprehension filters the
    empty segment either way), so the oracle is a stream suffix, which
    leaves the raw final segment as 'exe::$DATA' and matches nothing
    (mutation catch — the raw-name mutant survived the first version)."""
    names = {
        s.name for s in
        analyze_phishing(_mail([{"name": "statement.pdf.exe::$DATA"}])).signals
    }
    assert "attachment_double_extension" in names


def test_one_signal_per_destination_however_many_attachments_carry_it():
    """A newsletter link repeated across twelve attached statements is one
    finding, not twelve. Deduping per DESTINATION (not per record) is what
    keeps the summary's strong/moderate tally meaningful — and the earlier
    version of the cap test used distinct URLs throughout, so it never
    exercised this path (mutation catch)."""
    shared = "https://one-and-the-same.example/promo"
    result = analyze_phishing(_mail(
        [{"name": f"statement{i}.pdf", "urls": [shared]} for i in range(12)]
    ))
    embedded = [s for s in result.signals if s.name == "attachment_embedded_url"]
    assert len(embedded) == 1
    assert "attachment_embedded_urls_truncated" not in {
        s.name for s in result.signals
    }


def test_one_qr_signal_per_destination_across_attachments():
    shared = "https://same-qr.example/go"
    result = analyze_phishing(_mail(
        [{"name": f"page{i}.png", "qr_codes": [shared]} for i in range(8)]
    ))
    assert len([s for s in result.signals if s.name == "attachment_qr_url"]) == 1

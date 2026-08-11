"""Deterministic phishing deep-dive: email authentication and URL analysis.

Phishing is the flagship SOC alert class, and until now the copilot read
an email alert the way a layperson does — sender string, subject line,
"looks urgent". The facts that actually decide a phishing verdict live in
the headers, and they are computable: did any authenticated identifier
ALIGN with the domain the user sees, does the reply address lead
somewhere else, does the link go where it claims. This module computes
those facts deterministically so the model can cite them and never invent
them, exactly like the Sigma matcher and the asset inventory.

The analysis it produces is a set of FACTS WITH THEIR IDENTIFIER ATTACHED
("SPF pass for smtp.mailfrom=bounces.esp.example, which does NOT align
with header.from=brand.example") plus, for every signal, the legitimate
traffic pattern that also produces it. That second half is the difference
between a tool an analyst trusts and one they mute: a Return-Path on a
different domain is how every email service provider on earth works, and
a detection that calls it phishing is wrong far more often than right.

What it gets right on purpose, because these are the errors that make a
security tool embarrassing:

- ALIGNMENT, not string comparison. SPF authenticates the envelope
  (RFC 7208), DKIM authenticates a signing domain (RFC 6376); neither
  looks at the From: header the user sees. DMARC (RFC 9989) is the only
  one anchored to it, and it passes when SPF *or* DKIM passes AND that
  identifier's organizational domain matches From's. So this module
  computes alignment itself rather than echoing an upstream verdict.
- dmarc=none is NOT dmarc=fail. "The author domain publishes no policy"
  and "authentication failed" are different facts about the world;
  conflating them is the most common amateur error in tools like this.
- DMARC failure has loud benign causes — forwarding, mailing lists, and
  unconfigured third-party senders — so a failure is reported alongside
  whether an ARC chain (RFC 8617) explains it.
- DMARC PASS does not mean benign. A lookalike domain with its own
  perfect SPF/DKIM/DMARC passes trivially; that is why the lookalike and
  URL signals carry weight independent of the authentication verdict.
- Trust boundary. Anyone can type an Authentication-Results header into a
  message, so only the topmost one is read (RFC 8601 §5) and any others
  are reported as attacker-supplied text that was ignored.
- Hop count and Return-Path mismatch are NOISE and are deliberately not
  signals — only non-monotonic timestamps in the trace are.

What it does NOT do, stated plainly because a security tool that implies
coverage it lacks is worse than one that admits the gap:

- No DNS lookups and no live SPF/DKIM evaluation. It reads what the
  receiving mail infrastructure already recorded.
- No true Public Suffix List resolution — organizational domain uses a
  committed approximation (_MULTI_LABEL_SUFFIXES plus a generic
  second-level rule), and every alignment verdict is reported as resting
  on it.
- No ARC validation. An ARC chain is reported as CLAIMED; verifying a
  seal needs the sealer's key and a trust list.
- No lookalike/typosquat scoring of the SENDING domain. Brand
  impersonation is detected only where an operator-curated brand list
  makes it checkable (display name and link subdomain); edit-distance
  guessing against every brand on earth is how these tools start flagging
  legitimate mail.
- No attachment analysis, QR-code (quishing) extraction, or inspection of
  links inside PDFs and HTML attachments. Those are real phishing
  channels this module simply does not see.
"""
import json
import re
import unicodedata
from pathlib import Path

from .assets import load_inventory
from .models import Alert, PhishingAnalysis, PhishingSignal

BRANDS_PATH = Path(__file__).resolve().parents[1] / "data" / "phishing" / "brands.json"

# Organizational-domain approximation. The real rule is the RFC 9989 DNS
# tree walk (historically the Public Suffix List); shipping either would
# mean a dependency or a vendored snapshot that silently goes stale.
#
# Enumerating suffixes alone FAILS OPEN, which is the dangerous direction:
# an unlisted suffix like "co.th" collapses acmebank.co.th and
# phisher.co.th to the same organizational domain and reports them as
# ALIGNED (review catch). So enumeration is backed by a rule: under a
# two-letter country code, a second-level label drawn from the generic set
# below is treated as part of the suffix. That covers the whole
# <generic>.<cc> family without listing every country.
_MULTI_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "web.za",
    "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "com.ar", "com.co", "com.pe", "com.cl",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.sg", "com.hk", "com.tw", "com.my", "com.ph",
    "co.in", "net.in", "org.in", "gov.in",
    "co.kr", "or.kr", "com.tr", "com.ua", "co.il", "org.il",
    "com.es", "com.pl", "com.ru", "com.vn",
})
# Second-level labels that act as public suffixes under a country code.
_GENERIC_SLDS = frozenset({
    "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go",
    "govt", "web", "sch", "mil", "int", "asn", "id", "in", "nom", "gen",
    "ltd", "plc", "firm", "info", "biz", "name", "pro", "res", "gob",
})

# Hard bounds on attacker-controlled text before it reaches a regex. The
# address and URL patterns are linear on realistic input but quadratic on
# a long run of word characters with no match (review catch: a 64 KB
# display name took five seconds), and an investigation must never hang on
# enrichment. Real headers are orders of magnitude below these.
MAX_HEADER_CHARS = 4000
MAX_URLS = 200

# Header names, canonicalized lowercase, that the analyzer reads.
_H_FROM = "from"
_H_REPLY_TO = "reply-to"
_H_RETURN_PATH = "return-path"
_H_AUTH_RESULTS = "authentication-results"
_H_ARC_AUTH = "arc-authentication-results"
_H_RECEIVED = "received"
_H_SUBJECT = "subject"

# raw_log keys that may hold a header container (dict of header -> value).
_HEADER_CONTAINERS = ("headers", "email_headers", "email")

# Path fragments that a credential-harvest landing page tends to use. WEAK
# alone — every SaaS product on earth has a /login — and only meaningful
# combined with an unaligned or lookalike sender.
_CREDENTIAL_PATHS = (
    "/login", "/signin", "/sign-in", "/auth", "/verify", "/owa", "/webmail",
    "/account/secure", "/mfa", "/password", "/session", "/validate",
)

_ADDRESS_RE = re.compile(r"<([^<>]+)>")
_BARE_ADDRESS_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_IPV4_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# A Received hop's timestamp sits after the final ';'.
_RECEIVED_DATE_RE = re.compile(r";\s*(.+)$", re.DOTALL)


def load_brands(path: str | Path = BRANDS_PATH) -> dict:
    """Load the committed brand/shortener/free-mail reference data.

    Missing file degrades to empty lists rather than raising: the
    authentication analysis is still valuable without brand context, and
    the copilot must never fail an investigation over reference data.
    """
    p = Path(path)
    if not p.exists():
        return {"brands": {}, "url_shorteners": [], "free_mail": []}
    data = json.loads(p.read_text())
    return {
        "brands": data.get("brands", {}),
        "url_shorteners": data.get("url_shorteners", []),
        "free_mail": data.get("free_mail", []),
    }


def org_domain(domain: str) -> str:
    """The organizational domain — what DMARC alignment is computed over.

    'send.klaviyo.com' -> 'klaviyo.com'; 'mail.example.co.uk' ->
    'example.co.uk'; 'a.acmebank.co.th' -> 'acmebank.co.th' via the
    generic-second-level rule, so an unlisted country suffix cannot
    collapse two unrelated organizations into one. An approximation of the
    RFC 9989 tree walk, and reported as one.
    """
    d = (domain or "").strip().lower().rstrip(".")
    if not d or "." not in d:
        return d
    labels = [x for x in d.split(".") if x]
    if len(labels) < 2:
        return d
    if len(labels) >= 3:
        last_two = ".".join(labels[-2:])
        cc_generic = (
            len(labels[-1]) == 2 and labels[-1].isalpha()
            and labels[-2] in _GENERIC_SLDS
        )
        if last_two in _MULTI_LABEL_SUFFIXES or cc_generic:
            return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _aligned(identifier_domain: str | None, from_domain: str | None) -> bool | None:
    """Relaxed DMARC alignment: same organizational domain. None when
    either side is unknown — 'not computable' is not 'not aligned'."""
    if not identifier_domain or not from_domain:
        return None
    return org_domain(identifier_domain) == org_domain(from_domain)


def _split_outside_quotes(text: str, sep: str = ";") -> list[str]:
    """Split on `sep`, ignoring separators inside a quoted string.

    Authentication-Results pvalues may be quoted and may legitimately
    contain a semicolon (Gmail quotes smtp.mailfrom). A naive split lets an
    attacker close the quote and inject entire method clauses through the
    envelope address the MTA echoes back — forging `dkim=pass` into a
    header the receiving gateway wrote (review catch).
    """
    parts: list[str] = []
    buf: list[str] = []
    in_quotes = False
    escaped = False
    for ch in text:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\":
            buf.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
            continue
        if ch == sep and not in_quotes:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return parts


def _address_of(header_value: str | None) -> str | None:
    """The addr-spec out of a From/Reply-To value, display name discarded."""
    if not header_value:
        return None
    m = _ADDRESS_RE.search(header_value)
    if m:
        return m.group(1).strip().strip("<>").lower()
    m = _BARE_ADDRESS_RE.search(header_value)
    return m.group(0).lower() if m else None


def _display_name_of(header_value: str | None) -> str:
    """The display-name part of a From value ('' when there isn't one)."""
    if not header_value:
        return ""
    if "<" in header_value:
        return header_value.split("<", 1)[0].strip().strip('"').strip()
    return ""


def _domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().strip(">").lower()


def parse_authentication_results(raw: str) -> dict[str, list[dict]]:
    """Parse an RFC 8601 Authentication-Results field into its verdicts.

    Returns method -> LIST of result records, each carrying its own
    identifiers. A list, not one merged dict, because a message routinely
    carries several DKIM signatures and each is evaluated independently:
    merging them attaches one signature's verdict to another's `d=`, which
    fabricates alignment in exactly the case that matters — the signature
    that aligns being the one that failed (review catch, found
    independently by three reviewers).

    Tolerant by necessity: Microsoft 365 repeats the authserv-id before
    each method, violating the ABNF, so bare-domain segments are discarded
    rather than parsed as results. Splitting respects quoted pvalues so a
    hostile envelope address echoed into the header cannot inject clauses.
    """
    out: dict[str, list[dict]] = {}
    if not raw or not isinstance(raw, str):
        return out
    raw = raw[:MAX_HEADER_CHARS]
    # Comments in parentheses carry no parseable value and can contain
    # semicolons; drop them (repeatedly, for nesting) before splitting.
    text = raw
    for _ in range(4):
        stripped = re.sub(r"\([^()]*\)", " ", text)
        if stripped == text:
            break
        text = stripped
    for segment in _split_outside_quotes(text, ";"):
        seg = segment.strip()
        if not seg or "=" not in seg:
            continue  # the bare authserv-id (or M365's repeats of it)
        tokens = seg.split()
        method_token = tokens[0]
        if "=" not in method_token:
            continue
        method, _, result = method_token.partition("=")
        method = method.strip().lower()
        if method not in ("spf", "dkim", "dmarc", "compauth", "arc"):
            continue
        entry: dict = {"result": result.strip().lower().strip('"')}
        for token in tokens[1:]:
            if "=" not in token:
                continue
            prop, _, value = token.partition("=")
            entry[prop.strip().lower()] = value.strip().strip('"').rstrip(";")
        out.setdefault(method, []).append(entry)
    return out


def _method(auth: dict[str, list[dict]], name: str) -> dict:
    """The authoritative record for a single-result method (spf, dmarc,
    compauth): a passing one if present, else the first."""
    entries = auth.get(name) or []
    for e in entries:
        if e.get("result") == "pass":
            return e
    return entries[0] if entries else {}


def _dkim_signatures(auth: dict[str, list[dict]]) -> list[dict]:
    return auth.get("dkim") or []


def _headers_of(raw_log: dict) -> dict:
    """Header name (lowercased) -> value, from whichever container the
    source system used. Received may be a list; it is kept as one.

    String values are truncated: everything downstream feeds them to
    regexes that are quadratic on a long no-match run, and a hung
    investigation is a worse failure than a truncated header.
    """
    for key in _HEADER_CONTAINERS:
        container = raw_log.get(key)
        if isinstance(container, dict):
            return {
                str(k).strip().lower():
                    (v[:MAX_HEADER_CHARS] if isinstance(v, str) else v)
                for k, v in container.items()
            }
    return {}


def _scripts_of(token: str) -> set[str]:
    scripts = set()
    for ch in token:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW"):
            if name.startswith(script):
                scripts.add(script)
                break
    return scripts


def _is_mixed_script(text: str) -> bool:
    """True when a single WORD mixes writing systems — the homograph tell.

    Per token, not per string (review catch): "Zhang Wei (张伟)" and every
    other ordinary bilingual display name mixes scripts across the whole
    value, and flagging that as a homoglyph attack is exactly the kind of
    false positive that gets a detection muted. What is anomalous is one
    word built from two alphabets, which is how 'micrоsoft' is made
    (UTS #39 confusables).
    """
    for token in re.split(r"[\s@._\-<>()\"',]+", text):
        if len(token) > 1 and len(_scripts_of(token)) > 1:
            return True
    return False


def _brand_in(text: str, brand: str) -> bool:
    """Whether a brand token appears as a distinct word in text rather than
    as a bare substring (review catch: 'ups' is inside 'groups',
    'backups' and 'signups', so substring matching fired a STRONG brand
    signal on groups.google.com).

    The left edge always has to be a boundary. The right edge only has to
    be one for SHORT brand tokens: attackers write 'login-microsoftonline',
    so requiring a right boundary would miss the real construction, while
    leaving it open on a three-letter token is what produced the false
    positives.
    """
    left = rf"(?<![a-z0-9]){re.escape(brand)}"
    pattern = left + (r"(?![a-z0-9])" if len(brand) <= 4 else "")
    return re.search(pattern, text) is not None


def _decode_punycode(host: str) -> str:
    """Render an xn-- host as the characters a browser shows, so the
    confusable check runs on what the user actually sees. Falls back to
    the encoded form when the label is not decodable."""
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                out.append(label.encode("ascii").decode("idna"))
                continue
            except (UnicodeError, ValueError):
                pass
        out.append(label)
    return ".".join(out)


def _urls_in(raw_log: dict) -> list[str]:
    """Every URL the alert carries, de-duplicated, order preserved and
    bounded — collection must stay linear in hostile input."""
    found: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        for url in _URL_RE.findall(value):
            url = url.rstrip(".,;")
            if url not in seen and len(found) < MAX_URLS:
                seen.add(url)
                found.append(url)

    def walk(node: object) -> None:
        if len(found) >= MAX_URLS:
            return
        if isinstance(node, str):
            add(node[:100_000])
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(raw_log)
    return found


def _authority_of(url: str) -> str:
    """The authority component, terminated the way a browser terminates it.

    Backslash counts as a delimiter for http(s) URLs under the WHATWG URL
    standard, so `https://evil.example\\@brand.example/` goes to
    evil.example — naming brand.example as the destination would be
    reporting the opposite of the truth (review catch).
    """
    rest = url.split("://", 1)[1] if "://" in url else url
    return re.split(r"[/?#\\]", rest, 1)[0]


def _host_of(url: str) -> str:
    """The host of a URL, userinfo stripped (that IS the trick)."""
    authority = _authority_of(url)
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if authority.startswith("["):          # IPv6 literal
        return authority.split("]", 1)[0].lstrip("[").lower()
    return authority.split(":", 1)[0].lower()


def _has_userinfo(url: str) -> bool:
    return "@" in _authority_of(url)


def _signal(
    name: str, strength: str, fact: str, benign_cause: str | None = None
) -> PhishingSignal:
    return PhishingSignal(
        name=name, strength=strength, fact=fact, benign_cause=benign_cause
    )


def _auth_signals(
    auth: dict[str, list[dict]],
    arc_claimed: bool,
    from_domain: str | None,
    spf_aligned: bool | None,
    dkim_aligned: bool | None,
    aligned_pass: bool,
) -> list[PhishingSignal]:
    """Signals derived from the authentication verdicts and alignment."""
    signals: list[PhishingSignal] = []
    spf = _method(auth, "spf")
    dkim_sigs = _dkim_signatures(auth)
    dkim = next(
        (s for s in dkim_sigs if s.get("result") == "pass"),
        dkim_sigs[0] if dkim_sigs else {},
    )
    dmarc = _method(auth, "dmarc")
    dmarc_result = dmarc.get("result")

    if from_domain and not aligned_pass and (spf or dkim or dmarc):
        signals.append(_signal(
            "no_aligned_authentication",
            "strong",
            f"No authenticated identifier aligns with header.from="
            f"{from_domain}: SPF {spf.get('result', 'absent')} for "
            f"smtp.mailfrom={spf.get('smtp.mailfrom', 'unknown')} "
            f"(aligned: {spf_aligned}), DKIM {dkim.get('result', 'absent')} "
            f"for d={dkim.get('header.d') or dkim.get('header.i', 'unknown')} "
            f"(aligned: {dkim_aligned}). Nothing vouched for the domain the "
            f"recipient sees.",
            "Forwarding and mailing lists break SPF and can break DKIM; an "
            "unconfigured third-party sender (ESP) also produces this. Check "
            "whether an ARC chain or a known relay explains it before "
            "treating it as spoofing.",
        ))

    if dmarc_result == "fail":
        signals.append(_signal(
            "dmarc_fail",
            "strong",
            f"DMARC fail for header.from={dmarc.get('header.from', from_domain)}"
            + (
                " — an ARC chain is CLAIMED by the message (unverified here: "
                "ARC seals are only meaningful if the sealer is trusted and "
                "the chain validates, neither of which this analyzer does), "
                "and forwarding is the ordinary reason one appears"
                if arc_claimed else
                " with no ARC chain claimed to explain it"
            ),
            "Forwarding, mailing lists, and unconfigured third-party senders "
            "are the common benign causes — the reason DMARC failure alone is "
            "never a phishing verdict.",
        ))
    elif dmarc_result == "none":
        signals.append(_signal(
            "dmarc_no_policy",
            "moderate",
            f"DMARC none for header.from="
            f"{dmarc.get('header.from', from_domain)}: the author domain "
            f"publishes no DMARC policy, so nothing was enforced. This is "
            f"NOT an authentication failure — it is the absence of a policy.",
            "A large share of legitimate domains still publish no DMARC "
            "record; on its own this says nothing about this message.",
        ))
    elif dmarc_result == "bestguesspass":
        signals.append(_signal(
            "dmarc_best_guess",
            "moderate",
            "Microsoft reported dmarc=bestguesspass: the author domain has no "
            "DMARC record, but the message would have passed had it published "
            "one. Not a DMARC pass.",
            "Common for legitimate domains that have not deployed DMARC.",
        ))

    compauth = _method(auth, "compauth")
    if compauth.get("result") == "fail":
        reason = compauth.get("reason", "unknown")
        signals.append(_signal(
            "composite_auth_fail",
            "moderate",
            f"Microsoft composite authentication failed "
            f"(compauth=fail reason={reason}) — the receiving platform's own "
            f"implicit-authentication check on top of SPF/DKIM/DMARC. Reason "
            f"000 is an explicit DMARC failure under p=quarantine/reject; "
            f"001 is an implicit failure where the sending domain's records "
            f"are weak or absent.",
            "A sending domain with no DMARC record and imperfect SPF/DKIM "
            "fails composite auth without being a spoof — common for small "
            "suppliers and newly configured senders.",
        ))
    return signals


def _header_signals(
    headers: dict, brands: dict, from_addr: str | None, from_domain: str | None
) -> list[PhishingSignal]:
    """Signals from the visible headers: reply path, display name, From."""
    signals: list[PhishingSignal] = []
    free_mail = {d.lower() for d in brands.get("free_mail", [])}
    brand_map = brands.get("brands", {})

    raw_from = headers.get(_H_FROM)
    if isinstance(raw_from, list) and len(raw_from) > 1:
        signals.append(_signal(
            "multiple_from_headers",
            "strong",
            f"{len(raw_from)} From: header fields present. RFC 5322 permits "
            f"exactly one; multiples are parser-differential spoofing — the "
            f"mail client and the security scanner read different senders.",
            None,
        ))

    reply_to = _address_of(
        headers.get(_H_REPLY_TO) if isinstance(headers.get(_H_REPLY_TO), str)
        else None
    )
    reply_domain = _domain_of(reply_to)
    if reply_domain and from_domain:
        if org_domain(reply_domain) != org_domain(from_domain):
            if reply_domain in free_mail:
                signals.append(_signal(
                    "reply_to_free_mail",
                    "moderate",
                    f"Reply-To is a consumer mailbox ({reply_to}) while From "
                    f"is {from_addr}: replies leave the claimed organization "
                    f"entirely. This is the canonical business-email-"
                    f"compromise and invoice-fraud pattern — decisive when "
                    f"combined with an unaligned or lookalike sender, which "
                    f"is why it is not decisive alone.",
                    "Sole traders and small suppliers genuinely use free mail "
                    "as a reply address; so do contact-form relays, "
                    "scheduling tools, and recruiting mail that routes "
                    "replies to a personal mailbox.",
                ))
            else:
                signals.append(_signal(
                    "reply_to_other_domain",
                    "weak",
                    f"Reply-To ({reply_domain}) is a different organizational "
                    f"domain from From ({org_domain(from_domain)}).",
                    "Ticketing systems, no-reply senders redirecting to "
                    "support, and marketing platforms do this constantly.",
                ))

    display = _display_name_of(
        headers.get(_H_FROM) if isinstance(headers.get(_H_FROM), str) else None
    )
    if display:
        embedded = _BARE_ADDRESS_RE.search(display[:MAX_HEADER_CHARS])
        if embedded and from_addr and embedded.group(0).lower() != from_addr:
            signals.append(_signal(
                "display_name_contains_other_address",
                "moderate",
                f"The display name contains an email address "
                f"({embedded.group(0)}) that is not the actual sender "
                f"({from_addr}). Mail clients show the display name and hide "
                f"the real address.",
                "Helpdesk and ticketing systems put the REQUESTER's address "
                "in the display name, and 'via' senders name the original "
                "author — both produce this legitimately. It is decisive "
                "only when the embedded address impersonates a domain the "
                "sender is not authorized for.",
            ))
        if _is_mixed_script(display):
            signals.append(_signal(
                "display_name_mixed_script",
                "strong",
                f"The display name {display!r} mixes writing systems — the "
                f"homoglyph construction (a Cyrillic character standing in "
                f"for a Latin one).",
                "A name written wholly in one non-Latin script is perfectly "
                "normal; only the mixing is the tell.",
            ))
        lowered = display.lower()
        for brand, owners in brand_map.items():
            if _brand_in(lowered, brand) and from_domain:
                if org_domain(from_domain) not in {org_domain(o) for o in owners}:
                    signals.append(_signal(
                        "display_name_brand_mismatch",
                        "moderate",
                        f"The display name claims the {brand!r} brand but the "
                        f"message is sent from {from_domain}, which is not an "
                        f"authorized sending domain for it "
                        f"(authorized: {', '.join(owners[:4])}).",
                        "Brands legitimately outsource mail; an authorized "
                        "sender missing from the operator's brand list "
                        "produces exactly this signal.",
                    ))
                break
    return signals


def _url_signals(
    urls: list[str], brands: dict, from_domain: str | None, recipients: list[str]
) -> list[PhishingSignal]:
    """Signals from the links the message carries."""
    signals: list[PhishingSignal] = []
    shorteners = {s.lower() for s in brands.get("url_shorteners", [])}
    brand_map = brands.get("brands", {})
    seen: set[str] = set()

    for url in urls:
        host = _host_of(url)
        if not host:
            continue

        if "xn--" in host and "punycode" not in seen:
            seen.add("punycode")
            decoded = _decode_punycode(host)
            confusable = _is_mixed_script(decoded)
            signals.append(_signal(
                "punycode_domain",
                "strong" if confusable else "moderate",
                f"The link host {host} is punycode-encoded and renders as "
                f"{decoded!r}"
                + (
                    " — which MIXES writing systems inside a label, the "
                    "homoglyph construction."
                    if confusable else
                    " — a single-script internationalized name, which is a "
                    "legitimate way to write a domain."
                ),
                None if confusable else
                "Internationalized domains are normal for non-English "
                "organizations; only a mixed-script label is the attack.",
            ))

        if _has_userinfo(url) and "userinfo" not in seen:
            seen.add("userinfo")
            signals.append(_signal(
                "url_userinfo_authority",
                "strong",
                f"The link embeds userinfo before the host ({url[:120]}): "
                f"everything before the '@' is ignored by the browser, so the "
                f"apparent domain is not where the link goes — it goes to "
                f"{host}.",
                None,
            ))

        if _IPV4_HOST_RE.match(host) and "rawip" not in seen:
            seen.add("rawip")
            signals.append(_signal(
                "url_raw_ip_host",
                "moderate",
                f"The link addresses a bare IP ({host}) rather than a "
                f"hostname — no certificate identity, no domain reputation.",
                "Internal tools and appliances are often reached by IP; "
                "weigh by whether the sender is external.",
            ))

        if host in shorteners and "shortener" not in seen:
            seen.add("shortener")
            signals.append(_signal(
                "url_shortener",
                "weak",
                f"The link uses the shortener {host}, so its true destination "
                f"was not inspectable from the message.",
                "Marketing and internal comms use shorteners routinely; this "
                "means 'not inspectable', not 'malicious'.",
            ))

        labels = host.split(".")
        subdomain_part = ".".join(labels[:-2]) if len(labels) > 2 else ""
        for brand, owners in brand_map.items():
            if _brand_in(subdomain_part, brand) and f"brandsub:{brand}" not in seen:
                owner_orgs = {org_domain(o) for o in owners}
                if org_domain(host) not in owner_orgs:
                    seen.add(f"brandsub:{brand}")
                    signals.append(_signal(
                        "brand_in_subdomain",
                        "strong",
                        f"The link puts the {brand!r} brand in the SUBDOMAIN "
                        f"of {org_domain(host)} ({host}) — the part before "
                        f"the real domain, which is the part a hurried reader "
                        f"stops at. The site is controlled by "
                        f"{org_domain(host)}, not by {brand}.",
                        "A brand's own campaign microsites and agency-hosted "
                        "pages can look like this; the operator's brand list "
                        "decides.",
                    ))

        path_and_query = url[len(url.split("://")[0]) + 3 + len(host):].lower()
        if any(p in path_and_query for p in _CREDENTIAL_PATHS) and (
            "credpath" not in seen
        ):
            seen.add("credpath")
            signals.append(_signal(
                "credential_harvest_path",
                "weak",
                f"The link path targets an authentication surface "
                f"({url[:140]}).",
                "Every SaaS product has a /login; this is only meaningful "
                "combined with a lookalike domain or failed alignment.",
            ))

        fragment = url.split("#", 1)[1] if "#" in url else ""
        for recipient in recipients:
            # Word-bounded and length-floored: an unbounded substring test
            # makes a two-character user id match ordinary anchor text
            # (review catch), and a STRONG signal must not hinge on that.
            if (
                recipient
                and len(recipient) >= 4
                and re.search(
                    rf"(?<![a-z0-9._%+-]){re.escape(recipient.lower())}"
                    rf"(?![a-z0-9._%+-])",
                    fragment.lower(),
                )
            ):
                if "recipfrag" not in seen:
                    seen.add("recipfrag")
                    signals.append(_signal(
                        "recipient_in_url_fragment",
                        "strong",
                        f"The recipient's own address appears in the link's "
                        f"fragment ({recipient}), which phishing kits use to "
                        f"pre-fill the fake login form so the page looks "
                        f"personalized. Fragments are never sent to the "
                        f"server, so this is client-side pre-fill.",
                        "Legitimate mailers put addresses in the QUERY "
                        "string for unsubscribe links, not the fragment.",
                    ))
                break

        if from_domain and org_domain(host) != org_domain(from_domain):
            continue  # link-domain difference alone is not reported: noise
    return signals


def _received_signals(headers: dict) -> list[PhishingSignal]:
    """Trace-chain signals. Deliberately narrow: only non-monotonic
    timestamps, because hop count, private IPs, and HELO mismatches are
    normal in legitimate mail and alerting on them is how this kind of
    analysis loses an analyst's trust."""
    received = headers.get(_H_RECEIVED)
    if not isinstance(received, list) or len(received) < 2:
        return []
    from datetime import timedelta, timezone
    from email.utils import parsedate_to_datetime

    stamps = []
    for hop in received[:64]:
        if not isinstance(hop, str):
            continue
        m = _RECEIVED_DATE_RE.search(hop[:MAX_HEADER_CHARS])
        if not m:
            continue
        try:
            stamp = parsedate_to_datetime(m.group(1).strip())
        except (TypeError, ValueError, OverflowError):
            continue
        # RFC 5322 "-0000" means "offset unknown" and CPython returns a
        # NAIVE datetime for it, while "+0000" returns an aware one.
        # Comparing the two raises TypeError, which propagated out of the
        # analyzer and killed the whole investigation for any real-world
        # chain mixing the two — which qmail and several mail appliances
        # produce routinely (review catch). Treat unknown as UTC.
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        stamps.append(stamp)

    # Received is prepended by each MTA: topmost is most recent, so read
    # bottom-to-top for chronological order.
    chronological = list(reversed(stamps))
    # Ordinary MTAs disagree by seconds; only a real inversion is evidence
    # (review catch: one second of NTP drift raised a STRONG signal).
    tolerance = timedelta(seconds=120)
    for earlier, later in zip(chronological, chronological[1:]):
        if later < earlier - tolerance:
            return [_signal(
                "received_chain_non_monotonic",
                "strong",
                f"The trace chain goes backwards in time by "
                f"{(earlier - later).total_seconds():.0f}s: a later hop is "
                f"stamped {later.isoformat()} while the hop before it is "
                f"stamped {earlier.isoformat()} (normalized to UTC). Real "
                f"MTAs stamp in order; hand-written Received headers do not.",
                f"Clock skew between mail servers is normal, so inversions "
                f"under {int(tolerance.total_seconds())}s are ignored; only a "
                f"larger inversion trips this.",
            )]
    return []


def _sanctioned_sender(
    inventory: dict,
    from_domain: str | None,
    authenticated_domains: set[str],
) -> PhishingSignal | None:
    """An operator-recorded sanctioned bulk sender for this author domain.

    Grounded by PROVENANCE, like every other inventory claim: the operator
    wrote it, unlike the message itself. It says the sending arrangement is
    on the record — not that this particular message is safe.

    Only AUTHENTICATED identifiers may be matched against the record
    (review catch): the envelope address and DKIM d= are attacker-writable
    text, so matching them without requiring that they actually passed let
    a spoof claim the operator's own sanctioned arrangement as cover.
    """
    senders = inventory.get("mail_senders", {})
    if not isinstance(senders, dict) or not from_domain or not authenticated_domains:
        return None
    for author_domain, record in senders.items():
        if org_domain(author_domain) != org_domain(from_domain):
            continue
        authorized = {
            org_domain(d) for d in record.get("authorized_domains", [])
        }
        observed = authenticated_domains & authorized
        if observed:
            provider = record.get("provider", "a sanctioned provider")
            notes = record.get("notes", "")
            fact = (
                f"The operator's inventory records {provider} as an "
                f"authorized sender for {author_domain} using "
                f"{', '.join(sorted(authorized))}, and this message "
                f"AUTHENTICATED under {', '.join(sorted(observed))}. {notes}"
            ).strip()
            return _signal("sanctioned_bulk_sender", "weak", fact, None)
    return None


def analyze_phishing(
    alert: Alert,
    brands_path: str | Path = BRANDS_PATH,
    inventory_path: str | Path | None = None,
) -> PhishingAnalysis | None:
    """Analyze an alert's email headers and links, or return None.

    Returns None unless the alert actually carries email authentication or
    header material — a bare 'email_sender' string is not enough. That
    threshold is deliberate: an alert with nothing to analyze must leave
    the investigation prompt byte-for-byte unchanged, so adding this
    enricher cannot perturb the calibrated behavior of every existing
    alert family.
    """
    raw_log = alert.raw_log if isinstance(alert.raw_log, dict) else {}
    headers = _headers_of(raw_log)
    auth_raw = headers.get(_H_AUTH_RESULTS) or raw_log.get(
        "authentication_results"
    )
    if isinstance(auth_raw, list):
        auth_raw = auth_raw[0] if auth_raw else None
    # Header values arrive from whatever the source system serialized, and
    # a dict or int where a string belongs must not crash an investigation
    # (review catch: a nested-dict Authentication-Results raised TypeError
    # straight out of the analyzer). Anything non-string is ignored.
    if not isinstance(auth_raw, str):
        auth_raw = None
    has_from = isinstance(headers.get(_H_FROM), (str, list))
    if not auth_raw and not has_from:
        return None

    brands = load_brands(brands_path)
    inventory = (
        load_inventory(inventory_path) if inventory_path is not None
        else load_inventory()
    )

    auth = parse_authentication_results(auth_raw or "")
    raw_from = headers.get(_H_FROM)
    from_value = raw_from[0] if isinstance(raw_from, list) and raw_from else raw_from
    from_addr = _address_of(from_value if isinstance(from_value, str) else None)
    dmarc = _method(auth, "dmarc")
    from_domain = _domain_of(from_addr) or dmarc.get("header.from")

    spf = _method(auth, "spf")
    mailfrom = spf.get("smtp.mailfrom")
    # A null return-path ("<>", bounces and NDRs) authenticates nothing for
    # DMARC: SPF may only have checked the HELO identity, which RFC 9989
    # explicitly excludes from alignment (review catch).
    if mailfrom in ("<>", "", "@"):
        mailfrom = None
    envelope_domain = _domain_of(mailfrom) or mailfrom
    spf_aligned = _aligned(envelope_domain, from_domain)

    # Alignment is evaluated PER SIGNATURE and only over signatures that
    # themselves passed: attaching a passing verdict to a different
    # signature's d= is how a tool reports alignment that does not exist.
    dkim_sigs = _dkim_signatures(auth)
    passing_dkim = [s for s in dkim_sigs if s.get("result") == "pass"]
    aligned_dkim = next(
        (
            s for s in passing_dkim
            if _aligned(
                s.get("header.d") or _domain_of(s.get("header.i")), from_domain
            ) is True
        ),
        None,
    )
    reported_dkim = aligned_dkim or (
        passing_dkim[0] if passing_dkim else (dkim_sigs[0] if dkim_sigs else {})
    )
    dkim_domain = reported_dkim.get("header.d") or _domain_of(
        reported_dkim.get("header.i")
    )
    dkim_aligned = (
        True if aligned_dkim is not None
        else _aligned(dkim_domain, from_domain)
    )
    aligned_pass = (
        spf.get("result") == "pass" and spf_aligned is True
    ) or aligned_dkim is not None

    # Trust boundary (RFC 8601 §5): only the topmost Authentication-Results
    # is authoritative; anyone can type the header into a message.
    extra_auth = 0
    if isinstance(headers.get(_H_AUTH_RESULTS), list):
        extra_auth = max(0, len(headers[_H_AUTH_RESULTS]) - 1)
    # ARC is only CLAIMED here — validating a seal needs the sealer's key
    # and a trust list, neither of which this analyzer has, so an attacker
    # can write the header (review catch). It is reported as claimed.
    arc_claimed = bool(
        headers.get(_H_ARC_AUTH)
        or any(e.get("result") == "pass" for e in auth.get("arc", []))
    )

    recipients = [u for u in alert.indicators.get("users", []) if isinstance(u, str)]
    recipients += [
        r for r in [raw_log.get("recipient"), raw_log.get("email_recipient")]
        if isinstance(r, str)
    ]

    urls = _urls_in(raw_log)
    signals: list[PhishingSignal] = []
    signals += _auth_signals(
        auth, arc_claimed, from_domain, spf_aligned, dkim_aligned, aligned_pass
    )
    signals += _header_signals(headers, brands, from_addr, from_domain)
    signals += _url_signals(urls, brands, from_domain, recipients)
    signals += _received_signals(headers)

    if extra_auth:
        signals.append(_signal(
            "untrusted_authentication_results",
            "moderate",
            f"{extra_auth} additional Authentication-Results header(s) below "
            f"the boundary MTA's own were ignored: anyone can write that "
            f"header into a message, so only the topmost one is evidence.",
            "Inbound security gateways that re-inject a message legitimately "
            "add their own.",
        ))

    # Only identifiers that actually authenticated may be matched against
    # the operator's sanctioned-sender record.
    authenticated_domains: set[str] = set()
    if spf.get("result") == "pass" and envelope_domain:
        authenticated_domains.add(org_domain(envelope_domain))
    for sig in passing_dkim:
        d = sig.get("header.d") or _domain_of(sig.get("header.i"))
        if d:
            authenticated_domains.add(org_domain(d))
    sanctioned = _sanctioned_sender(
        inventory, from_domain, authenticated_domains
    )
    if sanctioned:
        signals.append(sanctioned)

    strong = sum(1 for s in signals if s.strength == "strong")
    moderate = sum(1 for s in signals if s.strength == "moderate")
    summary = (
        f"Email authentication: SPF {spf.get('result', 'absent')}"
        f" (aligned: {spf_aligned}), DKIM "
        f"{reported_dkim.get('result', 'absent')}"
        f" (aligned: {dkim_aligned}) over {len(dkim_sigs)} signature(s), "
        f"DMARC {dmarc.get('result', 'absent')}. "
        f"{strong} strong and {moderate} moderate signal(s) over "
        f"{len(urls)} link(s) examined. Organizational domains use a "
        f"committed approximation of the public-suffix rules, not a live "
        f"list."
    )

    return PhishingAnalysis(
        header_from=from_addr,
        envelope_from=envelope_domain,
        dkim_domain=dkim_domain,
        spf_result=spf.get("result"),
        dkim_result=reported_dkim.get("result"),
        dmarc_result=dmarc.get("result"),
        spf_aligned=spf_aligned,
        dkim_aligned=dkim_aligned,
        arc_present=arc_claimed,
        urls_examined=urls,
        signals=signals,
        summary=summary,
    )

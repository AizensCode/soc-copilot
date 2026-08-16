# Fixtures waiting on a cassette recording

These two alerts are complete and their deterministic analysis is already
tested (`tests/test_phishing.py`, the QR/attachment-channel section). They
are **not** in `data/sample_alerts/` yet because adding them there is a red
test until their indicators exist in the committed reputation cassette:

    tests/test_cassette.py::test_committed_cassette_covers_every_pinned_indicator

That guard is correct and deliberate — "adding a fixture with a new
indicator is a red test until it is recorded" — and satisfying it means
running the recorder:

    ABUSEIPDB_API_KEY=... VIRUSTOTAL_API_KEY=... URLSCAN_API_KEY=... \
        uv run python -m tests.record_cassette

**Why that was not done automatically.** The recorder is all-or-nothing: it
re-records *every* indicator any pinned fixture reaches and overwrites
`data/evals/cassettes/reputation.json` wholesale. That file is the frozen
ground truth the whole calibrated corpus reproduces its verdicts from, and
re-recording it moves real numbers — the last refresh took this repo's
pinned Tor exit node from 100/100 to 81 (see the README's "The harness
brings its own reputation, too"). Refreshing the ground truth for 21
calibrated fixtures is a deliberate decision about the eval baseline, not a
side effect of adding two files.

## To land them

1. Run the recorder above, and review the diff to `reputation.json` — the
   summary fields (scores, `found` flags) are what matter; the verbose
   detail arrays churn between records by design.
2. `git mv data/sample_alerts/pending/*.json data/sample_alerts/`
3. Add `EXPECTATIONS` entries in `tests/expectations.py`. Keep them honest:
   they are predictions until `python -m tests.calibrate` has recorded
   per-property pass rates the way every other entry carries them. The
   deterministic half is already pinned by unit tests, so the entries only
   need to assert model behavior (verdict, escalation, technique mapping).

## What the pair is for

`phishing_qr_mfa_lure.json` is quishing: the entire payload is a QR code, so
the message body carries **no links at all** and every URL-based defense has
nothing to bite on. Authentication passes and aligns — the attacker owns the
sending domain — so the discrimination has to come from the QR destination
(brand in the subdomain, recipient's address in the fragment, host unaligned
with the sender).

`benign_qr_mfa_enrollment.json` is its twin: same pretext, same channel, same
absence of body links, opposite verdict. The analyzer grades the attack
3 strong / 2 moderate and the twin 0 strong / 0 moderate / 2 weak, so a model
that calls the twin malicious is reading the *channel* as the verdict —
which is exactly the failure the twin exists to catch.

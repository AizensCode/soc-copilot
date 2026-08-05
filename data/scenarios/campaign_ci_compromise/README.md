# Scenario: CI build-server compromise (3 stages, one campaign)

The labeled set under `data/sample_alerts/` is deliberately
**memory-decoupled**: no two fixtures share an IOC or a host, because
cross-alert memory is global to a harness run and shared indicators make
results depend on execution order (`tests/test_fixtures.py` enforces
this).

That leaves one thing unmeasurable there: what the copilot does when
alerts *are* related. This directory is the counterpart — a scenario
where the coupling **is** the experiment. It is loaded only by
`tests/test_campaign_scenario.py`, which gives it a private history
store, so it never touches the labeled set's invariants.

## The story

An attacker with valid `svc-jenkins` credentials reaches an
internet-exposed CI build server, dumps credentials from it, then stages
and exfiltrates a repository archive — three separate detections over
~7 hours that a human analyst would immediately read as one intrusion.

| # | Time (UTC) | Detection | Shape | Links back via |
|---|---|---|---|---|
| 1 | 2026-06-10 22:14 | External SSH auth success, no MFA | **ECS hit** | — |
| 2 | 2026-06-11 01:03 | LSASS credential access by unsigned binary | native | host + `107.189.31.187` |
| 3 | 2026-06-11 04:47 | Archive staged, 2.4 GB uploaded to a bulletproof host | native | host + `107.189.31.187` |

Stage 1 is an ECS-shaped Elastic hit while stages 2–3 are native EDR
fixtures on purpose: a real campaign spans ingestion paths, so this also
holds `history.alert_host` to account — correlation must match
`{"host": {"name": ...}}` against `{"host": "..."}` or the campaign
silently breaks apart into unrelated alerts.

## Grounding notes

- Both attacker IPs are real bulletproof-hosting addresses scoring
  100/100 on AbuseIPDB (verified 2026-08-05), so live enrichment returns
  genuine reputation evidence rather than "unknown".
- `bld-ci-04.corp.internal` and `svc-jenkins` are deliberately **absent**
  from `data/asset_context.json`: an un-inventoried asset must not be
  blessed, and the scenario tests correlation, not environment context.
- Identifiers are decoupled from every fixture in `data/sample_alerts/`,
  so running this scenario cannot leak into the labeled set's results.

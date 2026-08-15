# SOC Copilot — operator runbook

What the unattended deployment does, what it touches, and what to do
when it makes noise. This document covers the `--watch` service; the
one-shot CLI commands (`--scorecard`, `--digest`, `--sync-feedback`,
single-alert runs) need nothing beyond a shell in the same directory.

## What the process is

One Python process polling Elastic for open alerts, investigating each
with the Anthropic API, and writing results back. Its policy flags are
the operator's decisions, not defaults: `--auto-close` (autonomous
closure of high-confidence false positives behind a deterministic
gate), `--notify` (webhook pages for escalations), `--case` (TheHive
alerts), `--dedup` (suppress near-duplicate repeats), `--tiered`
(cheap-model first pass), `--agentic` (tool-using investigations).
Start with none of them; add each after it earns trust (the README's
calibration story is the evidence trail).

## Everything it writes

| Where | What | Nature |
|---|---|---|
| `data/history/investigations.jsonl` | every investigation record | append-only JSONL |
| `data/history/dispositions.jsonl` | analyst rulings synced from TheHive | append-only |
| `data/history/closures.jsonl` | autonomous closures the desk performed | append-only |
| `data/history/created_alerts.jsonl` | provenance ledger of TheHive alerts it opened | append-only |
| Elastic results index | investigation docs, analyst-ruling annotations | remote |
| Elastic **alerts** index | status updates (acknowledged/closed) on worked alerts | remote |
| TheHive (with `--case`) | alert objects for escalations | remote |
| Webhook (with `--notify`, and health pages) | JSON POSTs | remote |

A least-privilege Elastic key therefore needs **write on both
indices** — results (index docs) and alerts (update status). Granting
only the results index makes every acknowledgement 403 *after* the paid
investigation succeeded, which the watchdog will eventually report as a
systemic outage.

Nothing else. No temp files, no logs on disk (stdout is the log —
capture it with `journalctl`/`docker logs`), no writes outside `data/`.
The systemd unit enforces that with `ProtectSystem=strict`.

**The history files are the copilot's memory.** Losing them loses
prior-sighting context, dedup anchors, the scorecard's evidence, and
the provenance ledger that lets analyst rulings be trusted. Back up
`data/history/` like you back up any small append-only database — and
beside it, the two operator-owned inputs a rebuild cannot regenerate:
`data/asset_context.json` (your tuned inventory, the false-positive
discriminator) and `.env` (secrets — store it wherever you keep
secrets, not with the data).

## Exit codes and restarts

| Code | Meaning | Right response |
|---|---|---|
| 0 | clean end (one-shot commands) | none |
| 1 | configuration error (missing/invalid key, bad `WEBHOOK_URL`) — printed as one line, at startup | fix `.env`, start again |
| 2 | two distinct causes, easy to tell apart: an **instant** exit 2 with a usage message is argparse rejecting a flag (fix the command); an exit 2 after ~30 minutes is **the watchdog giving up** on systemic failure (fetch crashing, or 2+ distinct alerts all failing) | typo: fix the flag. Watchdog: the supervisor restarts it; if it exits 2 again, read stdout — the cause is printed every cycle |
| 130 | operator Ctrl+C | none |
| 143 | SIGTERM (`docker stop` / `systemctl stop`) | none — this is what stopping looks like |

Both shipped supervisors (`restart: unless-stopped` in compose,
`Restart=on-failure` in the unit) catch exit 2. Only the systemd path
re-reads `.env` on restart; a compose policy restart reuses the env the
container was CREATED with, so after editing `.env` run
`docker compose up -d` (compose sees the changed env file and
recreates). The systemd unit stops
retrying after 10 failures in an hour so a hard-broken config becomes a
visibly failed unit instead of an infinite flap.

## Health pages

If `WEBHOOK_URL` is set, the loop pages **about itself** — even without
`--notify` (that flag gates per-alert noise; the desk being down is the
one message the channel exists for):

- after ~3 minutes of completing no work: one page per outage **per
  process lifetime** — under a supervisor, a persistent systemic outage
  therefore re-pages each restart round, roughly twice an hour, which is
  a deliberate reminder cadence rather than a pager storm; text
  beginning `🤒 soc-copilot watch loop is unhealthy` — check stdout for
  the per-cycle cause (`FAILED (will retry next cycle): ...` or
  `Poll cycle failed: ...`);
- just before an exit-2: a goodbye page saying it is handing over to
  the supervisor.

A page that names ONE alert id failing repeatedly with a quiet queue is
a poisoned record, not an outage: the process deliberately stays up.
Acknowledge or fix that alert in Elastic and the loop moves on.

## Stopping, restarting, upgrading

Stopping is `docker compose down` / `systemctl stop soc-copilot-watch`.
There is no graceful drain yet (roadmap): a stop mid-alert kills that
alert's work. This is SAFE by construction — the store records a
closure only after both Elastic writes succeed, so an interrupt can
undercount automation but never invent a closure, and the interrupted
alert is still open in Elastic and gets worked on next start. Upgrades
are: stop, pull/rebuild, start; there are no migrations — the history
files are append-only JSONL that new code reads as-is (records from
before a field existed are handled explicitly, see the store's tests).

## Rotating the history

The store reads incrementally and tolerates file replacement, but the
supported rotation is offline: stop the service, move
`data/history/*.jsonl` to an archive, start. Note what rotation costs:
prior sightings, dedup anchors, and scorecard evidence only see the
live files — rotate when history is old enough that losing its context
is acceptable, not on a size threshold. For scale: at 100k records
(~400 MB) the incremental store parses appends in well under a
millisecond, and the correlation/memory scans dominate at roughly a
tenth of a second per alert — noticeable, nowhere near a reason to
throw away context.

## Docker specifics

One-time setup, then build and run:

    echo "HOST_UID=$(id -u)" >> .env
    echo "HOST_GID=$(id -g)" >> .env
    docker compose up -d --build
    docker compose logs -f watch

(Not a `UID=... docker compose up` prefix: bash keeps `UID` readonly
and unexported, so that command prints a warning, passes nothing, and
the container silently runs as the fallback uid — on any host that
isn't uid 1000, every history write then fails after the paid model
call. Setting `HOST_UID`/`HOST_GID` once in `.env` is read by compose
on every invocation.)

Snap-installed Docker cannot bind-mount paths outside your home
directory (a `/tmp` checkout mounts as an empty root-owned dir and every
history write fails with `PermissionError`) — keep the checkout under
`$HOME`, or install Docker from the official repositories.

`.env` is read at start via `env_file:` and is never in the image
(`.dockerignore` keeps it, and any local `data/history/`, out of the
build context). With `HOST_UID`/`HOST_GID` set, the container runs as the host
user so the bind-mounted `data/` stays writable on both sides. One-shot commands reuse the same
image:

    docker compose run --rm watch --scorecard

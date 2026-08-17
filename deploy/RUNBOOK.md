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
| `data/history/watch_progress.jsonl` | the watch loop claiming (`started`) and finishing (`completed`) each alert | append-only |
| `data/history/archive/<stamp>/` | records aged out by `--rotate-history` | written only by that command |
| Elastic results index | investigation docs, analyst-ruling annotations | remote |
| Elastic **alerts** index | status updates (acknowledged/closed) on worked alerts | remote |
| TheHive (with `--case`) | alert objects for escalations | remote |
| Webhook (with `--notify`, and health pages) | JSON POSTs | remote |

A least-privilege Elastic key therefore needs **read and write on both
indices**. Write: results (index docs) and alerts (update status) —
granting only the results index makes every acknowledgement 403 *after*
the paid investigation succeeded, which the watchdog will eventually
report as a systemic outage. Read: the alerts index is searched every
poll cycle, and the results index is searched twice — by
`--sync-feedback` to stamp analyst rulings onto the docs it annotates,
and by the resume path to check whether an interrupted run had already
indexed its result. Elastic's `write` privilege does not imply `read`,
so a write-only key fails both, and the resume failure surfaces as a
failed alert on the first cycle after a crash-restart.

Nothing else. No temp files, no log files on disk — the process's
streams are the log, and `journalctl`/`docker logs` capture both:
narration (progress, failures, health) goes to **stderr** with a level;
a command's product (an investigation JSON, the scorecard) goes to
**stdout**, pipeable. No writes outside `data/`. The systemd unit
enforces that with `ProtectSystem=strict`.

## Reading the log

Two knobs in `.env`, validated loudly at startup:

- `LOG_FORMAT=json` emits one `{"ts","level","msg","alert_id"}` object
  per line (`ts` is UTC ISO-8601; `alert_id` is present on every line
  logged while that alert was being worked, so
  `jq 'select(.alert_id=="X")'` replays one alert's story). The default
  `text` is the same prose as always, message-only — journald and
  docker already stamp timestamps, so the copilot doesn't double them.
- `LOG_LEVEL` (default `INFO`): progress is INFO, degraded-but-
  continuing (a failed webhook page, a TheHive outage, a feedback-sync
  miss) is WARNING, a failed alert or cycle is ERROR. `journalctl -p
  warning` is the "problems only" view of an unattended night — health
  lines are WARNING and up, so that view never hides them.

Under the systemd unit the `journalctl -p` filter works because the
copilot detects that stderr is the journal socket (`$JOURNAL_STREAM`)
and prefixes each line with the sd-daemon `<N>` priority token, which
journald strips and records as the line's real priority. Without that,
every captured line would sit at the unit default (info) and the
filtered view would be empty. The prefix appears ONLY when stderr is
the journal — terminals, pipes, and Docker never see it. `docker logs`
has no priority filter at all: there, use `LOG_FORMAT=json` and filter
with `jq 'select(.level != "INFO")'`.

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
| 0 | clean end: one-shot commands, and a **drained stop** of `--watch` (SIGTERM finished the in-flight alert and exited) | none |
| 1 | configuration error (missing/invalid key, bad `WEBHOOK_URL`) — printed as one line, at startup | fix `.env`, start again |
| 2 | two distinct causes, easy to tell apart: an **instant** exit 2 with a usage message is argparse rejecting a flag (fix the command); an exit 2 after ~30 minutes is **the watchdog giving up** on systemic failure (fetch crashing, or 2+ distinct alerts all failing) | typo: fix the flag. Watchdog: the supervisor restarts it; if it exits 2 again, read the log (stderr — `journalctl`/`docker logs` capture it): the cause is printed every cycle |
| 130 | operator Ctrl+C | none |
| 143 | SIGTERM outside a drain: a **second** signal during a watch drain (immediate stop on request), a signal arriving during watch *startup* before the drain handler is installed, or a signal to a one-shot command. In each case the process dies **by** the signal, which systemd counts as a clean stop (no `SuccessExitStatus=` needed) | none — this is what an impatient (or non-watch) stop looks like |

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
  beginning `🤒 soc-copilot watch loop is unhealthy` (systemic — the
  exit countdown is real) or `🤒 soc-copilot watch loop is stuck`
  (one poisoned alert; the page says the process stays up, because it
  does) — check the log (stderr) for the per-cycle cause
  (`FAILED (will retry next cycle): ...` or `Poll cycle failed: ...`);
- just before an exit-2: a goodbye page saying it is handing over to
  the supervisor.

A page that names ONE alert id failing repeatedly with a quiet queue is
a poisoned record, not an outage: the process deliberately stays up.
Acknowledge or fix that alert in Elastic and the loop moves on.

Every sick cycle that takes no action itself — from the first, and
through the stretch between the page (3) and the exit (30) — the log
carries a heartbeat at WARNING: `HEALTH: sick streak at N consecutive
cycle(s), pages at 3 ...` (or `paged at 3` once it has), saying which
kind of sick the desk is — `systemic — exits for a supervisor restart
at 30`, or `confined to <alert id> — pages then holds` (the
lone-poisoned-record case above, which never exits). Recovery is
announced the same way (`HEALTH: recovered — work is completing again
after N sick cycle(s)`), at WARNING too, so a `journalctl -p warning`
view that saw the outage start also sees it end.

## Stopping, restarting, upgrading

Stopping is `docker compose down` / `systemctl stop soc-copilot-watch`.
Both deliver SIGTERM, and SIGTERM is a **drain**: the loop finishes the
alert in flight (its model call is already paid for; the verdict is
pushed, the alert acknowledged/closed, the record written), starts
nothing new, and exits 0. Unstarted alerts stay open in Elastic for the
next start.

A **second SIGTERM** stops immediately — the operator saying "now".
How to send it depends on the supervisor, and the obvious move is not
always right:

- **Docker**: run `docker stop` (or `docker compose down`) again; the
  second invocation delivers a second SIGTERM.
- **systemd**: `systemctl kill soc-copilot-watch`. Re-running
  `systemctl stop` does **not** send a second signal — the request
  merges into the pending stop job and you simply wait out the grace.

Both shipped supervisors give the drain 120 seconds
(`stop_grace_period` / `TimeoutStopSec`). That comfortably covers a
*typical* alert (this repo's recorded agentic telemetry is ~48s end to
end) — it is deliberately **not** claimed to cover the worst case,
because there is no bounded one: the Anthropic client uses the SDK
defaults (600s read timeout, 2 retries) and the agentic loop allows 15
iterations, so one stalled model call can outlast any sane grace. Raise
both values if your alerts are slower than your patience. When the
grace does run out, SIGKILL lands and the fallback contract holds — the
store records a closure only after both Elastic writes succeed, so a
kill can undercount automation but never invent a closure, and the
interrupted alert is still open next start.

That still-open alert is picked up on the next start and **finished**,
not re-investigated: the verdict was recorded before any Elastic write,
so the loop replays the writes that never landed rather than paying for
the same conclusion twice (`soc_copilot/resume.py`). You will see one
WARNING per resumed alert naming the original investigation time and
verdict.

What makes an alert resumable is the progress ledger, not guesswork: the
loop writes `started` before it commits to an alert and `completed` once
every effect has landed, and only a `started` with no `completed` is
resumed. Two consequences worth knowing:

- **Re-opening an alert in Elastic to demand a second look always
  works.** A completed alert that comes back is investigated afresh, at
  any interval — the ledger says it finished, so it is not mistaken for
  a crash. (This was the review's sharpest catch: an earlier version
  inferred interruption from "recent record + still open", which silently
  answered an analyst's re-open with the stale verdict, opened a second
  TheHive case and paged twice.)
- **A one-shot `soc-copilot --from-elastic` run never seeds a resume.**
  It records investigations without touching alert status, and it writes
  no progress ledger entry, so the watch service will not later commit
  that dry run's verdicts.

Resuming is additionally bounded to `RESUME_WINDOW_MINUTES` of the
original investigation (default 30; set `RESUME_WINDOW_MINUTES=0` in
`.env` to disable it) and never happens once an analyst has ruled on the
alert. The watch loop's startup line reports which window is in force.

A resume adds no investigation record — it concludes nothing new, so it
records nothing new, and the cost telemetry is not double-counted. It
does write the ledger's `completed` line, and (if the resumed verdict
qualifies under `--auto-close`) a closure record and the case/page the
interrupted run still owed.

Upgrades
are: stop, pull/rebuild, start; there are no migrations — the history
files are append-only JSONL that new code reads as-is (records from
before a field existed are handled explicitly, see the store's tests).

## Rotating the history

Retention, not size. After the index work the store parses appends in
well under a millisecond at 100k records and the memory scans run in
fractions of one, so nothing here is a performance fix. What forces the
issue is that an investigation record contains usernames, mailbox
addresses, hostnames and source IPs, and a retention policy needs a way
to age that out on a schedule.

    soc-copilot --rotate-history [DAYS] [--dry-run] [--include-human-records]

Default 90 days. **Stop the service first.** Records older than the
cutoff are moved to `data/history/archive/<UTC-timestamp>/`; nothing is
deleted, so a rotation you regret is a `cat` away from being undone.
Start with `--dry-run`, which plans through exactly the same code path
and changes nothing.

**Two files are held back on purpose, and the investigation rows their
rulings point at are pinned with them.** The command says so every time
it runs, and reports the pinned count:

- `dispositions.jsonl` — analyst rulings. `closure.py` reads these to
  REFUSE an autonomous close when a human has overturned the copilot on
  a related indicator. Archive them and the desk becomes *more* willing
  to close what a human already called real.
- `created_alerts.jsonl` — the provenance ledger that lets a synced
  TheHive ruling be trusted at all. Archive it and later rulings on
  those cases arrive un-provenanced and are rejected.

Both grow at human speed rather than alert speed, so there is no
operational reason to trim them. `--include-human-records` rotates them
anyway if a retention obligation leaves you no choice — take the safety
cost knowingly.

Holding those two files back is not enough on its own, which is worth
knowing if you ever reason about this yourself: the auto-close gate does
not read `dispositions.jsonl`. It reads the *prior sightings* attached to
an investigation, and those are built by walking the **investigations**
index and only then joining the ruling on. Archive the investigation row
and the retained ruling has nothing to attach to. So any investigation
row whose alert has a ruling is **pinned** — retained regardless of age —
and the report counts them separately from the unclassifiable ones.

What rotating the rest costs, all in the safe direction: prior sightings
and dedup anchors for *unruled* alerts older than the cutoff disappear,
so a repeat that would have been suppressed is investigated afresh (you
pay for a look you could have skipped); the scorecard's automation rate
stops counting the archived closures, and note the scorecard reads the
whole store with no window of its own, so its historical numbers shrink
with the retention you choose; and `watch_progress.jsonl` entries going
away simply means nothing from before the cutoff is resumable.

Records whose age cannot be established — malformed lines, or records
from before `investigated_at` existed — are **kept**, never archived,
and the report counts them. Aging a record out requires knowing it is
old.

If the watch loop is running, rotation aborts with exit 1 and changes
nothing: every file's size is re-checked before any of them is replaced,
so a loop appending mid-rotation is detected rather than silently losing
those records. Detection is not avoidance — stop the service.

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

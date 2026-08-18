# SOC Copilot — operator runbook

What the unattended deployment does, what it touches, and what to do
when it makes noise. This document covers the `--watch` service; the
one-shot CLI commands (`--scorecard`, `--digest`, `--sync-feedback`,
`--tuning-report`, `--propose-inventory`, `--memory-status`,
`--migrate-memory`, single-alert runs) need nothing beyond a shell in the
same directory.

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
| Elastic memory index (shared memory only) | investigation records and analyst rulings, when `HISTORY_BACKEND=elastic` | remote; replaces the first two rows above |
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

## Sharing one memory across the desk

By default the desk's memory is a directory of JSONL files: one process,
one machine, filesystem permissions as the whole access-control story.
That is also strictly single-writer — two processes appending to one file
interleave partial lines — so a second analyst running `--ask`, or a
second watcher, gets a *different* memory rather than a shared one. The
same IP is ruled a false positive on one host and re-investigated from
scratch on the next, and the analyst ruling that would have blocked an
autonomous closure is invisible to the instance about to make it.

`HISTORY_BACKEND=elastic` puts the two ledgers that are facts about the
world into one Elasticsearch index instead.

```bash
# .env
HISTORY_BACKEND=elastic
ELASTIC_URL=https://elastic.internal:9200
ELASTIC_API_KEY=...
ELASTIC_MEMORY_INDEX=soc-copilot-memory      # default
INSTANCE_ID=soc-desk-01                      # default: this host's name
```

**Set `INSTANCE_ID` explicitly.** It defaults to the hostname, which is
right on bare metal and wrong in a container: Docker assigns a fresh
random hostname on every recreate, so a redeploy makes the desk a
stranger to its own history — the guard below refuses to start, and once
past it, dedup and resume stop recognising records the same deployment
wrote yesterday. The shipped compose file pins `hostname:` for the same
reason. Two instances on ONE host need two values here *and* two
`HISTORY_PATH` directories, because the three local ledgers are
single-writer files.

```bash
soc-copilot --memory-status          # provisions the index, reports what it finds
soc-copilot --migrate-memory --dry-run
soc-copilot --migrate-memory         # idempotent; re-run it after any failure
soc-copilot --memory-status          # confirm the counts before moving the local files aside
```

`--memory-status` is the command that answers "am I actually sharing?",
which the configuration cannot: it says what was *asked for*. The status
names the index really reached, the ledgers really shared, this
instance's writer id, and every other instance writing to the same
memory, with counts. It also reports two things that are invisible
everywhere else:

- **Clock skew.** Records are ordered by wall-clock timestamps from
  writers nobody sequences, and each instance re-reads only a window
  behind its own position (5 minutes). Two instances whose clocks are
  further apart than that window **cannot see each other's writes at
  all**, and nothing else notices: both desks look healthy and both
  report full counts. The status prints how far the newest shared record
  is from this host's clock and warns past the window. Run NTP.
- **A half-finished import.** The start-up guard below asks only whether
  this instance is represented at all, so a migration that died a third
  of the way through disarms it with its first record. The status
  compares the local ledgers against what this instance actually put in
  shared memory and says so. Re-run `--migrate-memory`; it imports
  nothing twice.

Migrating while an instance is already running does **not** reach it:
imported records keep their original write times, which are older than
any running tail's window. `--migrate-memory` says so; restart the
watchers.

**Turning it on while a local ledger holds records shared memory has
never seen from this instance is refused**, by ledger, naming the file.
The test is "shared memory holds nothing this instance wrote", not "the
shared index is empty" — emptiness only protects the first desk to join,
and the second analyst to flip the switch would find someone else's
records, sail past, and abandon their own rulings. Starting anyway would discard
every prior sighting and every analyst ruling the safety gates read —
the quiet direction, from one line in a unit file. Either run
`--migrate-memory` or move the local file aside to join without it.

**Going back is guarded too**, and it is the easier accident: `jsonl` is
the DEFAULT, so losing a line of a unit file — or starting the process
from a shell that never read it — would silently swap the desk's memory
for whatever stale local files are still sitting there. A desk that has
run on shared memory leaves a `data/history/.shared-memory` marker;
delete it to go back to local memory on purpose. The rulings ledger is checked separately from the
investigations ledger for a reason: a desk whose investigations migrated
but whose rulings did not looks completely healthy — full history,
sensible reports — while the one gate that lets a human overrule
autonomous closure quietly matches nothing.

### What is shared, and what deliberately is not

| Ledger | Where | Why |
|---|---|---|
| `investigations` | **shared** | evidence; every reader that consumes it can only make the desk louder |
| `dispositions` | **shared** | ground truth, and the thing a second analyst most needs to see |
| `created_alerts` | local | a *trust* ledger — the alert ids whose synced rulings this copilot believes |
| `closures` | local | what *this* instance did autonomously; not evidence about the world |
| `watch_progress` | local | one loop's cursor through its own cycle |

Sharing `watch_progress` would let one instance resume — and re-push, and
re-acknowledge — an alert another instance is working right now. Sharing
`created_alerts` would hand back the property the ruling-provenance work
bought, since it exists precisely because a self-asserted label is not
provenance. Sharing `closures` would let one instance's record make an
alert look already handled in another's morning digest, which is why it
stays local even though it costs a metric: **in shared mode the
scorecard's automation rate understates automation**, counting the whole
desk's investigations against this instance's closures. Read it per
instance, or sum them.

### What sharing changes about safety

Every record now carries the `writer` that produced it, and two readers
check it before acting. Both are asking to do **less** work:

- **dedup's anchor** (`--dedup`) will not borrow a verdict from another
  instance. Borrowing means acknowledging an alert with no model call at
  all, on the strength of one record — one document in an index, and a
  detection is silently off. Two instances on one queue therefore each
  pay for the first copy of a noisy detection. That is a cost in money,
  against a risk of silence.
- **resume** will not finish a run it did not start. "Finish the run
  this loop interrupted" is the premise; delivering someone else's
  record would push a verdict this instance never reached.

A record with **no** writer is not this instance's in shared mode, so it
is cited freely and never borrowed. `--memory-status` counts them.

Analyst rulings are **latest-wins**, in the reports and in the safety
gates alike — one answer to "what did the analyst decide". A shared
ledger does make that a way to *cancel* a block (a later
`false_positive` on an alert ruled a true positive removes both the
autonomous-close block and dedup's fingerprint-wide refusal), and there
was a per-writer rule here to stop it. It was removed: `writer` is a
field in a document, so anything able to append the cancelling ruling
can append it under the blocked writer's name, while a real analyst's
correction could be left unable to land. Which means the ruling ledger's
integrity is the index ACL below, and nothing else.

One consequence to accept deliberately: `--sync-feedback` trusts a ruling
for an alert **this desk handled**, and with shared memory "this desk"
becomes every instance writing to the index, not just this process. Two
things follow, and both are worth knowing before you turn it on. The
trusted set of alert ids grows to everything any instance ever
investigated. And for the alerts this instance did not itself open a
TheHive case for, there is no `created_alerts` entry to id-match the
incoming ruling against, so those rulings are trusted on the alert id
alone — the same footing as rulings on investigations that predate the
provenance ledger. Whoever can post into your TheHive feed can therefore
claim a ruling on any alert the desk has ever worked. That is what
sharing a memory means; it is also why the next paragraph is the
important one.

### The index's write ACL is the security boundary

`writer` is self-asserted. It separates honest instances from each other;
it does not separate an attacker from the desk, because anything that can
write to the memory index can write any `writer` it likes. Provision the
key accordingly:

- The copilot instances need **read and write** on the memory index.
- **Nothing else should have write on it.** A dashboard, an ingest
  pipeline or a shared "elastic admin" key with write here is a way to
  plant a prior sighting, a ruling, or an anchor.
- Keep it a **separate index** from the results index. That one is a
  dashboard surface whose documents other things may map and mutate;
  this one is the desk's memory and its mapping is load-bearing.

That mapping matters more than it looks. `record` is stored but **not
indexed** (`"enabled": false`), because a record carries full alert and
investigation dumps and a dynamically mapped index hits
`index.mapping.total_fields.limit` and then starts *rejecting* writes —
a desk that stops remembering without saying so. `--memory-status`
refuses to use an index whose `record` is mapped any other way, which is
what an index auto-created by a stray write looks like.

### Retention, and two watchers

`--rotate-history` splits local JSONL files, so in shared mode it rotates
the local ledgers and **holds the shared ones back**, saying so. Retention
on the memory index is the cluster's job — an ILM policy or a scoped
delete-by-query — and it must pin the same rows this command pins: the
investigation row an analyst ruling points at. Archive that row and the
carefully retained ruling has nothing to attach to, the prior sighting
never exists, and a documented block on autonomous closure silently
becomes an auto-close.

Shared memory shares **memory, not work assignment**. Two `--watch`
instances polling the same alert index will both pick up the same open
alert and both pay for it; nothing here leases an alert. Partition the
queue (different Elastic queries per instance) or run one watcher and as
many read-only `--ask`/report users as you like — the second shape is the
one this was built for.

Finally: a memory outage **fails loudly**. A store that answered "no
prior sightings" because the cluster was unreachable would turn every
gate that rests on memory off at exactly the moment nobody is watching,
so a read that cannot reach the index raises, the cycle is marked sick,
and the dead-man's switch above takes it from there.

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
with shared memory, back up the memory index too and keep backing up
`data/history/`, which still holds the three local ledgers. And beside
them, the two operator-owned inputs a rebuild cannot regenerate:
`data/asset_context.json` (your tuned inventory, the false-positive
discriminator) and `.env` (secrets — store it wherever you keep
secrets, not with the data).

## Exit codes and restarts

| Code | Meaning | Right response |
|---|---|---|
| 0 | clean end: one-shot commands, and a **drained stop** of `--watch` (SIGTERM finished the in-flight alert and exited) | none |
| 1 | configuration error (missing/invalid key, bad `WEBHOOK_URL`) — printed as one line, at startup. With `HISTORY_BACKEND=elastic`, a memory index that cannot be reached at startup lands here too: the desk refuses to begin with no memory rather than begin with a blank one | fix `.env`, start again. If the message names the memory index, the cluster is the problem — the supervisor will keep retrying until the start limit turns it into a failed unit |
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

**With shared memory this command only rotates what is still local.**
The investigations and rulings ledgers live in the memory index, which
this command cannot split; it lists them as held back and points at the
cluster. Everything above about pinning applies just as hard there — an
ILM policy or delete-by-query that ages out an investigation row whose
alert carries a ruling turns a documented block on autonomous closure
into an auto-close, and no warning will be printed by anything. The
three local ledgers are still rotated normally, which matters because
`watch_progress.jsonl` grows two lines per alert whatever the backend
is.

If the watch loop is running, rotation aborts with exit 1 and changes
nothing: every file's size is re-checked before any of them is replaced,
so a loop appending mid-rotation is detected rather than silently losing
those records. Detection is not avoidance — stop the service.

## Response actions in the output

Every true-positive investigation carries a `response_actions` list —
typed containment steps derived deterministically from its own findings
(`soc_copilot/actions.py`). They appear in the JSON, in the HTML report,
in the TheHive case description, and as a narration block on stderr.

**Nothing in this repo executes them.** They are proposals. Read the
status before acting:

| Status | Means |
|---|---|
| `proposed` | Nothing the desk knows argues against it. |
| `needs_approval` | The target is operator-inventoried infrastructure (owner named), or shared infrastructure such as a widely-scanned domain. Get the owner's agreement first. |
| `withheld` | The desk considered it and refused. The rationale says why — read these, or you will make the same call by hand without the reason. |

The `basis` field is not cosmetic. `reputation` means external ground
truth about the target itself and holds whatever this alert turns out to
be. `technique` means the investigation's ATT&CK mapping — a model
judgment about *this* alert. `analysis` means a deterministic analyzer's
finding. Weigh a `technique`-grounded `disable_account` differently from
a `reputation`-grounded `block_ip`.

Two limits worth knowing before you work the list in bulk:

- **The inventory gate reaches only what the asset matcher matched** —
  IPs, hosts, service accounts and SaaS apps, from *this* alert. An
  entity your inventory documents but the matcher did not match on this
  alert cannot be gated by it. Keeping `data/asset_context.json` current
  is what makes `needs_approval` fire.
- **A `block_ip` is a perimeter change and the desk does not know your
  topology.** It refuses non-routable addresses and AbuseIPDB-whitelisted
  ones; it cannot know that a given address is your own egress NAT.

## Keeping the inventory current

    soc-copilot --propose-inventory [DAYS]

Read-only, no API calls, safe to run while the watch loop is running.
**It writes nothing to `data/asset_context.json`** — it prints evidence
for entries you write by hand.

`data/asset_context.json` is the trust anchor: it is the one source the
copilot may cite for "this is sanctioned infrastructure", and its own
header warns that a stale entry blessing a decommissioned scanner is an
attacker's best friend. Keeping it current is an operator job, and this
command is the input to it.

What it prints:

- **CANDIDATES** — identifiers that recurred in 3+ alerts *analysts
  dismissed*, across 2+ days, and are not already in the inventory. Only
  analyst rulings count; the copilot's own false-positive verdicts are
  never evidence here, because an entry learned from model output would
  let the desk cite its own opinion back at itself as authority.
- **REFUSED** — recurred, but an analyst has since confirmed a true
  positive on the same entity. Do not write these.
- **STALE ENTRIES** — already in your inventory, *and* since confirmed in
  a true positive. This is the dangerous row: an entry that is currently
  telling every investigation the asset is sanctioned, on an asset the
  desk has been wrong about. Re-read it.
- A JSON fragment with `role`, `owner` and `notes` left as **TODO**. It
  is deliberately not paste-ready. `role` is the sentence a future
  investigation will cite to call activity routine; the desk has shown
  the identifier recurs in dismissed alerts, which is not the same claim.

Read the caveats on individual rows. A `service_accounts` proposal only
means the identifier arrived in a `user.name` field — a **person's**
account recurring in dismissed alerts is a case for training or a
detection change, not an entry that blesses it as automation. An `ips`
entry is only a pointer to a `hosts` entry and grants the bare role
"inventoried asset" on its own.

`DAYS` bounds the evidence, never the refusals: an entity an analyst has
ever confirmed is refused whatever window you pass, because an inventory
entry does not expire the way a report does.

## Tuning the detections

    soc-copilot --tuning-report [DAYS]

Read-only, no API calls, safe to run while the watch loop is running.
Without `DAYS` it reads all recorded history; with it, the window bounds
which detections appear and their volume figures — **not** the safety
checks, which always read the whole store (see below).

What it prints, and what each part is worth:

- **NOISY DETECTIONS** — 80%+ false positive over at least 5 firings and
  at least 2 judged alerts. Both floors matter: firings count every
  alert the rule raised including near-duplicates the desk suppressed
  without judging, so without the second floor a rule with 39 suppressed
  repeats of one investigated alert reads as "100% false over 40
  firings" on the strength of a single verdict.
- The rate line says how much of it a **human** confirmed. The rest is
  the copilot's opinion. Do not tune a production sensor on an unruled
  rate without reading the alerts.
- Lines beginning `!` are **blockers** — this rule has caught
  analyst-confirmed true positives, or its false-positive calls have
  been overturned. They are printed beside the rate, never averaged in.
- `->` is the actionable half: the entity present in **every** one of
  that rule's false positives, preferring one your asset inventory
  documents. **Scope an exception to that entity — do not disable the
  rule.** If the report says NO SAFE EXCEPTION, the entity you would
  have excepted is one this same rule already caught something on, and
  it names the alert.
- **ALSO CONSIDERED AND REFUSED** appears when a safe candidate exists
  alongside refused ones. Read it. The alias map only links identifiers
  your inventory linked, so a host and its own address are unrelated
  strings to it: "safe" can mean "we could not tell it was the same
  box". Confirm before you write the exception.
- **UNDER-RANKED** is the opposite direction and has no volume
  threshold — one analyst-confirmed true positive that arrived as
  `low`/`medium` is a finding. Raising a detection costs attention;
  quieting one can cost you an attack.

Two scoping rules worth knowing before you act on it:

- **The window never scopes the safety.** Blockers, the true positives
  an exception is checked against, the alias map and the technique table
  all read the whole store regardless of `DAYS`. An exception is a
  permanent change to a sensor and must not get easier to recommend
  because you typed a smaller number.
- **Rotation shrinks the evidence.** `--rotate-history` archives
  investigation rows, and this report reads them. After a rotation a
  rule's firing counts and its true-positive blockers both cover only
  what remains — rulings are pinned, but an old true positive on an
  unruled alert is not. Run the tuning report *before* a rotation if you
  are about to act on it.

Detections are keyed by the rule name the source recorded
(`kibana.alert.rule.name` and the other shapes in `_RULE_PATHS`), and by
the alert title when the source named no rule. Title-keyed rows are
marked `[key derived from title]` and never share a row with a
rule-keyed one. A templated title (Kibana's `reason`) splits one rule
across many rows, so each lands under the floor and nothing is
recommended — noise hidden rather than invented, which is the direction
to fail in.

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

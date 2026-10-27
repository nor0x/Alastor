# Alastor architecture

Alastor is an orchestrator and control plane, not a security engine. Each capability is provided by an
established open-source tool (fail2ban, CrowdSec, Trivy, Lynis, …). Alastor installs or adopts the
tool, owns a clearly marked slice of its configuration, reads the tool's own structured output, and
normalizes everything into one event model, one policy model and one dashboard.

```
          ┌──────────────── alastor-server (one binary) ───────────────────────┐
browser ──┤ Svelte SPA (embedded) · REST /api · SignalR /hubs/dashboard          │
          │ EF Core → SQLite (WAL) | PostgreSQL · workers (presence, retention,  │
          │ threat feed ← NVD, CISA KEV, security news RSS; blocklists; Trivy/   │
          │ Grype database mirror)                                               │
          └──────────▲───────────────────────────────▲──────────────────────────┘
                     │ HTTPS REST (pull)             │ SignalR /hubs/agent ("wake" only)
          ┌──────────┴───────────── alastor-agent (per host) ───────────────────┐
          │ Supervisor: heartbeat → reconcile → commands      EventPump (5 s)     │
          │      │ IToolIntegration                                                │
          │      ├── Fail2BanIntegration ── fail2ban-client, jail.d/alastor.local, fail2ban.log
          │      ├── BaselineIntegration, BlocklistIntegration (nft / ipset)
          │      ├── UpdatesIntegration ── apt-get -s / dnf / apk, unattended-upgrade
          │      ├── VulnerabilityIntegration ── trivy rootfs | grype dir:/ (offline, server db)
          │      ├── HardeningIntegration ── lynis audit system --cronjob → report.dat
          │      ├── NetworkIntegration ── tailscale status --json, sshd -T, /proc/net/tcp, ip -j, ufw/nft
          │      ├── (CrowdSec, ClamAV, … later)
          └───────────────────────────────────────────────────────────────────────┘
```

## 1. The normalized Event model

`src/Alastor.Core/Events/SecurityEvent.cs`. Every tool's output becomes this shape **on the agent**, so the
server's pipeline, storage and UI contain no tool-specific code.

```csharp
public sealed record SecurityEvent
{
    Guid       Id          // agent-generated; content-derived for log lines → re-delivery is idempotent
    DateTime   OccurredAt  // UTC, the tool's timestamp (not read time)
    Capability Capability  // Agent | Banning | Blocklist | Firewall | Updates | Vulnerabilities | Hardening | Network | Malware
    Severity   Severity    // Info < Low < Medium < High < Critical (stored as int so >= filters work)
    string     SourceTool  // "fail2ban", "trivy", "alastor-agent", "alastor-server"
    string     Kind        // dotted, tool-independent: ban.added, auth.failures, tool.error, config.drift, vuln.found …
    string?    Subject     // primary entity: IP/CIDR, CVE id, package, check id
    string     Message     // one human-readable line
    string?    Raw         // verbatim tool output line(s), for forensics
    IReadOnlyDictionary<string,string> Metadata   // jail, count, firstSeen, cvss, version …
    string     DedupKey    // leaky-bucket key for the alert pipeline (default tool:kind:subject)
}
```

The host is **not** a field the agent can set. The server stamps it from the authenticated agent identity,
so one agent cannot forge events for another host.

**fail2ban mapping** (`Fail2BanEventNormalizer`, tested against a real fail2ban 1.1.0 log):

| fail2ban output | Kind | Severity | Notes |
|---|---|---|---|
| `NOTICE [jail] Ban ip` | `ban.added` | Low (Info for `alastor-manual`) | `metadata.manual` |
| `NOTICE [jail] Increase Ban ip (…)` | `ban.increased` | Medium | repeat offender |
| `NOTICE [jail] Restore Ban ip` | `ban.restored` | Info | after fail2ban restart |
| `NOTICE [jail] Unban ip` | `ban.removed` | Info | |
| `INFO [jail] Found ip - …` | `auth.failures` | Info | **aggregated** per (jail, IP) per 5 s batch with `count`, never one event per line |
| `ERROR Failed to execute ban jail … action …` | `tool.error` | High | the ban was recorded but **not enforced** |
| `ERROR` (other) | `tool.error` | Medium | `fail2ban.utils` stderr detail lines are folded into the summary above |
| config apply/drift/conflict/rejection | `config.*` | Info/Medium/High | from the reconcile loop |

## 2. The integration interface

`src/Alastor.Core/Integrations/IToolIntegration.cs`. The supervisor only ever talks to tools through it.

```csharp
public interface IToolIntegration
{
    ToolDescriptor Descriptor { get; }                    // id, capability, license, distro packages
    Task<ToolStatus>      DetectAsync(ct);                // read-only: installed? version? running? ownership? config state?
    Task<ToolStatus>      EnsureInstalledAsync(req, ct);  // adopt if present, else install from distro repos (if policy allows)
    bool                  IsWanted(PolicyDocument);       // does the effective policy want this tool?
    Task<ReconcilePlan>   PlanAsync(req, ct);             // PURE diff desired vs actual; unit-testable, previewable
    Task<ReconcileResult> ApplyAsync(plan, ct);           // validate → atomic swap → reload → verify → roll back on failure
    IAsyncEnumerable<SecurityEvent> CollectEventsAsync(ct); // drain normalized events since last call (every 5 s)
    Task<ReconcileResult> RemoveManagedStateAsync(ct);    // uninstall: remove only what we own
}

public interface IBanProvider      // optional capability (fail2ban, CrowdSec, nftables blocklist)
{
    Task<IReadOnlyList<BanEntry>> ListBansAsync(ct);
    Task<CommandOutcome> BanAsync(IpTarget target, string? reason, ct);
    Task<CommandOutcome> UnbanAsync(IpTarget target, ct);
}
```

Rules every implementation follows:

* **Structured output first.** fail2ban uses `fail2ban-client status`, `get <jail> banip --with-time`,
  `get logtarget`, `-t`, `ping`, `--version`. The log file (whose path comes from `get logtarget`) is read only
  for real-time ban/failure events, which the client cannot stream. That is fail2ban's documented log format.
* **Ownership.** Files we write carry a header with `alastor-revision` and a `alastor-sha256` of the body
  (`ManagedFile`). A hand edit makes the file *Drifted*: it is reported and **not** overwritten until the
  operator clicks *Reclaim*. A file at our path without the marker is *Foreign* and is never touched. A jail the
  admin defines in `jail.local` / `jail.d/*.local` is skipped and reported as a *Conflict*, unless the policy
  sets `takeover: true`.
* **All-or-nothing apply.** Back up, write atomically (temp file + rename), run `fail2ban-client -t`, reload,
  then verify the `alastor-manual` jail is up. Any failure restores the backups and reloads.
* **Never fail silently.** Missing tool, missing package (for example EPEL needed on RHEL), unsupported distro: all
  become `Availability.Unavailable` with a human-readable reason, shown in the capability matrix.
* **Side effects behind seams.** `ICommandRunner`, `IFileSystem`, `IPackageManager` (apt/dnf/apk),
  `IServiceManager` (systemd/OpenRC) and `IStateStore` are all faked in tests.

What the fail2ban integration owns:

| Artifact | Purpose |
|---|---|
| `/etc/fail2ban/jail.d/alastor.local` | Only the jails the policy names, plus `[alastor-manual]`. Never a `[DEFAULT]` section. |
| `/etc/fail2ban/filter.d/alastor-manual.conf` | Empty filter: the manual jail only holds dashboard bans. |
| `[alastor-manual]` jail | `logpath=/dev/null`, `bantime` = `banning.manualBantime` (default permanent); bans persist in fail2ban's own DB. |

## 3. API surface

Live OpenAPI document: `GET /openapi/v1.json`. Auth columns: **R** = signed-in user *or* read-only API key
(`X-Api-Key`); **A** = signed-in admin only; **Ag** = agent credential; **–** = anonymous.
Cookie-authenticated writes must also send `X-Alastor-Request: 1` (CSRF guard on top of `SameSite=Strict`).

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /api/auth/login` · `POST /api/auth/logout` | – | JWT in httpOnly `alastor_session` cookie (rate-limited) |
| `GET /api/auth/me` · `POST /api/auth/password` | R · A | |
| `GET /api/overview` | R | fleet cards, recent alerts, top offenders |
| `GET /api/stats/events?days&hostId&utcOffsetMinutes` | R | events per day by severity (every day, zeros included, in the browser's time zone), counts by capability, top kinds |
| `GET /api/stats/bans?hours&hostId` | R | bans and auth-failure events per hour |
| `GET /api/stats/posture?days&hostId` | R | fleet (or one host's) daily posture from the snapshots: average baseline score and hardening index, CVE and KEV totals, hosts needing updates, reboots, public SSH, malware findings; null where no host reported |
| `GET /api/stats/matrix` | R | host × capability grid: `ok`/`warn`/`bad`/`unknown`/`off` with a short label per cell |
| `GET /api/issues?state&hostId&minSeverity&rule` · `GET /api/issues/summary` · `GET /api/issues/rules` | R | open problems (`state`: open, unacknowledged, acknowledged, resolved, all) with per-severity counts · counts for the navigation badge · rule ids and labels |
| `POST /api/issues/{id}/ack` `{note}` · `POST /api/issues/{id}/unack` | A | acknowledge an open issue (audited); it stops counting in the badge until it resolves or reopens |
| `GET /api/hosts` · `GET /api/hosts/{id}` | R | summaries · detail with capability matrix and policy report |
| `GET /api/hosts/{id}/metrics?hours=` | R | downsampled CPU/mem/disk/load history |
| `GET /api/hosts/{id}/effective-policy` · `/commands` | R | merged YAML and revision · command history |
| `PATCH /api/hosts/{id}` · `DELETE /api/hosts/{id}` | A | rename, group, tags · remove (revokes the agent) |
| `POST /api/hosts/{id}/actions/{reconcile\|reclaim\|refresh-bans\|recheck\|check-updates\|apply-updates\|collect-software\|scan-storage\|scan-vulnerabilities\|run-audit\|check-network\|scan-malware\|check-integrity\|accept-integrity\|scan-rootkits\|accept-rootkits\|reboot}` | A | operator actions (`recheck` re-runs the security baseline; the update and scan actions queue a `run-job` command; `reboot` is refused with 409 while the host is offline) |
| `GET /api/hosts/{id}/updates` | R | pending packages (security first), reboot flag, last install with its log tail, effective update schedules |
| `GET /api/updates` · `POST /api/updates/apply` `{hostIds}` | R · A | per-host update counts across the fleet · "install now" on several hosts |
| `GET /api/hosts/{id}/software` | R | installed packages (version, source package, installed on purpose or as a dependency, protected), each with its update candidate, known CVEs (scan + OSV.dev) and the manual upgrade/remove command; last upgrade/uninstall with its log tail |
| `POST /api/hosts/{id}/software/plan` `{op, package}` · `GET …/software/plan/{commandId}` | A · R | ask the agent for a dry run of `upgrade` or `remove` (a `package-plan` command) · its result |
| `POST /api/hosts/{id}/software/{upgrade\|remove}` `{package}` | A | upgrade or uninstall one package (a `package-action` command, audited) |
| `GET /api/software?all` · `GET /api/software/{name}/hosts` · `POST /api/software/upgrade` `{package, hostIds}` | R · R · A | packages across the fleet with version spread, outdated and vulnerable host counts · the hosts that have one · upgrade it on several hosts |
| `GET /api/hosts/{id}/storage` | R | filesystems, the folder tree, the biggest files, the cleanups that apply (with size, risk and the command to run by hand), the last cleanup and one still running |
| `POST /api/hosts/{id}/storage/cleanup` `{cleanup, confirm?}` | A | run one cleanup by id (a `storage-cleanup` command, audited); destructive ones need `confirm` = the host name |
| `GET /api/storage` · `POST /api/storage/cleanup` `{cleanup, hostIds, confirm?}` | R · A | every host by root disk usage with what it can free, plus the cleanup catalog · one cleanup on every selected host it applies to (destructive: `confirm` = `delete`) |
| `GET /api/hosts/{id}/vulnerabilities` | R | every finding (package, installed → fixed, severity, CVSS, KEV flag, accepted), scanner and database info, ignored-package counts |
| `GET /api/vulnerabilities?minSeverity&fixable&kev&q&limit` | R | fleet view: open CVEs ranked KEV → severity → hosts affected, per-host counts, database mirror status |
| `GET /api/vulnerabilities/db` · `POST /api/vulnerabilities/db/{trivy\|grype}/refresh` | R · A | mirror status · check upstream now |
| `GET /api/hosts/{id}/hardening` | R | latest Lynis audit: hardening index, every warning and suggestion (category, details, solution, accepted), test ids resolved since the previous audit, Lynis status and schedule |
| `GET /api/hosts/{id}/network` | R | latest network check: SSH ports, auth settings, listeners, addresses, firewall verdict, Tailscale state, and the exposure re-assessed with the address the server sees and `network.allowPublicSsh` |
| `GET /api/network` | R | fleet view: per-host SSH exposure, password logins, firewall verdict, Tailscale state |
| `GET /api/hosts/{id}/integrity` | R | latest AIDE run (mode, entries, each changed path with what changed and whether it's critical, watched paths) and rkhunter check (warnings with details, severity and whether `rootkitIgnore` matches), with schedules and tool state |
| `GET /api/hosts/{id}/logins` | R | SSH login sources learned for the host (user, address, first/last seen, count, whether it alerted), the latest login events and the effective `logins` policy |
| `GET /api/hosts/{id}/malware` | R | latest ClamAV scan: findings (path, signature), files scanned, unreadable paths, signature versions, scan settings, ClamAV status and the server mirror's state |
| `GET /api/malware`, `GET /api/malware/db` | R | fleet view (scans on, findings per host) and the ClamAV signature mirror |
| `GET /api/hardening?limit` | R | fleet view: average index, per-host index and counts, warnings and suggestions ranked by hosts affected (accepted excluded) |
| `GET /api/baseline` · `GET /api/baseline/catalog` | R | fleet baseline: per-check pass/fail counts with failing hosts, per-host scores · check catalog |
| `GET /api/hosts/{id}/baseline` | R | every baseline check merged with this host's result, copy-paste commands and the policy key that fixes it |
| `GET/POST/PUT/DELETE /api/groups[/{id}]` | R/A | host groups |
| `GET/POST/DELETE /api/enrollment-tokens[/{id}]` | A | single-use tokens; POST returns the secret once plus the install command |
| `GET/POST/DELETE /api/api-keys[/{id}]` | A | read-only API keys (secret shown once) |
| `GET /api/events?hostId&minSeverity&capability&ip&kind&q&from&before&limit` | R | alert timeline, cursor-paged |
| `GET /api/feed?type&minSeverity&exploited&tag&source&q&sort&order&page&pageSize` | R | threat feed (CVEs + news), offset-paged with `total` |
| `GET /api/feed/sources` · `GET /api/feed/tags?limit` | R | per-source fetch health · most common tags of the last 7 days |
| `GET /api/bans?hostId&q&manual` | R | active bans across the fleet |
| `POST /api/bans` `{target, hostIds?, reason}` | A | manual ban (IP/CIDR) → per-host agent commands |
| `POST /api/bans/unban` `{target, hostIds?}` | A | manual unban |
| `GET/POST/DELETE /api/allowlist[/{id}]` | R/A | global allowlist → fail2ban `ignoreip` on every host, and unbans covered IPs |
| `GET /api/policies` | R | all layers |
| `GET/PUT /api/policies/global` · `/group/{id}` · `/host/{id}` | R/A | current YAML + version list · save new version (422 with issues if invalid) |
| `POST /api/policies/preview` `{scope, targetId, yaml}` | R | validation issues, merged result, rendered fail2ban fragment |
| `GET /api/policies/layers/{layerId}/versions/{v}` · `POST …/revert/{v}` | R · A | history · revert (creates a new version) |
| `GET/POST /api/notifications/channels` · `PUT/DELETE …/{id}` | A | email, webhook and ntfy channels; secret fields are write-only (empty on update = keep) |
| `POST /api/notifications/channels/{id}/test` · `GET /api/notifications/deliveries?channelId&limit` | A | send a test now → `{success, error}` · delivery log |
| `GET /api/blocklists` · `GET /api/blocklists/lookup?ip=` | R | list health and usage, per-host enforcement (backend, entries, dropped packets) · which lists contain an address |
| `POST /api/blocklists/{id}/refresh` | A | fetch one list now |
| `GET /api/audit` | A | audit log |
| `GET /api/about` · `GET /healthz` · `GET /install/{agent.sh,server.sh,alastor.sh}` · `GET /install/agent/{alastor-agent-linux-x64,…-arm64,SHA256SUMS}` | – | licenses · liveness · installers · agent binaries |
| `POST /api/agent/enroll` | – (token) | consume single-use token → `{agentId, agentSecret}` |
| `POST /api/agent/heartbeat` | Ag | metrics + tool statuses + last apply report → `{desiredRevision, pendingCommands}` |
| `GET /api/agent/desired-state` | Ag | effective policy + revision |
| `POST /api/agent/events` | Ag | batch of `SecurityEvent` (≤1000), idempotent |
| `POST /api/agent/baseline` | Ag | one baseline run; the server replaces the host's result set and recomputes the score |
| `POST /api/agent/reports` | Ag | result of a scheduled job (`AgentReport`: updates now, CVE scans and audits later); the server keeps the latest per host and kind |
| `GET /api/agent/vulndb/{trivy\|grype\|clamav-main\|clamav-daily\|clamav-bytecode}` | Ag | mirrored scanner database or ClamAV signature file; `ETag` = sha256 (304 when current), range requests; 503 + `Retry-After` while the first mirror runs |
| `GET /api/agent/blocklist` | Ag | this host's merged blocklist as minimal CIDRs; `ETag`/`If-None-Match` (304), gzip |
| `POST /api/agent/bans` | Ag | full ban snapshot per tool (server replaces that host's active set) |
| `GET /api/agent/commands` · `POST /api/agent/commands/{id}/result` | Ag | pull pending commands · report outcome |
| `/hubs/agent` · `/hubs/dashboard` | Ag · R | SignalR: `Wake(reason)` to agents · `hostUpdated`, `eventsCreated`, `bansChanged`, `policyChanged`, `commandUpdated`, `feedUpdated`, `baselineUpdated`, `issuesChanged` to browsers |

### Agent ↔ server protocol

All data moves over REST and is **pulled** by the agent. SignalR only carries a `Wake` nudge, so if WebSockets,
SSE and long polling are all blocked, everything still works, only later (60 s heartbeat):

1. `heartbeat` → the response says the desired policy revision and whether commands are waiting.
2. If the revision differs (or 5 minutes passed, as a drift check): `desired-state` → plan/apply per tool → the
   next heartbeat carries the `PolicyApplyReport`.
3. If commands are pending: `commands` → execute → `result`, then a fresh ban snapshot.
4. Every 5 s, independently: drain `CollectEventsAsync` from each tool → `events`; push a ban snapshot if it
   changed (or every 5 minutes). Unsent events wait in a bounded in-memory outbox (20k) and are retried.

## 4. Policy model

YAML layers **global → group → host**, each versioned and immutable (`PolicyLayer` / `PolicyVersion`). The
effective policy is the merge of the layers, plus the server's global allowlist. Its revision is a content hash
of a canonical JSON form, so key order never matters. Reverting creates a new version. Validation rejects
unknown keys (with line numbers), bad durations, reserved jail names, and any value that could inject INI lines
into the rendered fail2ban config. It warns about lockout risks (empty allowlist, `maxretry < 3` on sshd).
The default template is `policy/default.yaml`.

### Timings and schedules

**Rule: every recurring or time-based action is configurable.** Nothing user-visible is a hardcoded interval.
There are two places for timings:

* **Per host (policy):** anything that may reasonably differ between groups or hosts. Edited in the dashboard,
  versioned, and overridable per group or host like any other policy key.
* **Per server (env vars):** server-internal housekeeping.

Recurring jobs use one shared type, `Schedule` (`src/Alastor.Core/Policy/Schedule.cs`). Features never parse
times themselves. A schedule is `every 6h` (interval since the last run), a 5-field cron such as `0 3 * * *`
(evaluated in the **host's local time zone**, DST-safe), or `off`. A missed cron run (host down at 03:00)
catches up once when the agent comes back. Each host gets a stable offset in `[0, agent.scheduleSpread)`, so a
fleet doesn't run heavy scans in the same minute. Every key has a built-in default (`ScheduleDefaults`,
`AgentTimings.Default`), so a server whose stored policy predates a key still behaves sensibly. A test keeps
`policy/default.yaml` identical to those defaults. The policy preview returns each schedule's next three run
times, so the editor can show `0 4 * * 1-5` as "Mon 04:00, Tue 04:00, …".

| Policy key | Default | Bounds | Used by |
|---|---|---|---|
| `agent.heartbeatInterval` | `60s` | 10s–1h | heartbeat/poll. Offline detection scales with it per host |
| `agent.driftCheckInterval` | `5m` | 1m–1d | re-verify tool config/daemons without a policy change |
| `agent.eventFlushInterval` | `5s` | 1s–10m | ship tool events to the server |
| `agent.banSnapshotInterval` | `5m` | 30s–1d | full ban-list resync |
| `agent.scheduleSpread` | `30m` | 0–12h | per-host offset for scheduled jobs |
| `agent.offlineGracePeriod` | `24h` | any, or `permanent` | release server-pushed firewall state |
| `blocklists.refreshSchedule` | `every 1h` | ≥1m | agent asks the server for a newer blocklist (conditional, usually a 304) |
| `baseline.checkSchedule` | `every 1h` | ≥1m | security baseline checks; also run at agent start, after policy changes, and on "Re-check now" |
| `updates.checkSchedule` | `every 6h` | ≥1m | refresh package lists and count pending (security) updates; also at agent start and on "Check now" |
| `updates.applySchedule` | `off` | ≥1m | install security updates automatically, e.g. `0 4 * * *`; `off` = report only plus "Install now" |
| `storage.scanSchedule` | `every 12h` | ≥1m | disk usage scan (§5c-2); also at agent start and after every cleanup |
| `updates.inventorySchedule` | `every 6h` | ≥1m | software inventory (§5c-1); also at agent start, after every upgrade or uninstall, and on "Refresh inventory" |
| `vulnerabilities.scanSchedule` | `0 3 * * *` | ≥1m | Trivy/Grype scan of installed packages; also at agent start and on "Scan now" |
| `hardening.auditSchedule` | `0 5 * * 0` | ≥1m | Lynis audit (§5e) |
| `network.checkSchedule` | `every 1h` | ≥1m | SSH exposure and Tailscale check (§5f) |
| `malware.scanSchedule` | `off` | ≥1m | ClamAV, opt-in (D10) |
| *notification digest* | `off` | ≥1m | per channel, set on *Settings → Notifications*; same `Schedule` type, server time zone |

| Server env var | Default | |
|---|---|---|
| `ALASTOR_HEARTBEATINTERVAL` | `60s` | fallback when no policy sets `agent.heartbeatInterval` |
| `ALASTOR_OFFLINEAFTERMISSEDHEARTBEATS` | `3` | |
| `ALASTOR_PRESENCECHECKINTERVAL` | `30s` | offline sweep |
| `ALASTOR_RETENTIONRUNINTERVAL` | `1h` | pruning job |
| `ALASTOR_METRICRETENTION` / `ALASTOR_EVENTRETENTION` | `7d` / `90d` | |
| `ALASTOR_POSTURERETENTION` | `365d` | daily posture snapshots behind the trend charts (one row per host per day) |
| `ALASTOR_ENROLLMENTTOKENTTL` | `24h` | default; overridable per token |
| `ALASTOR_COMMANDREDELIVERAFTER` / `ALASTOR_COMMANDMAXATTEMPTS` | `5m` / `3` | unacknowledged agent commands |
| `ALASTOR_PENDINGCOMMANDTTL` | `24h` | commands for hosts that stay offline |
| `ALASTOR_SESSIONLIFETIME` | `12h` | dashboard login |
| `ALASTOR_AUTHRATELIMITPERMINUTE` | `10` | login/enroll attempts per IP |
| `ALASTOR_BLOCKLISTSENABLED` | `true` | download public blocklists; `false` for air-gapped servers (own entries still work) |
| `ALASTOR_BLOCKLISTREFRESHINTERVAL` | `4h` | per-list refetch while some policy uses it (1h–7d); failures back off from 5 min |
| `ALASTOR_VULNDBENABLED` | `true` | mirror the Trivy/Grype databases agents ask for; `false` for air-gapped servers (place the files by hand, §5d) |
| `ALASTOR_VULNDBREFRESHINTERVAL` | `12h` | how often a database in use is checked for a newer build (1h–7d); failures back off from 5 min |
| `ALASTOR_TRIVYDBREPOSITORY` / `ALASTOR_GRYPEDBURL` | `ghcr.io/aquasecurity/trivy-db:2` / `https://grype.anchore.io/databases` | upstream sources (e.g. `mirror.gcr.io/aquasec/trivy-db:2`, or your own mirror) |
| `ALASTOR_ALERTDEDUPWINDOW` / `ALASTOR_ALERTBURST` | `1h` / `1` | alert dedup: per host and dedup key, `burst` notifications per window (§5a) |
| `ALASTOR_THREATFEEDENABLED` | `true` | fetch NVD, CISA KEV and news RSS (§5) |
| `ALASTOR_OSVENABLED` | `true` | look up the fleet's package versions on OSV.dev (§5c-1); `false` for air-gapped servers |
| `ALASTOR_THREATFEEDINTERVAL` | `20m` | per-source refetch after a success (5m–1d) |
| `ALASTOR_THREATFEEDRETENTION` | `30d` | feed items older than this are pruned and not fetched |
| `ALASTOR_NVDAPIKEY` | – | optional; raises NVD's rate limit from 5 to 50 requests / 30 s |
| `ALASTOR_UPDATECHECKENABLED` | `true` | `UpdateCheckWorker` asks GitHub for the latest release at startup and every 12 h; the sidebar shows a notice when it's newer |
| `ALASTOR_UPDATEREPOSITORY` | `nor0x/Alastor` | `owner/name` whose releases the update check reads (404, e.g. a private repo, means no notice) |

All values are validated: an invalid policy is rejected with the key's path, and invalid server config stops
startup with a message naming the variable. Deliberately **not** knobs: retry backoffs, tool command timeouts
and internal caches. These are failure handling, not scheduled actions.

## 5. Threat feed

The server, not the agents, aggregates public threat intelligence into one timeline (`/api/feed`, the dashboard's
*Threat feed* page). Code: `src/Alastor.Server/Services/ThreatFeed/`, driven by `ThreatFeedWorker`.

| Source | Kind | Notes |
|---|---|---|
| NVD CVE API 2.0 | `cve` | first run: CVEs published in the last 7 days, plus CVEs added to KEV within the retention window (so they get CVSS); afterwards everything `lastModified` since the stored cursor (5 min overlap), which also picks up late CVSS scores |
| CISA KEV catalog | flags | conditional GET; falls back to CISA's GitHub mirror when cisa.gov's CDN refuses the server's IP (common on VPS ranges) |
| The Hacker News, BleepingComputer, Krebs on Security, SecurityWeek, Dark Reading | `news` | RSS 2.0 / RDF / Atom, conditional GET, DTDs never processed |

**Item model** (`FeedItem`): `id, source, type (cve\|news), title, url, publishedAt, summary, severity, cvssScore,
exploited, tags, products`. Dedup is by id, derived from the source's own item id: the CVE id, or
`{source}:{sha256(guid)}` for articles. A CVE is **one row** whether NVD or KEV saw it first; the other source
merges into it. `severity` is the CVSS base severity (v4.0 > v3.1 > v3.0 > v2, NVD's primary score within a
version); news has none. `exploited` means the CVE, or a CVE an article mentions, is in KEV. KEV is
authoritative: removals unflag, and a catalog less than half the stored size is refused rather than applied.
A CVE added to KEV after publication is dated by its KEV addition, because that is when it became news.
HTML is reduced to plain text and only absolute `http(s)` links are stored.

**Scheduling and failure handling.** Every source has its own row in `FeedSources`: after a success the next
fetch is `ThreatFeedInterval` ±10 % jitter; after a failure it backs off 1, 2, 4 … minutes (max 2 h), or the
server's `Retry-After` if longer. 429/502/503/504 (and NVD's rate-limit 403) are retried in-run up to 3 times
when the wait is short. NVD pages are paced at 6 s without an API key, as NVD asks. A response that arrived
but couldn't be applied doesn't keep its ETag, so it's fetched in full next time. Sources are independent, and
the worker runs off the request path starting right after startup: the API only reads stored rows, so a slow
or failing source never delays the dashboard. The SPA shows per-source health and gets a `feedUpdated`
SignalR hint when new items arrive.

## 5a. Alert pipeline

Code: `src/Alastor.Server/Services/Alerts/`. Every event the server stores (from agents or its own presence
checks) goes through `AlertPipeline` right after the insert:

1. **Threshold.** Events below the lowest `minSeverity` of any enabled channel are never considered.
2. **Dedup: a leaky bucket per `hostId|dedupKey`.** The bucket holds `AlertBurst` notifications and drains one per
   `AlertDedupWindow`. An event that fits is sent; one that doesn't is *suppressed* and counted, and the count rides
   along with the next notification for that key ("4 similar suppressed since the last alert"). An event more severe
   than the last one sent for its key always goes out, so escalation is never hidden. Each event records its
   outcome (`alert: None | Notified | Suppressed`), shown in the timeline.
3. **Delivery** runs off the request path (a bounded in-memory queue drained by `NotificationDispatcher`), so a slow
   SMTP server never delays an agent. Each channel gets one message per batch of matching events (severity and
   optional capability filter), 3 attempts with 2 s / 15 s backoff, and the outcome lands in the delivery log
   (newest 1000 kept) and on the channel (`lastError`, shown as *failing* on the dashboard).
4. **Digests** (optional, per channel): everything matching the channel since its last digest, grouped by severity
   and host, on the channel's schedule. A channel can be digest-only.

| Channel | Transport | Notes |
|---|---|---|
| Email | SMTP via MailKit (MIT): STARTTLS, implicit TLS or plain | High and Critical are sent with `Priority: urgent` |
| Webhook | `POST` JSON | formats: `json` (stable Alastor payload: `source, kind, title, text, severity, link, events[]`), `slack` (Slack and Mattermost), `discord`. With a secret: `X-Alastor-Signature: sha256=<hex HMAC-SHA256 of the body>` |
| ntfy | ntfy's JSON publish API on ntfy.sh or a self-hosted server | severity → ntfy priority (Critical 5 … Info 1), optional access token, click opens the host |

Channel configs are encrypted with ASP.NET Data Protection (keys in the data dir) and only decrypted in memory
to send. The API never returns the SMTP password, webhook secret or ntfy token; it says which are set.

## 5b. Blocklists

Code: `src/Alastor.Core/Blocklists/` (catalog, parser, agent enforcement), `src/Alastor.Core/Net/IpRangeSet.cs`
(range math), `src/Alastor.Server/Services/Blocklists/`. Policy: `blocklists: {enabled, lists, extra, refreshSchedule}`;
`lists` replaces across layers (a host can pick its own), `extra` is a union.

1. **The server pulls** only lists some policy layer uses: Spamhaus DROP (its JSON feed), FireHOL level 1, abuse.ch Feodo,
   ET compromised, blocklist.de, CINS Army (their documented netset text). Conditional GET per URL. A download that
   shrinks a list below 10 % of its last good size, or parses to nothing, is refused and the last good copy kept.
   Entries wider than /8 (IPv4) or /16 (IPv6) are skipped.
2. **Per host**, the server unions the host's lists and `extra`, then subtracts the special-purpose ranges (private,
   CGNAT/Tailscale `100.64.0.0/10`, loopback, link-local, documentation, multicast: FireHOL level 1 carries the bogons)
   and the allowlist (server-wide plus `banning.allowlist`), and emits the minimal CIDR list. The result is cached by
   content and addressed by an ETag.
3. **The agent** fetches it on `blocklists.refreshSchedule` and after policy changes, and owns exactly one kernel
   object: nftables table `inet alastor` (interval sets `blocklist4/6`, a `prerouting` chain at priority -300, so
   packets are dropped before conntrack for the host and for containers alike, with counters for the dashboard), or on
   hosts without `nft`, ipsets `alastor4/6` filled off to the side and swapped in, matched from a `ALASTOR`
   chain in iptables' raw table. The server's own addresses are always accepted first. Updates are one `nft -f`
   transaction after `nft -c` validates it, so a failure leaves the previous set loading. The table is removed when
   blocklists are turned off, on `alastor-agent uninstall`, and after `agent.offlineGracePeriod` without server
   contact (restored on reconnect). Containers and LXC/OpenVZ plans usually refuse firewall changes; the agent reports
   that once as `config.rejected` with an explanation, and the dashboard shows the host as *refused*.

## 5c. Security updates

Code: `src/Alastor.Core/Updates/`, `src/Alastor.Core/Integrations/ScheduledJobs.cs`, `src/Alastor.Server/Endpoints/ReportEndpoints.cs`.

Updates are the first user of the agent's **scheduled-job** framework, which CVE scans, Lynis audits and ClamAV
reuse: an integration exposes `ScheduledJob`s, each tied to a policy schedule key. The supervisor runs a job when it
is due (with the per-host spread), at first start if the job asks for it, or on a `run-job` command from the
dashboard. The result goes to `POST /api/agent/reports` as an `AgentReport`, retried from a small outbox if the
server is unreachable. The server stores the latest report per host and kind, plus summary columns for list views.

* **Check (`updates.check`)** asks the host's own package manager, with no output scraping beyond its documented
  formats: apt `apt-get update` then `apt-get -s dist-upgrade` (the `Inst` lines carry the origin, so packages
  from a `-security` pocket are marked as security updates), plus `/var/run/reboot-required(.pkgs)`; dnf
  `check-update` and `check-update --security` (exit code 100 = updates available), plus `needs-restarting -r`;
  apk `list --upgradable`. Alpine doesn't mark security updates, so every pending update counts as a possible one there.
* **Install (`updates.apply`)**, on `updates.applySchedule` or "Install now": Debian/Ubuntu run `unattended-upgrade`,
  so its configured origins, blacklist and dpkg conffile handling apply exactly as they would from its own timer.
  If it isn't installed (and `autoInstall` is off), the fallback is `apt-get install --only-upgrade` of the security
  packages only, keeping existing config files. RHEL family runs `dnf upgrade --security`, Alpine runs `apk upgrade`.
  Installing never reboots. The agent reports `updates.reboot-required` once, and the dashboard shows it with a
  Reboot button: the `reboot` command runs `shutdown -r +1` (acknowledged before the host goes down, cancellable with
  `shutdown -c`, a redelivered copy is ignored), and the first start afterwards re-runs `updates.check`.
* **Services to restart.** After every check and install, `needrestart -b -r l` (batch output, list mode: it never
  restarts anything) on Debian/Ubuntu, or `needs-restarting -s` on the RHEL family, lists the services still running
  code from libraries or binaries an update replaced. needrestart is adopted, never installed: installing it changes how
  apt restarts services after upgrades. Its kernel check (`NEEDRESTART-KSTA` 2 or 3: a newer kernel is installed than
  the one running) also marks a reboot as required. The list is reported as `restartServices`, shown on the host's
  *Updates* tab with a copy-paste `systemctl restart`, raised once as `updates.restart-required` (Medium) when it
  grows, and kept as an `updates.restart` issue until the services restart. `null` means neither tool is installed.
* **Events:** `updates.pending` when the set of pending security updates changes (not on every check),
  `updates.applied` / `updates.failed` after an install, `updates.reboot-required` and `updates.restart-required`. They go through the normal
  alert pipeline (§5a).

## 5c-1. Software inventory, single-package upgrades and uninstalls

* **Inventory (`software.inventory`)**, on `updates.inventorySchedule`, at first start and after every change: every
  installed package from the package database, never from a package manager's "pretty" output. Debian/Ubuntu:
  `dpkg-query -W` with a fixed tab-separated format (name, version, arch, status, size, priority, `Essential`,
  `Source`) and `apt-mark showmanual`; RHEL family: `rpm -qa --qf` (epoch only when set, as dnf prints it; the source
  name from the SRPM) and `dnf repoquery --userinstalled`; Alpine: `apk list --installed` (origin = source) and
  `/etc/apk/world`. "Manual" marks packages someone installed on purpose; the dashboard shows those by default.
  The server stores one `HostPackages` row per package, replaced per report, like CVE findings.
* **Enrichment, at read time.** Each package is joined with the host's last update check (the candidate version and
  the security flag), its Trivy/Grype findings for OS packages (`deb`/`rpm`/`apk`), and cached OSV.dev results.
  Findings are merged by CVE id: an OSV advisory (DSA-…, UBUNTU-CVE-…, ALSA-…) expands into the CVEs it names in
  `aliases`/`upstream`, and the scanner's finding wins where both have one. KEV marks exploited CVEs.
* **OSV.dev.** `OsvWorker` (every 15 min, off with `ALASTOR_OSVENABLED=false`) sends the distinct
  (ecosystem, package, version) tuples of the fleet to `POST /v1/querybatch` (1,000 per request) and caches the
  answer for 24 h; advisories are fetched once from `GET /v1/vulns/{id}` and refetched when OSV reports them modified.
  Only package names and versions leave the server. Ecosystems come from os-release: `Debian:12`, `Ubuntu:24.04:LTS`,
  `Alpine:v3.20` (queried by source package), `AlmaLinux:9`, `Rocky Linux:9` (binary package). RHEL, whose OSV
  ecosystem is split per repository, and Fedora aren't covered. Severity is the distribution's own rating where it has
  one (as Trivy does), else the CVSS v3 base score computed from the vector.
* **Upgrade and uninstall.** Always two steps. The dashboard first queues `package-plan` `{op, package}`: the agent
  runs the package manager's dry run (`apt-get -s`, `dnf --assumeno`, `apk --simulate`) and returns the transaction in
  the command result's `Detail`. The dialog shows it next to the command to run by hand (both come from
  `PackageCommands`, so they never differ). Applying queues `package-action`, which the agent acknowledges at once and
  runs off the heartbeat loop under the same lock as `updates.apply`: `apt-get install --only-upgrade` (keeping changed
  config files) / `apt-get remove`, `dnf upgrade` / `dnf remove`, `apk upgrade` / `apk del`. It then re-collects the
  inventory, reports it with `lastAction` (from → to, log tail), and re-runs the update check and CVE scan.
* **Protection.** Package names must match `^[A-Za-z0-9][A-Za-z0-9.+_:~@-]{0,127}$` (never an option) and be in the
  host's inventory. Packages that would break booting, logins or the package manager (Debian `Essential`/`required`,
  kernels, systemd, libc, sudo, openssh-server, apt/dpkg/rpm/dnf/apk) are never removed: the server refuses them, and
  the agent re-checks the dry run and refuses any removal that would take one along, whatever the server asked.
  apt's own "Yes, do as I say!" guard for essential packages stays in place (`-y` never answers it). There is no
  bulk uninstall. Events: `software.upgraded`, `software.removed`, `software.failed`.

## 5c-2. Storage: disk usage and cleanups

* **Scan (`storage.scan`)**, on `storage.scanSchedule` (every 12 h), at first start and after every cleanup, under
  `nice -n 19 ionice -c 3` when those exist. Filesystems from `df -PTk` and `df -Pi` (memory, overlay and snap mounts
  left out; BusyBox `df -Pk` without types as a fallback). For each local disk mount (ext*, xfs, btrfs, zfs, …, at most
  8): `du -xk -d 3` for the folder tree, pruned to the 15 biggest children per folder of 25 MB or more (400 in all), and
  `find -xdev -type f -size +100M -printf` for the 50 biggest files (`-exec stat` on BusyBox). The report is stored as
  a `HostReports` row of kind `storage`; no extra tables.
* **Cleanups** (`StorageCleanups`): a fixed catalog, each with a risk (`Safe`, `Caution`, `Destructive`) and the
  command to run by hand. The agent measures every one that applies with the tool it belongs to: `du` of the package
  caches (`apt-get clean`, `dnf clean all`, `apk cache clean`), `journalctl --disk-usage` above 200 MB
  (`--vacuum-size=200M`), rotated logs under `/var/log` (`find … -delete`), `docker system df` (build cache, stopped
  containers, unused images, unused volumes: `docker … prune`), container json logs (`truncate -s 0`),
  `podman system df`, `apt-get -s autoremove` with `dpkg-query` sizes, `dnf --assumeno autoremove`, disabled snap
  revisions, pip/npm/yarn/Go/Composer caches directly in `/root` and `/home/<user>`, crash dumps, and files in `/tmp`
  and `/var/tmp` untouched for 10 days. "Can be freed" sums them without the destructive ones.
* **Running one.** The dashboard sends only the id: `storage-cleanup` `{cleanup}`. The agent acknowledges it, measures
  that cleanup again, runs exactly its commands (argument lists, never a shell; paths only from its own measurement),
  compares `df` before and after for the freed space, reports the fresh filesystems and candidates with `lastCleanup`
  (the scan's folder tree is carried along), and queues a full scan. One cleanup runs at a time. autoremove takes the
  package-manager lock and is refused when it would remove a protected package or the running kernel (from
  `/proc/sys/kernel/osrelease`); older kernels may go. Unused Docker volumes delete data, so the server wants the host
  name typed (`delete` for several hosts). Events: `storage.cleaned` (Info), `storage.cleanup-failed` (Medium).
* **Disk almost full.** The server watches the root filesystem in every heartbeat: crossing 90% (and 95%) raises
  `storage.low` (Medium, then High) once, and the `storage.low` issue stays open while it is that full.

## 5d. Vulnerability scans (Trivy / Grype)

Code: `src/Alastor.Core/Vulnerabilities/`, `src/Alastor.Server/Services/Vulnerabilities/`, `src/Alastor.Server/Endpoints/VulnerabilityEndpoints.cs`.
Policy: `vulnerabilities: {scanSchedule, scanner, languagePackages, ignorePackages, ignore, alertSeverity}`.

* **Scanners are adopted, not bundled.** Neither Trivy nor Grype is in the Debian, Ubuntu or RHEL repositories, and the
  spec forbids vendored binaries. So the agent uses whichever one the admin installed from its vendor's package
  repository (Trivy preferred with `scanner: auto`), and installs one itself only where the distribution ships it
  (Alpine's `trivy`, at most one attempt a day). A host without a scanner reports the tool as *disabled*, not as a
  problem, and the host's CVEs tab shows the copy-paste repository setup.
* **Databases come from the server.** Agents never contact Aqua or Anchore. The first time an agent asks
  (`GET /api/agent/vulndb/{scanner}`), the server pulls the database: Trivy's is the OCI artifact
  `ghcr.io/aquasecurity/trivy-db:2` (one `db.tar.gz` layer, ~130 MB, anonymous registry token); Grype's is named by
  `{url}/v6/latest.json` (~190 MB `.tar.zst`). Each download is verified against the upstream sha256, which then serves
  as the ETag, so the nightly agent check is usually a 304. The agent waits (up to 20 min, honoring `Retry-After`) for
  the first mirror instead of failing. Databases nobody asked for in 7 days stop being refreshed. With
  `ALASTOR_VULNDBENABLED=false`, an admin places `data/vulndb/trivy/db.tar.gz` or `data/vulndb/grype/db.tar.zst` by
  hand; the server hashes it and serves it.
* **Scanning** runs offline at low CPU priority: `trivy rootfs --skip-db-update --offline-scan --scanners vuln
  --list-all-pkgs=false --format json /` against the documented air-gapped layout (`{state}/vulndb/trivy/db/trivy.db`),
  or `grype db import` followed by `grype dir:/ -o json` with auto-update, update checks and age validation off.
  Pseudo-filesystems, caches, container storage and the agent's own state are skipped. Java archives are skipped too,
  because they need Trivy's separate ~900 MB Java database, which isn't mirrored. A scan of this repo's dev container
  (Ubuntu 26.04 with .NET, Node and Go tooling) takes about 35 s.
* **Normalization:** both JSON formats map to one finding shape (id, package, installed, fixed, severity, CVSS, fix
  state, package type, path). Grype's GHSA/ALSA ids are mapped to their CVE where it names one, so hosts and the threat
  feed line up. `ignorePackages` defaults to `linux-libc-dev`: distributions track every kernel CVE against the kernel
  *headers* package (3151 of 3741 findings on a stock Ubuntu 26.04), though no kernel code runs from it. Dropped
  findings are counted and shown. Reports carry at most 15,000 findings, least severe dropped first.
* **Server side:** findings are stored per host (`HostVulnerabilities`, replaced per scan, `FirstSeenAt` kept); a failed
  scan keeps the last good set. Accepted CVEs (`vulnerabilities.ignore`, a union across layers) are applied by the server,
  and re-applied whenever a policy layer is saved, so "Accept risk" in the dashboard takes effect without a rescan. Counts
  are per distinct CVE.
* **Alerts:** the agent raises `vulnerabilities.found` once per newly appearing *fixable* finding at or above
  `alertSeverity` (default `high`): an alert should come with something to do. The server raises
  `vulnerabilities.exploited` (Critical) when a host has a CVE in CISA's KEV catalog, which it already mirrors for the
  threat feed: at scan time for new findings, and when CISA adds a CVE that hosts already have.
* **Container images** (`vulnerabilities.scanContainers: true`, off by default): after the host scan, the agent lists
  running containers (`docker ps --format '{{json .}}'`, `podman ps --format json`) and scans each distinct image, at
  most 20, from the local image store: `trivy image --image-src docker|podman --offline-scan` or
  `grype docker:|podman:`, against the same mirrored database. Nothing is pulled from a registry. One image failing is
  recorded in the report's `images` list and doesn't fail the scan. Findings carry their `image`; the host's counts
  stay its own packages (host updates don't reach images), images get their own counts, a `cve.image-critical` issue
  and a source filter on the host's *CVEs* tab. The new-findings alert stays about host packages.

## 5e. Hardening audits (Lynis)

Code: `src/Alastor.Core/Hardening/`, `src/Alastor.Server/Services/Hardening/`, `src/Alastor.Server/Endpoints/HardeningEndpoints.cs`.
Policy: `hardening: {auditSchedule, ignore}`.

* **Installed from distro repos.** Lynis is packaged by Debian, Ubuntu, Alpine and EPEL, so the agent installs it like
  fail2ban when `agent.autoInstall` allows (at most one attempt a day; the error mentions EPEL on the RHEL family), and
  adopts an existing install otherwise. `hardening.auditSchedule: off` stops both installing and auditing.
* **Audit:** `nice -n 15 lynis audit system --cronjob --quiet --no-colors --profile {state}/lynis/alastor.prf
  --report-file {state}/lynis/report.dat --log-file {state}/lynis/lynis.log`. The profile only sets
  `skip-upgrade-test=yes`: Lynis's upgrade check is a DNS query to cisofy.com, and agents talk only to their server.
  Lynis merges it over its own `default.prf`, so an admin's `/etc/lynis/custom.prf` still applies. A full audit takes
  about 3 minutes on this repo's dev container (243 tests). The report and log stay in the agent's state directory;
  `/var/log/lynis*.log` (an admin's own cron runs) is left alone.
* **Parsing:** the agent reads Lynis's machine-readable report file, which is the format Lynis's own `lynis show`
  commands read: `hardening_index`, `lynis_version`, `lynis_tests_done`, and `warning[]` / `suggestion[]` lines of the
  form `TEST-ID|text|details|solution|`. No console output is parsed. Only these fields go to the server, not the
  rest of the report (installed packages, network listeners, users).
* **Server side:** items are stored per host (`HardeningItems`, replaced per audit, `FirstSeenAt` kept); a failed audit
  keeps the last good checklist. Each report records which test ids the previous audit had and this one doesn't
  ("resolved since the previous audit"). Accepted items (`hardening.ignore`, Lynis test ids, a union across layers)
  are applied by the server, like accepted CVEs, and re-applied on every policy save. They don't change Lynis's index,
  which is its own; they drop out of the warning and suggestion counts and the fleet view.
* **Alerts (agent):** `hardening.warning` (Medium) when a warning appears that the previous audit didn't have, and
  `hardening.regressed` (Medium) when the index drops by 5 or more points between audits.
* **Dashboard:** each host's *Hardening* tab shows the index, warnings first, and a checklist grouped by Lynis category,
  with each test id linked to its CISOfy control page. Where a finding overlaps with something Alastor already does
  (SSH and kernel settings and automatic updates are baseline fixes; pending updates and vulnerable packages have
  their own tabs; DEB-0880's `jail.local` advice doesn't apply to the jail.d drop-in), the row says so and links
  there. The Baseline page's *Lynis audit* view ranks findings across the fleet.

## 5f. SSH exposure, listening services and Tailscale

Code: `src/Alastor.Core/Network/`, `src/Alastor.Server/Services/Network/`, `src/Alastor.Server/Endpoints/NetworkEndpoints.cs`.
Policy: `network: {checkSchedule, allowPublicSsh, allowPublicPorts}`.

* **Tailscale is detected, never installed.** It isn't in most distributions' repositories, and joining a tailnet
  needs the admin's login, so the agent only adopts it: `tailscale status --json` (ipnstate.Status) gives the backend
  state, tailnet, addresses, peers and node-key expiry; `tailscale debug prefs` adds whether Tailscale SSH is on (best
  effort). The tool reports *disabled* when absent, which isn't a problem. The agent warns
  (`tailscale.key-expiring`) 14 days before the node key expires, when the host would drop off the tailnet.
* **SSH exposure** is worked out from what the host shows, read-only, on `network.checkSchedule`:
  sshd's ports and auth settings from `sshd -T`; listening sockets from `/proc/net/tcp{,6}` (the kernel's documented
  format; without netlink there's no other API); the host's addresses from `ip -j addr`; and the host firewall from
  `ufw status verbose` when ufw is active (first matching rule for the SSH port decides; ufw has no machine-readable
  output) or `nft -j list ruleset` otherwise (input-hook base chains read in order, following jumps, skipping
  established/loopback rules; a source or interface match makes an accept a *restriction*). Rules loaded with
  iptables-legacy are reported as unreadable rather than guessed. The result is one level: `Public`, `PossiblyPublic`,
  `Restricted`, `PrivateOnly`, `TailnetOnly`, `LocalOnly`, `NotListening`, `NoSsh` or `Unknown`, with the reasons.
* **The server's view.** On AWS, GCP and Azure an instance often has only a private interface address behind 1:1 NAT.
  The server records the address each agent's requests come from; a wildcard-bound sshd on a host with only private
  addresses, seen from a public address, is `PossiblyPublic`. Provider firewalls and security groups are invisible to
  both, and the dashboard says so instead of claiming the port is reachable.
* **Listening services** (the exposure inventory), in the same check: every TCP and UDP listener from `ss -tulpnH`
  with its owning process (falling back to `/proc/net/{tcp,udp}{,6}` without owners), the process's systemd unit from
  `/proc/<pid>/cgroup`, and the unit's `systemd-analyze security --json=short` score (systemd 250+; 0 is sandboxed, 10
  unprotected). Each service is judged like SSH: bound addresses first (wildcards expand to the host's addresses),
  then the same ufw/nft snapshot for that port and protocol, giving `Public`, `Restricted` (public address, firewall
  limits it), `Private`, `Tailnet` or `Local`. A public service that isn't sshd and isn't in `network.allowPublicPorts`
  (`443`, `443/tcp`, `51820/udp`, `60000-61000/udp`; union across layers; the default policy allows 80/tcp and 443/tcp)
  is *unexpected*: the agent raises `exposure.service` (Medium) once per port, the server lists it on the host row
  (`PublicServices`), and it becomes a `service.public` issue until the port closes or is allowed. The host's
  *Network* tab lists the services with an *Allow* button that adds the port to the host's policy layer.
* **Closing ports:** with `firewall.manage` (§5l) the same `allowPublicPorts` list becomes ufw allow rules, so what the
  inventory flags as unexpected is what the managed firewall blocks.
* **Alerts:** `exposure.detected` when SSH becomes `Public` (High with password logins on, Medium for key-only), once
  per transition. `network.allowPublicSsh: true` (a bastion) marks it accepted: listed, not counted, not alerted,
  applied by the server at once.
* **Dashboard:** a host's *Network* tab shows the level, the reasons, copy-paste ufw commands that close the port (to
  the tailnet when Tailscale is up, else to an admin address), Tailscale details, and a hint when the ban allowlist
  doesn't cover the tailnet (100.64.0.0/10). The Baseline page's *Exposure* view and overview tiles cover the
  fleet, with each host's unexpected public services.
* **Why built:** no bundled tool answers "can the internet reach this host's SSH?" or "which of its services face the
  internet?". Lynis and the baseline check sshd's *settings*; this combines sockets, addresses, firewall and the
  server's view of the host. `ss`, the kernel's socket tables and `systemd-analyze` do the reading.

## 5g. CrowdSec (opt-in banning engine)

Code: `src/Alastor.Core/Integrations/CrowdSec/`. Policy: `banning: {engine: crowdsec, crowdsecCentralApi, allowlist, manualBantime}`.

* **Engine switch.** `banning.engine` picks exactly one engine per host: fail2ban (default) or CrowdSec. Both implement
  `IBanProvider`, so manual bans, unbans, the Bans page and ban snapshots work the same; the supervisor routes commands
  to whichever is wanted. Switching back to fail2ban removes CrowdSec's managed allowlist and leaves CrowdSec installed.
* **Install.** `crowdsec` and `crowdsec-firewall-bouncer` from Debian/Ubuntu's repositories (the bouncer's package
  registers itself with the Local API). Elsewhere CrowdSec isn't packaged, so a copy installed from CrowdSec's own
  repository is adopted. A missing or stopped bouncer is a warning: decisions exist but nothing blocks them.
* **No third-party traffic by default.** CrowdSec's Central API shares attack signals with crowdsec.net and pulls its
  community blocklist. It stays off unless `banning.crowdsecCentralApi: true`: before installing, the agent writes
  `online_api_credentials.yaml` itself (the Debian package skips registration when that file has content), and an
  owned systemd drop-in (`crowdsec.service.d/alastor.conf`) starts the daemon with `-no-capi`. Turning it on
  removes both and runs `cscli capi register`. The drop-in survives an engine switch, so data sharing never starts
  as a side effect. The hub is the package's offline copy; the agent never runs `cscli hub update`.
* **Owned config.** One parser whitelist, `parsers/s02-enrich/alastor-allowlist.yaml`, from `banning.allowlist`
  (IPs and CIDRs; CrowdSec drops events from them before any scenario runs). Every change is validated with
  `crowdsec -t` and rolled back if rejected; allowlist changes reload, drop-in changes restart. Hand edits are drift,
  like every managed file. fail2ban's jail settings don't apply: CrowdSec's scenarios and its profile (4 h bans by
  default) decide what is banned.
* **Bans and events** come from cscli's JSON: `cscli decisions list -o json` for the ban list (time left, scenario,
  manual or not), and `cscli alerts list -o json`, polled every 30 s, for new alerts (`ban.added` per alert; alerts
  without a decision, such as simulation mode, as `auth.failures`). The last alert id is kept so a restart doesn't
  replay a day of alerts; community-blocklist pulls are skipped. Manual bans are `cscli decisions add` with
  `banning.manualBantime` (CrowdSec has no permanent decisions, so "permanent" is ten years) and a `alastor:` reason.

## 5h. Malware scans (ClamAV, opt-in)

Code: `src/Alastor.Core/Malware/`, `src/Alastor.Server/Services/Malware/`, `src/Alastor.Server/Endpoints/MalwareEndpoints.cs`,
the ClamAV part of `VulnDbMirror`. Policy: `malware: {scanSchedule, paths, exclude, maxFileSize}`.

* **Opt-in by schedule.** `malware.scanSchedule` is `off` by default; any schedule makes the agent install `clamav`
  from the distro repositories. Debian pulls in `clamav-freshclam`, which the agent stops and disables on hosts where it
  installed ClamAV, so hosts never contact ClamAV's CDN. On adopted installs it is left alone, with a warning.
* **Signatures come from the server.** ClamAV's CDN only serves its own update tools, so the server runs `freshclam`
  (distro package `clamav-freshclam`, included in the Docker image) into `data/vulndb/clamav/` with its own config:
  whole `.cvd` files (no incremental `.cld`), no test load (it would take ~1 GB of RAM). freshclam verifies each
  file's signature. Agents fetch `clamav-main`, `clamav-daily` and `clamav-bytecode` through the same conditional,
  authenticated endpoint as the CVE databases (`/api/agent/vulndb/{name}`, ETag = sha256), only when a scan runs, and
  check the `ClamAV-VDB:` header before swapping a file in. The mirror runs only for databases some agent asked for in
  the last 7 days, on `ALASTOR_VULNDBREFRESHINTERVAL`.
* **Scan.** `nice -n 19 clamscan --database=<state>/clamav -r --infected --stdout --max-filesize=…`
  over the configured paths that exist (missing ones are listed, not errors), with `--exclude-dir` regexes built from
  `malware.exclude`. clamscan has no machine-readable output, so the agent reads its documented text format:
  `<path>: <signature> FOUND` lines and the scan summary; unreadable paths are counted, not fatal.
* **Memory guard.** clamscan holds every signature in RAM (measured peak 967 MB with ClamAV 1.5.4 and 3.6 M
  signatures). The agent checks `MemAvailable` first and skips the scan with a clear error below 1.1 GB rather than push
  a small VPS into the OOM killer. This is why the feature is opt-in.
* **Report only.** Nothing is deleted or quarantined; a false positive in a web root would take a site down.
  `malware.found` (High) fires once per new file and signature. The host's *Malware* tab lists findings, unreadable
  paths, the scan settings and the mirror's state; the Hosts list and an overview tile flag hosts with findings.

## 5i. Posture history and issues

The report tables keep only the latest result per host, and the host row carries denormalized summaries (baseline
score, CVE counts, pending updates, SSH exposure, …). Two server-side views sit on top of those columns:

* **Posture snapshots** (`PostureSnapshots`): one row per host per UTC day with the day's latest values. Report,
  baseline and presence handlers write the reporting host's row; `PostureWorker` writes every host hourly, which
  carries values forward through quiet days. A measure stays null until the host first reports it, so charts show a
  gap rather than a false zero. `/api/stats/posture` aggregates them per day (averages for scores, sums for counts),
  and the dashboard draws them as trends. Pruned after `ALASTOR_POSTURERETENTION` (365 days).
* **Issues** (`Issues`): `IssueRules` turns a host's current state into the problems open right now: host offline,
  failed policy apply, a tool down or with a refused or hand-edited config, SSH reachable from the internet, password SSH
  on a public host, known-exploited (KEV) CVEs, critical CVEs, malware, failing high or critical baseline checks,
  pending security updates, a required reboot and a root filesystem 90% full (High from 95%). `IssueService` diffs that against the stored rows after every report,
  after a heartbeat that changed tool health, on presence changes, after policy saves (which can accept a risk) and
  hourly. A cleared condition resolves its issue; one that comes back reopens the same row with a new occurrence and
  without its acknowledgement. Every one of these conditions already raises its own alerting event when it starts
  (`host.offline`, `exposure.detected`, `vulnerabilities.exploited`, `baseline.failed`, `storage.low`, …), so issues don't notify
  again: opening and resolving are recorded as Info events (`issue.opened`, `issue.resolved`) on the timeline. Resolved
  issues are pruned with events.

## 5j. File integrity and rootkits (AIDE, rkhunter; opt-in)

Code: `src/Alastor.Core/Integrity/`, `src/Alastor.Core/Malware/RkhunterIntegration.cs`, `src/Alastor.Server/Services/Integrity/`,
`src/Alastor.Server/Endpoints/IntegrityEndpoints.cs`.
Policy: `integrity: {checkSchedule, paths, exclude}`, `malware: {rootkitSchedule, rootkitIgnore}`. Both schedules default to `off`.

* **AIDE** (capability `Integrity`). The agent installs `aide` from the distribution (disabling Debian's
  `dailyaidecheck.timer` when it did the install) and runs it with its own config and database under the agent's state
  directory, so the distribution's aide.conf is never involved. The config watches `integrity.paths` (system binaries,
  `/etc`, `/root/.ssh`, systemd units by default) for permissions, owner, group, size, mtime and SHA-256; inode and
  ctime are left out because every package upgrade changes them. Volatile files (`/etc/mtab`, `/etc/resolv.conf`, …)
  and every file the agent manages (`/etc/.*alastor`) are excluded. The first run records the baseline (`aide --init`);
  later runs (`aide --check`, exit code 0-7 is a bit mask of differences) report each added, removed or changed path
  with what changed, from the JSON report on AIDE 0.18+ (`report_format=json`, which must come before `report_url`) or
  the plain report on older versions. Binaries, SSH, PAM, sudo and account files are *critical*. New differences raise
  one `integrity.changed` event (High when any is critical), and the host has an `integrity.changed` issue until the
  baseline is accepted. **Accept changes** (`integrity.accept`, an on-demand job with no schedule) runs `aide --update`
  and swaps the database in.
* **rkhunter** (capability `Malware`). Installed from the distribution (EPEL on the RHEL family). The first run records
  file properties (`rkhunter --propupd`), then `rkhunter --check --sk --nocolors --rwo` (warnings only; exit 1 means
  warnings) runs at the lowest CPU priority. It never runs `--update`, so hosts don't contact rkhunter's mirrors. Each
  warning keeps its indented detail lines and gets a severity: rootkit or backdoor findings Critical, changed or
  replaced binaries High, hidden or suspicious files Medium, configuration notes Low. Medium-and-up warnings not
  matched by `malware.rootkitIgnore` (text fragments; evaluated on the server, so ignoring takes effect at once) raise
  `malware.rootkit-warning` once each and keep a `rootkit.warning` issue open. **Accept file properties**
  (`malware.rootkitsAccept`) re-runs `--propupd` after an update replaced binaries.
* **Dashboard:** a host *Integrity* tab lists AIDE's changes (critical first) and rkhunter's warnings, with *Check now*
  and the two accept actions; an overview tile and a matrix column cover the fleet.
* **Why bundled:** both are the standard, packaged tools for the job; the agent adds the schedule, the baseline
  handling and the report.

## 5k. SSH logins

Code: `src/Alastor.Core/Access/`, `src/Alastor.Server/Services/Access/LoginService.cs`, `src/Alastor.Server/Endpoints/AccessEndpoints.cs`.
Policy: `logins: {monitor, alertOnNewSource, trustedSources}`.

* **Agent.** A built-in integration (capability `Access`) reads sshd's `Accepted <method> for <user> from <address>`
  messages, at most every 30 s: from the journal with `journalctl -o json -t sshd -t sshd-session` (OpenSSH 9.8+
  logs from `sshd-session`), resuming after the saved `__CURSOR`, or, where journald can't be read, from
  `/var/log/auth.log` or `/var/log/secure` with the same offset-tracking tailer fail2ban uses. The first read starts
  at "now": history is never replayed. Each login is an Info `auth.login` event (user, method, key fingerprint).
* **Server.** `LoginService` keeps every host's (user, address) pairs (`LoginSources`: first and last seen, count,
  last method). A pair it hasn't seen raises `auth.login-new-source`: High, Critical for root, and the message says
  whether it's the user's first login on the host or a new address for a known user. Three exceptions are learned
  without alerting: the host's first batch of logins (otherwise every admin would alert once when the agent starts
  reporting), addresses in `logins.trustedSources`, and everything when `logins.alertOnNewSource` is false. Only login
  events the server hasn't stored before are processed, so a re-delivered batch never alerts twice.
* **Dashboard:** the host's *Network* tab lists the sources, newest first, marking the ones first seen this week and
  the ones that alerted. `GET /api/hosts/{id}/logins`.
* **Why built:** fail2ban and CrowdSec look at *failed* logins; nothing bundled reports the successful ones, which
  are what matters after a key or password leaks. sshd's own messages and the journal do the work.

## 5l. Firewall (ufw, opt-in)

Code: `src/Alastor.Core/Firewall/`. Policy: `firewall: {manage, ssh, allow, defaultIncoming}`, plus `network.allowPublicPorts`.

* With `firewall.manage: true` (Debian/Ubuntu; RHEL-family hosts use firewalld and are reported unavailable) the agent
  installs ufw if needed and keeps a set of allow rules it owns, tagged `comment 'alastor'` and read back with
  `ufw show added`: SSH on each of sshd's ports (`sshd -T`) from each `firewall.ssh` source (`any` by default,
  `from CIDR`, `on tailscale0`), every `network.allowPublicPorts` entry, and `firewall.allow` (`5432/tcp from
  10.0.0.0/8`, `9100/tcp on tailscale0`, ranges like `60000-61000/udp`; a union across layers). Rules without the tag
  belong to someone else and are never touched. It then sets `ufw default deny|reject incoming` and enables ufw.
* **Lockout guards.** Before anything changes, the plan is refused (state `Rejected`, a High `config.rejected` event)
  when no rule would allow one of sshd's ports, or when SSH is limited to an interface that isn't up. Policy validation
  refuses an empty `firewall.ssh` and warns when SSH is only reachable over an interface. Each new rule is checked with
  `ufw --dry-run` first; a failing step undoes the steps before it, in reverse. Turning `firewall.manage` off leaves
  every rule in place (removing the SSH rule from an active firewall could cut access); uninstalling the agent removes
  its rules except SSH ones while ufw is active.
* **Why ufw:** it's the firewall front end Debian and Ubuntu ship, its rules survive reboots on their own, and its
  comments give the agent a clean ownership marker without parsing raw iptables or nft rules.

## 6. Security model

| Secret | At rest |
|---|---|
| Admin password | PBKDF2 (`PasswordHasher`), dummy-hash timing equalization on unknown and locked users; 5 failures lock the account for 1 min, doubling up to 1 h |
| Dashboard sessions | HS256 JWT in an httpOnly, SameSite=Strict cookie whose `jti` is a `Sessions` row: sign-out, password changes and *Settings → Account* revoke it before it expires (checked per request, cached 30 s) |
| Two-factor secrets (optional, per user) | TOTP (RFC 6238, ±1 step, no reuse of a step) secret under Data Protection; 10 single-use recovery codes stored as SHA-256 |
| Enrollment tokens (`sve_…`, 256-bit) | SHA-256; consumed by an atomic conditional `UPDATE` (single use), 24 h TTL |
| Agent credentials (`{hostId}.sva_…`) | SHA-256; constant-time compare; deleting a host revokes it |
| API keys (`svk_…`) | SHA-256; reader role only. Writes return 403 |
| JWT signing key | `data/jwt.key` (0600) or `ALASTOR_JWTKEY` |
| Notification channel credentials | Data Protection (AES-256-CBC + HMAC), keys in `data/keys`; write-only over the API |

**Exposure.** The server listens on `127.0.0.1:8080` unless `ASPNETCORE_URLS` says otherwise, and answers only the
networks in `DashboardAllowFrom` (SPA, `/api`, `/hubs/dashboard`, `/openapi`) and `AgentAllowFrom` (`/api/agent`,
`/hubs/agent`, `/install`), both `loopback,private,tailnet` by default; anything else gets a bare 404 before
authentication. `X-Forwarded-For` is trusted from loopback only, so a local Caddy or `tailscale serve` passes the real
client address. Every response carries a strict CSP (same-origin scripts, `frame-ancestors 'none'`), `nosniff`,
`no-referrer` and HSTS over HTTPS. The OpenAPI document and the exact version need a sign-in.

**Self-check.** `SelfChecks` (Services/Security) judges the server's own posture: listening addresses against the
machine's NICs, plain HTTP outside loopback and the tailnet, allowlists that reach the internet, running as root, data
dir and `jwt.key` permissions, admins still on their first-start password, and agents whose heartbeats arrive over plain
HTTP from public addresses (`Hosts.ObservedScheme`). Failures are logged at startup, shown in *Settings → Security* and as
an overview banner; `alastor-server security-check` runs the configuration part without starting the server (exit 1 on
failure). Two-factor sign-in is reported as information only: it's optional.

**Own data.** The retention worker also prunes the audit log, stale SSH login sources, policy history beyond
`PolicyVersionsKeep` per layer (never the current version), old enrollment tokens and sessions, OSV advisories no
package refers to, and partial mirror downloads. SQLite is compacted (`VACUUM`) at most weekly once free pages exceed a
quarter of the file and 50 MB, or on demand in *Settings → Alastor data*, which also deletes mirrored databases no agent
has asked for in 30 days and extraction folders of older server versions.

Agents refuse plain HTTP unless enrolled with `--insecure` (except loopback, `100.64.0.0/10`, `fd7a:115c:a1e0::/48`
and `*.ts.net`), and support certificate pinning (`--pin <sha256>`) for self-signed servers. Manual bans refuse ranges wider than /8 (v4) or /32 (v6), anything overlapping the
allowlist, and the operator's own address.

**Not yet.** The agent's systemd unit runs as root without a sandbox (it installs packages and manages the firewall, so
the safe subset needs testing per distribution); agent installs skip checksum verification when no `SHA256SUMS` is
published; and commands and policy are trusted on TLS alone, not signed by a key the agent pins at enrollment.

## 7. Measured footprint (this repo, linux-x64)

| | Size | Idle memory |
|---|---|---|
| `alastor-agent` (Native AOT, default) | 11 MB | ~37 MB RSS, ~16 MB private |
| `alastor-agent` (`-p:AgentAot=false`, trimmed single-file JIT) | 20 MB | ~54 MB RSS, ~29 MB private |
| `alastor-server` (single file, SPA embedded) | 56 MB | – |
| fail2ban 1.1.0 itself | – | ~18 MB |

## 8. Why some pieces are built rather than bundled

* **Supervisor, policy engine, event normalization.** This *is* the product: no existing tool unifies these
  engines.
* **Blocklist merging and loading.** FireHOL's `update-ipsets`/`iprange` do this on a single box but fetch from every
  host and need bash plus a dozen helpers; CrowdSec's bouncers only load CrowdSec decisions. The spec requires that only
  the server talks to list providers, so the server merges (about 150 lines of range math, `IpRangeSet`) and the agent
  hands the result to `nft -f` / `ipset restore`, the tools' own bulk loaders.
* **Alert channels.** Email goes through MailKit; webhook and ntfy are one HTTP POST each. A notification router such as
  Apprise would add a Python runtime to the server for three transports.
* **Update checks and installs.** unattended-upgrades and dnf-automatic install updates, but neither reports to a
  central place or can be triggered remotely. The agent adds only the scheduling and the report. Installing is still
  done by `unattended-upgrade` (or `dnf`/`apk`), and counting reads the package manager's own simulation output.
* **Vulnerability database mirror.** Trivy and Grype can each be pointed at a mirror, but that needs a registry or a web
  server with their exact layout, and both would still check the vendor for updates. The server downloads each database
  once, verifies its checksum and serves it over the agents' authenticated channel (about 200 lines). The agent hands it
  to the scanner's own documented air-gapped mechanisms (`--skip-db-update` with the cache layout, `grype db import`).
  Scanning and matching remain entirely the scanners' work.
* **ClamAV signature mirror.** freshclam does the downloading and verification; the server only runs it on a schedule
  and serves its output over the agents' authenticated channel, which freshclam's `PrivateMirror` option can't use
  (it has no way to send the agent's credential).
* **Ban snapshots and manual-ban jail.** These use fail2ban's own mechanisms (`banip`, jail DB). We add no
  firewall code for banning.
* **Security baseline.** About twenty checks that matter most on an internet-facing server (SSH, firewall,
  automatic updates, pending reboot, kernel network hardening, UID 0 and empty-password accounts, shadow file
  permissions, time sync). Lynis (§5e) audits far more broadly, but it only *suggests*: it has no "apply" and no
  undo. The baseline exists for the short list where a fix is safe to automate. It still parses nothing by hand:
  checks read the system's own authoritative output (`sshd -T` for the *effective* SSH config, `sysctl -e`,
  `ufw status`, `nft -j list ruleset`, `iptables -S`, `apt-config dump`, `timedatectl show`, `passwd -S -a`,
  `getent`). Fixes are policy (`baseline.mitigations.<check>: apply | ignore | report`, merged key by key, so a
  host can opt out of a global `apply` with `report`). The agent applies them as two managed drop-ins:
  `/etc/ssh/sshd_config.d/01-alastor.conf` (sorts before cloud-init's `50-…`, because sshd keeps the *first*
  value; checked with `sshd -t` before sshd reloads, rolled back on failure; only keywords this sshd prints in
  `sshd -T` are written) and `/etc/sysctl.d/99-zz-alastor.conf` (sorts last; values it replaced are recorded
  and restored when a fix is removed). `sysctl -p` exits 0 even when `/proc/sys` is read-only (containers,
  LXC/OpenVZ VPS), so the agent reads the values back and reports what the kernel refused. Lockout guards:
  passwords are only turned off when an admin account (root, sudo, wheel, admin) has an authorized key, and root
  password login only when root has a key or another admin exists. Firewall, updates, reboots and account fixes
  stay manual (the agent can't know which ports you need or who `toor` is); the dashboard shows commands filled
  in with the host's SSH port, distro and user names. Score: severity-weighted (critical 10, high 6, medium 3,
  low 1); accepted, unknown and not-applicable checks are left out.
* **Metrics from /proc.** Five files are cheaper than shipping node_exporter for four numbers.

# SentinelVPS architecture

SentinelVPS is an orchestrator and control plane, not a security engine. Each capability is provided by an
established open-source tool (fail2ban, CrowdSec, Trivy, Lynis, …). SentinelVPS installs or adopts the
tool, owns a clearly marked slice of its configuration, reads the tool's own structured output, and
normalizes everything into one event model, one policy model and one dashboard.

```
          ┌──────────────── sentinel-server (one binary) ───────────────────────┐
browser ──┤ Svelte SPA (embedded) · REST /api · SignalR /hubs/dashboard          │
          │ EF Core → SQLite (WAL) | PostgreSQL · workers (presence, retention,  │
          │ threat feed ← NVD, CISA KEV, security news RSS)                      │
          └──────────▲───────────────────────────────▲──────────────────────────┘
                     │ HTTPS REST (pull)             │ SignalR /hubs/agent ("wake" only)
          ┌──────────┴───────────── sentinel-agent (per host) ───────────────────┐
          │ Supervisor: heartbeat → reconcile → commands      EventPump (5 s)     │
          │      │ IToolIntegration                                                │
          │      ├── Fail2BanIntegration ── fail2ban-client, jail.d/sentinel-vps.local, fail2ban.log
          │      ├── (CrowdSec, nftables, unattended-upgrades, Trivy, Lynis, … later)
          └───────────────────────────────────────────────────────────────────────┘
```

## 1. The normalized Event model

`src/Sentinel.Core/Events/SecurityEvent.cs`. Every tool's output becomes this shape **on the agent**, so the
server's pipeline, storage and UI contain no tool-specific code.

```csharp
public sealed record SecurityEvent
{
    Guid       Id          // agent-generated; content-derived for log lines → re-delivery is idempotent
    DateTime   OccurredAt  // UTC, the tool's timestamp (not read time)
    Capability Capability  // Agent | Banning | Blocklist | Firewall | Updates | Vulnerabilities | Hardening | Network | Malware
    Severity   Severity    // Info < Low < Medium < High < Critical (stored as int so >= filters work)
    string     SourceTool  // "fail2ban", "trivy", "sentinel-agent", "sentinel-server"
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
| `NOTICE [jail] Ban ip` | `ban.added` | Low (Info for `sentinel-manual`) | `metadata.manual` |
| `NOTICE [jail] Increase Ban ip (…)` | `ban.increased` | Medium | repeat offender |
| `NOTICE [jail] Restore Ban ip` | `ban.restored` | Info | after fail2ban restart |
| `NOTICE [jail] Unban ip` | `ban.removed` | Info | |
| `INFO [jail] Found ip - …` | `auth.failures` | Info | **aggregated** per (jail, IP) per 5 s batch with `count`, never one event per line |
| `ERROR Failed to execute ban jail … action …` | `tool.error` | High | the ban was recorded but **not enforced** |
| `ERROR` (other) | `tool.error` | Medium | `fail2ban.utils` stderr detail lines are folded into the summary above |
| config apply/drift/conflict/rejection | `config.*` | Info/Medium/High | from the reconcile loop |

## 2. The integration interface

`src/Sentinel.Core/Integrations/IToolIntegration.cs`. The supervisor only ever talks to tools through it.

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
* **Ownership.** Files we write carry a header with `sentinel-revision` and a `sentinel-sha256` of the body
  (`ManagedFile`). A hand edit makes the file *Drifted*: it is reported and **not** overwritten until the
  operator clicks *Reclaim*. A file at our path without the marker is *Foreign* and is never touched. A jail the
  admin defines in `jail.local` / `jail.d/*.local` is skipped and reported as a *Conflict*, unless the policy
  sets `takeover: true`.
* **All-or-nothing apply.** Back up, write atomically (temp file + rename), run `fail2ban-client -t`, reload,
  then verify the `sentinel-manual` jail is up. Any failure restores the backups and reloads.
* **Never fail silently.** Missing tool, missing package (for example EPEL needed on RHEL), unsupported distro: all
  become `Availability.Unavailable` with a human-readable reason, shown in the capability matrix.
* **Side effects behind seams.** `ICommandRunner`, `IFileSystem`, `IPackageManager` (apt/dnf/apk),
  `IServiceManager` (systemd/OpenRC) and `IStateStore` are all faked in tests.

What the fail2ban integration owns:

| Artifact | Purpose |
|---|---|
| `/etc/fail2ban/jail.d/sentinel-vps.local` | Only the jails the policy names, plus `[sentinel-manual]`. Never a `[DEFAULT]` section. |
| `/etc/fail2ban/filter.d/sentinel-manual.conf` | Empty filter: the manual jail only holds dashboard bans. |
| `[sentinel-manual]` jail | `logpath=/dev/null`, `bantime` = `banning.manualBantime` (default permanent); bans persist in fail2ban's own DB. |

## 3. API surface

Live OpenAPI document: `GET /openapi/v1.json`. Auth columns: **R** = signed-in user *or* read-only API key
(`X-Api-Key`); **A** = signed-in admin only; **Ag** = agent credential; **–** = anonymous.
Cookie-authenticated writes must also send `X-Sentinel-Request: 1` (CSRF guard on top of `SameSite=Strict`).

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /api/auth/login` · `POST /api/auth/logout` | – | JWT in httpOnly `sentinel_session` cookie (rate-limited) |
| `GET /api/auth/me` · `POST /api/auth/password` | R · A | |
| `GET /api/overview` | R | fleet cards, recent alerts, top offenders |
| `GET /api/hosts` · `GET /api/hosts/{id}` | R | summaries · detail with capability matrix and policy report |
| `GET /api/hosts/{id}/metrics?hours=` | R | downsampled CPU/mem/disk/load history |
| `GET /api/hosts/{id}/effective-policy` · `/commands` | R | merged YAML and revision · command history |
| `PATCH /api/hosts/{id}` · `DELETE /api/hosts/{id}` | A | rename, group, tags · remove (revokes the agent) |
| `POST /api/hosts/{id}/actions/{reconcile\|reclaim\|refresh-bans\|recheck}` | A | operator actions (`recheck` re-runs the security baseline) |
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
| `GET /api/about` · `GET /healthz` · `GET /install/{agent.sh,server.sh}` | – | licenses · liveness · installers |
| `POST /api/agent/enroll` | – (token) | consume single-use token → `{agentId, agentSecret}` |
| `POST /api/agent/heartbeat` | Ag | metrics + tool statuses + last apply report → `{desiredRevision, pendingCommands}` |
| `GET /api/agent/desired-state` | Ag | effective policy + revision |
| `POST /api/agent/events` | Ag | batch of `SecurityEvent` (≤1000), idempotent |
| `POST /api/agent/baseline` | Ag | one baseline run; the server replaces the host's result set and recomputes the score |
| `GET /api/agent/blocklist` | Ag | this host's merged blocklist as minimal CIDRs; `ETag`/`If-None-Match` (304), gzip |
| `POST /api/agent/bans` | Ag | full ban snapshot per tool (server replaces that host's active set) |
| `GET /api/agent/commands` · `POST /api/agent/commands/{id}/result` | Ag | pull pending commands · report outcome |
| `/hubs/agent` · `/hubs/dashboard` | Ag · R | SignalR: `Wake(reason)` to agents · `hostUpdated`, `eventsCreated`, `bansChanged`, `policyChanged`, `commandUpdated`, `feedUpdated`, `baselineUpdated` to browsers |

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

Recurring jobs use one shared type, `Schedule` (`src/Sentinel.Core/Policy/Schedule.cs`). Features never parse
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
| `updates.checkSchedule` | `every 6h` | ≥1m | pending security update count (D6) |
| `updates.applySchedule` | `off` | ≥1m | auto-apply security updates (D6) |
| `vulnerabilities.scanSchedule` | `0 3 * * *` | ≥1m | Trivy/Grype (D7) |
| `hardening.auditSchedule` | `0 5 * * 0` | ≥1m | Lynis (D8) |
| `malware.scanSchedule` | `off` | ≥1m | ClamAV, opt-in (D10) |
| *notification digest* | `off` | ≥1m | per channel, set on *Settings → Notifications*; same `Schedule` type, server time zone |

| Server env var | Default | |
|---|---|---|
| `SENTINEL_HEARTBEATINTERVAL` | `60s` | fallback when no policy sets `agent.heartbeatInterval` |
| `SENTINEL_OFFLINEAFTERMISSEDHEARTBEATS` | `3` | |
| `SENTINEL_PRESENCECHECKINTERVAL` | `30s` | offline sweep |
| `SENTINEL_RETENTIONRUNINTERVAL` | `1h` | pruning job |
| `SENTINEL_METRICRETENTION` / `SENTINEL_EVENTRETENTION` | `7d` / `90d` | |
| `SENTINEL_ENROLLMENTTOKENTTL` | `24h` | default; overridable per token |
| `SENTINEL_COMMANDREDELIVERAFTER` / `SENTINEL_COMMANDMAXATTEMPTS` | `5m` / `3` | unacknowledged agent commands |
| `SENTINEL_PENDINGCOMMANDTTL` | `24h` | commands for hosts that stay offline |
| `SENTINEL_SESSIONLIFETIME` | `12h` | dashboard login |
| `SENTINEL_AUTHRATELIMITPERMINUTE` | `10` | login/enroll attempts per IP |
| `SENTINEL_BLOCKLISTSENABLED` | `true` | download public blocklists; `false` for air-gapped servers (own entries still work) |
| `SENTINEL_BLOCKLISTREFRESHINTERVAL` | `4h` | per-list refetch while some policy uses it (1h–7d); failures back off from 5 min |
| `SENTINEL_ALERTDEDUPWINDOW` / `SENTINEL_ALERTBURST` | `1h` / `1` | alert dedup: per host and dedup key, `burst` notifications per window (§5a) |
| `SENTINEL_THREATFEEDENABLED` | `true` | fetch NVD, CISA KEV and news RSS (§5) |
| `SENTINEL_THREATFEEDINTERVAL` | `20m` | per-source refetch after a success (5m–1d) |
| `SENTINEL_THREATFEEDRETENTION` | `30d` | feed items older than this are pruned and not fetched |
| `SENTINEL_NVDAPIKEY` | – | optional; raises NVD's rate limit from 5 to 50 requests / 30 s |

All values are validated: an invalid policy is rejected with the key's path, and invalid server config stops
startup with a message naming the variable. Deliberately **not** knobs: retry backoffs, tool command timeouts
and internal caches. These are failure handling, not scheduled actions.

## 5. Threat feed

The server, not the agents, aggregates public threat intelligence into one timeline (`/api/feed`, the dashboard's
*Threat feed* page). Code: `src/Sentinel.Server/Services/ThreatFeed/`, driven by `ThreatFeedWorker`.

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

Code: `src/Sentinel.Server/Services/Alerts/`. Every event the server stores (from agents or its own presence
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
| Webhook | `POST` JSON | formats: `json` (stable SentinelVPS payload: `source, kind, title, text, severity, link, events[]`), `slack` (Slack and Mattermost), `discord`. With a secret: `X-Sentinel-Signature: sha256=<hex HMAC-SHA256 of the body>` |
| ntfy | ntfy's JSON publish API on ntfy.sh or a self-hosted server | severity → ntfy priority (Critical 5 … Info 1), optional access token, click opens the host |

Channel configs are encrypted with ASP.NET Data Protection (keys in the data dir) and only decrypted in memory
to send. The API never returns the SMTP password, webhook secret or ntfy token; it says which are set.

## 5b. Blocklists

Code: `src/Sentinel.Core/Blocklists/` (catalog, parser, agent enforcement), `src/Sentinel.Core/Net/IpRangeSet.cs`
(range math), `src/Sentinel.Server/Services/Blocklists/`. Policy: `blocklists: {enabled, lists, extra, refreshSchedule}`;
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
   object: nftables table `inet sentinel_vps` (interval sets `blocklist4/6`, a `prerouting` chain at priority -300, so
   packets are dropped before conntrack for the host and for containers alike, with counters for the dashboard), or on
   hosts without `nft`, ipsets `sentinel-vps4/6` filled off to the side and swapped in, matched from a `SENTINEL-VPS`
   chain in iptables' raw table. The server's own addresses are always accepted first. Updates are one `nft -f`
   transaction after `nft -c` validates it, so a failure leaves the previous set loading. The table is removed when
   blocklists are turned off, on `sentinel-agent uninstall`, and after `agent.offlineGracePeriod` without server
   contact (restored on reconnect). Containers and LXC/OpenVZ plans usually refuse firewall changes; the agent reports
   that once as `config.rejected` with an explanation, and the dashboard shows the host as *refused*.

## 6. Security model

| Secret | At rest |
|---|---|
| Admin password | PBKDF2 (`PasswordHasher`), dummy-hash timing equalization on unknown users |
| Enrollment tokens (`sve_…`, 256-bit) | SHA-256; consumed by an atomic conditional `UPDATE` (single use), 24 h TTL |
| Agent credentials (`{hostId}.sva_…`) | SHA-256; constant-time compare; deleting a host revokes it |
| API keys (`svk_…`) | SHA-256; reader role only. Writes return 403 |
| JWT signing key | `data/jwt.key` (0600) or `SENTINEL_JWTKEY` |
| Notification channel credentials | Data Protection (AES-256-CBC + HMAC), keys in `data/keys`; write-only over the API |

Agents refuse plain HTTP unless enrolled with `--insecure`, and support certificate pinning (`--pin <sha256>`)
for self-signed servers. Manual bans refuse ranges wider than /8 (v4) or /32 (v6), anything overlapping the
allowlist, and the operator's own address.

## 7. Measured footprint (this repo, linux-x64)

| | Size | Idle memory |
|---|---|---|
| `sentinel-agent` (Native AOT, default) | 11 MB | ~37 MB RSS, ~16 MB private |
| `sentinel-agent` (`-p:AgentAot=false`, trimmed single-file JIT) | 20 MB | ~54 MB RSS, ~29 MB private |
| `sentinel-server` (single file, SPA embedded) | 56 MB | – |
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
* **Ban snapshots and manual-ban jail.** These use fail2ban's own mechanisms (`banip`, jail DB). We add no
  firewall code for banning.
* **Security baseline.** About twenty checks that matter most on an internet-facing server (SSH, firewall,
  automatic updates, pending reboot, kernel network hardening, UID 0 and empty-password accounts, shadow file
  permissions, time sync). Lynis (D8) audits far more broadly, but it only *suggests*: it has no "apply" and no
  undo. The baseline exists for the short list where a fix is safe to automate. It still parses nothing by hand:
  checks read the system's own authoritative output (`sshd -T` for the *effective* SSH config, `sysctl -e`,
  `ufw status`, `nft -j list ruleset`, `iptables -S`, `apt-config dump`, `timedatectl show`, `passwd -S -a`,
  `getent`). Fixes are policy (`baseline.mitigations.<check>: apply | ignore | report`, merged key by key, so a
  host can opt out of a global `apply` with `report`). The agent applies them as two managed drop-ins:
  `/etc/ssh/sshd_config.d/01-sentinel-vps.conf` (sorts before cloud-init's `50-…`, because sshd keeps the *first*
  value; checked with `sshd -t` before sshd reloads, rolled back on failure; only keywords this sshd prints in
  `sshd -T` are written) and `/etc/sysctl.d/99-zz-sentinel-vps.conf` (sorts last; values it replaced are recorded
  and restored when a fix is removed). `sysctl -p` exits 0 even when `/proc/sys` is read-only (containers,
  LXC/OpenVZ VPS), so the agent reads the values back and reports what the kernel refused. Lockout guards:
  passwords are only turned off when an admin account (root, sudo, wheel, admin) has an authorized key, and root
  password login only when root has a key or another admin exists. Firewall, updates, reboots and account fixes
  stay manual (the agent can't know which ports you need or who `toor` is); the dashboard shows commands filled
  in with the host's SSH port, distro and user names. Score: severity-weighted (critical 10, high 6, medium 3,
  low 1); accepted, unknown and not-applicable checks are left out.
* **Metrics from /proc.** Five files are cheaper than shipping node_exporter for four numbers.

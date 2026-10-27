[← Alastor](../README.md) · Tools and data sources

# Tools and data sources

Alastor doesn't reinvent security engines. It installs these from your distribution's repositories (or adopts an
existing install) and never vendors binaries. Trivy, Grype and Tailscale aren't packaged by most distributions, so the
agent adopts them when you install them from their vendor's repository (Alpine's `trivy` package is the exception it
installs itself). `GET /api/about` and the dashboard's About page list the same set with licenses.

## Included tools

| Tool | Capability | What Alastor does with it | License | Status |
|---|---|---|---|---|
| [fail2ban](https://github.com/fail2ban/fail2ban) | Banning | writes `jail.d/alastor.local` from policy, validates, reloads, streams bans/unbans | GPL-2.0-or-later | ✅ |
| [nftables](https://netfilter.org/projects/nftables/) / ipset | Blocklists | loads merged public blocklists into its own `inet alastor` table (ipset + iptables fallback) | GPL-2.0 | ✅ |
| [unattended-upgrades](https://wiki.debian.org/UnattendedUpgrades), dnf, apk | Updates | counts pending security updates, installs them on schedule or on demand, flags required reboots | GPL-2.0 | ✅ |
| [needrestart](https://github.com/liske/needrestart), dnf `needs-restarting` | Updates | adopted, never installed: after each check lists services still running replaced libraries (`needrestart -b -r l`, list only) and a pending kernel | GPL-2.0 | ✅ |
| SSH login monitor (built in) | Access | reads sshd's `Accepted …` messages from the journal (or auth.log / secure); the server alerts on new (user, address) pairs | MIT | ✅ |
| SSH authorized keys (built in) | Access | lists every account's authorized_keys, adds and removes keys from the dashboard, alerts on keys added outside it | MIT | ✅ |
| [Trivy](https://github.com/aquasecurity/trivy) or [Grype](https://github.com/anchore/grype) | Vulnerabilities | offline CVE scans of OS and language packages against a server-mirrored database | Apache-2.0 | ✅ |
| [Lynis](https://cisofy.com/lynis/) | Hardening | scheduled audits; hardening index, warnings and suggestions as a checklist | GPL-3.0 | ✅ |
| Exposure inventory (built in) | Network | every listening service from `ss -tulpn` (iproute2), its systemd unit and `systemd-analyze security` score, judged against ufw/nft; flags public ports outside `network.allowPublicPorts` | MIT | ✅ |
| Security baseline (built in) | Hardening | 21 checks via `sshd -T`, `sysctl`, `ufw status`, `nft -j`, … with reversible one-click fixes | MIT | ✅ |
| [Caddy](https://caddyserver.com/) | Server TLS | optional, set up by `install.sh --domain` for automatic HTTPS | Apache-2.0 | ✅ |
| [CrowdSec](https://github.com/crowdsecurity/crowdsec) + firewall bouncer | Banning | `banning.engine: crowdsec`: installs both from distro repos, owns a parser whitelist for the allowlist, bans and events via `cscli … -o json`; Central API off by default | MIT | ✅ opt-in |
| [ufw](https://launchpad.net/ufw) | Firewall | `firewall.manage`: the agent keeps its own allow rules (tagged `alastor`: SSH from `firewall.ssh`, `network.allowPublicPorts`, `firewall.allow`), validated with `--dry-run`, rolled back on failure, refused when SSH could be locked out | GPL-3.0 | ✅ opt-in |
| [Tailscale](https://tailscale.com/) | Network | detected, never installed: tailnet state, IPs, Tailscale SSH, key expiry; SSH exposure check suggests limiting SSH to the tailnet | BSD-3-Clause | ✅ opt-in |
| [AIDE](https://aide.github.io/) | Integrity | `integrity.checkSchedule`: runs with the agent's own config and database; reports added, removed and changed system files against an accepted baseline; "accept changes" re-records it | GPL-2.0-or-later | ✅ opt-in |
| [rkhunter](https://rkhunter.sourceforge.net/) | Malware | `malware.rootkitSchedule`: `--check --rwo` after recording file properties; never updates from the internet; warnings ranked by severity, `rootkitIgnore` for known ones | GPL-2.0-or-later | ✅ opt-in |
| [ClamAV](https://www.clamav.net/) | Malware | `malware.scanSchedule`: niced `clamscan` of web roots and upload dirs, report only; signatures from the server's freshclam mirror (hosts never contact ClamAV's CDN) | GPL-2.0 | ✅ opt-in |

Why a few pieces (baseline checks, exposure inventory, SSH login monitor) are built rather than bundled is explained
in [architecture.md](architecture.md#8-why-some-pieces-are-built-rather-than-bundled).

## Data sources the server fetches

All free, no account needed. Air-gapped servers can switch each one off (see [configuration.md](configuration.md)).

| Source | Used for |
|---|---|
| [NVD](https://nvd.nist.gov/) CVE API 2.0 | threat feed (optional `ALASTOR_NVDAPIKEY` raises the rate limit) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | threat feed; flags host CVEs that are actively exploited |
| The Hacker News, BleepingComputer, Krebs on Security, SecurityWeek, Dark Reading (RSS) | security news in the threat feed |
| [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/), [FireHOL level 1](https://iplists.firehol.org/?ipset=firehol_level1), [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/blocklist/), [Emerging Threats compromised](https://rules.emergingthreats.net/), [blocklist.de](https://www.blocklist.de/en/export.html), [CINS Army](https://cinsscore.com/#list) | IP blocklists, merged per host minus private ranges and your allowlist |
| `ghcr.io/aquasecurity/trivy-db:2`, Grype DB v6 | vulnerability databases mirrored for agents |
| [OSV.dev](https://osv.dev/) API | known vulnerabilities for the software inventory (only package names and versions are sent) |
| ClamAV signatures (`database.clamav.net`, through `freshclam`) | malware scans; mirrored only once some host has a malware scan schedule |

## Main libraries

ASP.NET Core, EF Core (SQLite, [Npgsql](https://www.npgsql.org/)), SignalR, [Serilog](https://serilog.net/),
[YamlDotNet](https://github.com/aaubry/YamlDotNet), [Cronos](https://github.com/HangfireIO/Cronos),
[MailKit](https://github.com/jstedfast/MailKit) on the backend; [Svelte 5](https://svelte.dev/),
[Vite](https://vite.dev/), `@microsoft/signalr` and [yaml](https://eemeli.org/yaml/) in the dashboard.

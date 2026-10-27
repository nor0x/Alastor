[← Alastor](../README.md) · Features

# Features

Everything below works today, across the server (REST API, SignalR, SQLite or PostgreSQL), the agent and the Svelte
dashboard. Live updates use SignalR, with polling when the hub is unreachable.

## Fleet overview

- **Hosts:** a table or a grid of host cards (OS, kernel, IPs, uptime, usage and posture), and host detail with live
  metrics, a capability matrix, events, bans and commands. Reboot a host from the dashboard (in one minute, with a
  warning to logged-in users).
- **Charts:** events per day by severity, ban activity per hour, a host × area posture matrix, and 30/90/365-day trends
  of baseline score, CVEs, exploited CVEs and pending updates from daily posture snapshots.
- **Issues:** open problems per host (public SSH, exploited CVEs, malware, failing checks, tools down, …) that resolve on
  their own when fixed, with acknowledge and a badge in the navigation.
- **Alerts:** email, webhook and ntfy channels, with dedup and digests.

## Policy

- **Policy:** layered global → group → host, with form and YAML editors, live validation, schedule preview, version
  history and revert.

## Keeping attackers out

- **Banning:** fail2ban, or CrowdSec with its firewall bouncer (opt-in), managed from policy, with bans and allowlist
  in the dashboard.
- **Blocklists:** public IP blocklists, merged by the server.
- **Firewall:** ufw managed from policy (opt-in, Debian/Ubuntu) with lockout guards for SSH.
- **Exposure:** warnings when SSH is reachable from the internet, an inventory of every listening service (owner,
  systemd unit, `systemd-analyze security` score, firewall verdict) with alerts for public ports outside
  `network.allowPublicPorts`, and Tailscale detection.
- **SSH logins:** successful logins from the journal or auth.log, with an alert on a user's first login from a new
  address (Critical for root) and trusted sources that never alert.
- **SSH keys:** every account's authorized keys with fingerprints and weak keys flagged; add and remove keys from the
  dashboard (with a guard against removing the last admin key), and an alert when a key appears that nobody added
  through Alastor.

## Patching and vulnerabilities

- **Security updates:** reported, installed now or on a schedule, with the services still running replaced code
  (needrestart / needs-restarting) and a kernel-reboot check.
- **CVE scans:** Trivy or Grype against a server-mirrored database, joined with CISA KEV, plus the images of running
  Docker/Podman containers (opt-in, local images only).
- **Software inventory:** every installed package and version per host and across the fleet, with available updates
  and known CVEs from the CVE scan and OSV.dev; upgrade or uninstall one package after a dry run, or copy the command.
- **Threat feed:** NVD, CISA KEV and security news.

## Hardening

- **Security baseline:** 21 checks per host with one-click, reversible fixes.
- **Lynis audits:** hardening index and a remediation checklist.

## Malware and tampering

- **Malware scans:** ClamAV (opt-in) over web roots and upload directories, with signatures mirrored by the server.
- **File integrity and rootkits:** AIDE (opt-in) compares binaries, `/etc` and SSH keys with an accepted baseline;
  rkhunter (opt-in) checks for rootkits and changed binaries. Both report only, with accept actions in the dashboard.

## Housekeeping

- **Storage:** the biggest folders (with what the common ones hold) and files per host, and one-click cleanups with
  the command next to each: package caches, old journal entries, rotated logs, Docker build cache, stopped containers,
  unused images and volumes, old kernels, snap revisions, dev caches. A fleet view sorted by disk usage cleans several
  hosts at once, and a host whose root filesystem passes 90% gets an issue and an alert.
- **Settings and About:** groups, enrollment tokens, API keys, audit log, and tool licenses.
- **Installers:** one-line installers for the server and the agent that open nothing new by default (tailnet or
  loopback), an `alastor` command and a dashboard card to start and stop them on the server's machine, and a Docker
  image with compose for the server.
  See [install.md](install.md).

The tools behind each feature are listed in [tools.md](tools.md); how each one is wired up is in
[architecture.md](architecture.md).

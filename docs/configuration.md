[← Alastor](../README.md) · Configuration

# Server configuration

The server reads environment variables. With the installer they live in `/etc/alastor/server.env`
(`systemctl restart alastor-server` after editing); with Docker, pass them to `docker compose`. What each host does
(banning, scans, schedules, firewall, …) is set in the policy editor in the dashboard, not here.

| Env var | Default | |
|---|---|---|
| `ALASTOR_DATADIR` | `./data` next to the binary | SQLite DB, JWT key, data-protection keys |
| `ALASTOR_ADMINUSER` / `ALASTOR_ADMINPASSWORD` | `admin` / generated (printed once) | first-run admin |
| `ALASTOR_DATABASEPROVIDER` | `sqlite` | or `postgres` with `ALASTOR_CONNECTIONSTRING` |
| `ALASTOR_PUBLICURL` | request host | used in generated install commands |
| `ALASTOR_AGENTDOWNLOADDIR` | `./agent` next to the binary | agent binaries served at `/install/agent/` to hosts being installed |
| `ALASTOR_HEARTBEATINTERVAL` | `60s` | default heartbeat; per-host override via `agent.heartbeatInterval` |
| `ALASTOR_RETENTIONRUNINTERVAL`, `…METRICRETENTION`, `…EVENTRETENTION`, … | `1h`, `7d`, `90d` | all server timings: see [architecture.md](architecture.md#timings-and-schedules) |
| `ALASTOR_SECURECOOKIES` | `true` | set `false` only for plain-HTTP local dev |
| `ALASTOR_DASHBOARDALLOWFROM` | `loopback,private,tailnet` | who may reach the dashboard: `any`, `loopback`, `private`, `tailnet` and CIDRs. Everyone else gets a bare 404 before sign-in |
| `ALASTOR_AGENTALLOWFROM` | `loopback,private,tailnet` | the same for the agent API and installers (`/api/agent`, `/hubs/agent`, `/install`) |
| `ALASTOR_AUDITRETENTION` / `ALASTOR_LOGINSOURCERETENTION` / `ALASTOR_POLICYVERSIONSKEEP` | `365d` / `365d` / `50` | retention for the audit log, known SSH login sources and policy history (see *Settings → Alastor data*) |
| `ALASTOR_BLOCKLISTSENABLED` / `ALASTOR_BLOCKLISTREFRESHINTERVAL` | `true` / `4h` | public IP blocklists the server pulls and merges per host (*Bans → Blocklists*) |
| `ALASTOR_OSVENABLED` | `true` | look up installed package versions on OSV.dev for the *Software* view; `false` for air-gapped servers |
| `ALASTOR_VULNDBENABLED` / `ALASTOR_VULNDBREFRESHINTERVAL` | `true` / `12h` | mirror the Trivy/Grype databases for agents' CVE scans; `false` for air-gapped servers (place the files in `data/vulndb/`) |
| `ALASTOR_FRESHCLAMPATH` / `ALASTOR_CLAMAVMIRROR` | `freshclam` / `database.clamav.net` | ClamAV signature mirror for agents' malware scans (needs the `clamav-freshclam` package on the server; the Docker image has it). Also under `data/vulndb/clamav/` |
| `ALASTOR_TRIVYDBREPOSITORY` / `ALASTOR_GRYPEDBURL` | `ghcr.io/aquasecurity/trivy-db:2` / `https://grype.anchore.io/databases` | where the mirror pulls from (an internal registry or mirror) |
| `ALASTOR_ALERTDEDUPWINDOW` / `ALASTOR_ALERTBURST` | `1h` / `1` | alert dedup per host and event; channels (email, webhook, ntfy) are set up under *Settings → Notifications* |
| `ALASTOR_THREATFEEDENABLED` | `true` | fetch NVD, CISA KEV and security news RSS; `false` for air-gapped servers |
| `ALASTOR_THREATFEEDINTERVAL` / `ALASTOR_THREATFEEDRETENTION` | `20m` / `30d` | |
| `ALASTOR_NVDAPIKEY` | – | optional, free; raises NVD's rate limit tenfold |
| `ALASTOR_UPDATECHECKENABLED` / `ALASTOR_UPDATEREPOSITORY` | `true` / `nor0x/Alastor` | twice a day, ask GitHub for the latest release and show a notice in the sidebar when it's newer than this server; `false` for air-gapped servers |
| `ASPNETCORE_URLS` | `http://127.0.0.1:8080` | loopback by default: put Caddy/nginx with TLS or `tailscale serve` in front, or listen on the tailnet address |

The network allowlists and other protections are explained in [security.md](security.md).

# SentinelVPS

Free, self-hosted endpoint protection for Linux VPS fleets: one lightweight agent per server, one central
server, one dashboard. SentinelVPS doesn't reinvent security engines. It **orchestrates** proven open-source
tools (fail2ban, CrowdSec, Trivy, Lynis, unattended-upgrades, …): it installs or adopts them, owns their
configuration declaratively, and turns their output into one normalized alert pipeline.

**Status:** deliverables 1–3 backend complete (server API, SQLite/PostgreSQL migrations, agent with heartbeat,
fail2ban integration end to end), threat feed (NVD CVEs, CISA KEV, security news). The Svelte dashboard has
started: sign-in and the *Threat feed* page; fleet views come next.
See [docs/architecture.md](docs/architecture.md) for the event model, integration interface and API surface.

## Repository layout

```
src/Sentinel.Core     domain: SecurityEvent, policy model, IToolIntegration, fail2ban integration, platform seams
src/Sentinel.Server   ASP.NET Core minimal API + SignalR + EF Core; serves the embedded SPA; single-file publish
src/Sentinel.Agent    supervisor daemon (Native AOT); enroll | run | status | uninstall
src/sentinel-web      Svelte 5 + Vite dashboard; builds into Sentinel.Server/wwwroot
tests/Sentinel.Tests  xUnit: parsers and normalization on real fail2ban fixtures, reconciliation, policy, API e2e
policy/default.yaml   global default policy (embedded into the server)
docs/                 architecture
```

## Development quickstart

Requirements: .NET 10 SDK. For a real agent: a Linux box with systemd and root.

```bash
# server on :8080, data in ./data (SQLite, WAL)
SENTINEL_DATADIR=./data SENTINEL_ADMINPASSWORD='change-me-please' SENTINEL_SECURECOOKIES=false \
  dotnet run --project src/Sentinel.Server

# log in, create a single-use enrollment token
curl -c cj -X POST localhost:8080/api/auth/login -H 'content-type: application/json' \
  -d '{"username":"admin","password":"change-me-please"}'
curl -b cj -X POST localhost:8080/api/enrollment-tokens -H 'content-type: application/json' \
  -H 'X-Sentinel-Request: 1' -d '{"note":"my vps"}'

# on the target host (root): enroll, then run
sudo ./sentinel-agent enroll --server http://SERVER:8080 --token sve_... --insecure   # https:// in production
sudo ./sentinel-agent run
```

Dashboard development: with the server running on :8080, `cd src/sentinel-web && npm install && npm run dev`
serves the SPA with hot reload on :5173 and proxies `/api` and `/hubs` to the server. `npm run build` writes the
production bundle into `src/Sentinel.Server/wwwroot` (Release builds of the server run it automatically).

The agent adopts an existing fail2ban, or installs it from the distro repos, writes
`/etc/fail2ban/jail.d/sentinel-vps.local` from the policy, validates it with `fail2ban-client -t`, reloads,
and starts streaming ban events.

## Configuration (server)

| Env var | Default | |
|---|---|---|
| `SENTINEL_DATADIR` | `./data` next to the binary | SQLite DB, JWT key, data-protection keys |
| `SENTINEL_ADMINUSER` / `SENTINEL_ADMINPASSWORD` | `admin` / generated (printed once) | first-run admin |
| `SENTINEL_DATABASEPROVIDER` | `sqlite` | or `postgres` with `SENTINEL_CONNECTIONSTRING` |
| `SENTINEL_PUBLICURL` | request host | used in generated install commands |
| `SENTINEL_HEARTBEATINTERVAL` | `60s` | default heartbeat; per-host override via `agent.heartbeatInterval` |
| `SENTINEL_RETENTIONRUNINTERVAL`, `…METRICRETENTION`, `…EVENTRETENTION`, … | `1h`, `7d`, `90d` | all server timings: see [docs/architecture.md](docs/architecture.md#timings-and-schedules) |
| `SENTINEL_SECURECOOKIES` | `true` | set `false` only for plain-HTTP local dev |
| `SENTINEL_THREATFEEDENABLED` | `true` | fetch NVD, CISA KEV and security news RSS; `false` for air-gapped servers |
| `SENTINEL_THREATFEEDINTERVAL` / `SENTINEL_THREATFEEDRETENTION` | `20m` / `30d` | |
| `SENTINEL_NVDAPIKEY` | – | optional, free; raises NVD's rate limit tenfold |
| `ASPNETCORE_URLS` | `http://0.0.0.0:8080` | put Caddy/nginx with TLS in front |

## Build & test

```bash
dotnet test
dotnet publish src/Sentinel.Server -c Release -r linux-x64 -o artifacts/server   # one file, SPA embedded
dotnet publish src/Sentinel.Agent  -c Release -r linux-x64 -o artifacts/agent    # Native AOT (needs clang, zlib1g-dev)
dotnet publish src/Sentinel.Agent  -c Release -r linux-x64 -p:AgentAot=false -o artifacts/agent-jit
```

## License

MIT for SentinelVPS's own code. Bundled tools are installed from your distribution and keep their own
licenses; `GET /api/about` lists them.

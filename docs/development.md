[← Alastor](../README.md) · Development

# Development

## Repository layout

```
src/Alastor.Core      domain: SecurityEvent, policy model, IToolIntegration, the tool integrations
                      (fail2ban, CrowdSec, baseline, blocklists, updates, vulnerabilities, Lynis, network, ClamAV),
                      platform seams
src/Alastor.Server    ASP.NET Core minimal API + SignalR + EF Core; serves the embedded SPA; single-file publish
src/Alastor.Agent     supervisor daemon (Native AOT); enroll | run | status | uninstall
src/alastor-web       Svelte 5 + Vite dashboard; builds into Alastor.Server/wwwroot
tests/Alastor.Tests   xUnit: parsers on captured tool output (Fixtures/, each folder documents its source),
                      reconciliation, policy, API end to end
policy/default.yaml   global default policy (embedded into the server)
install/              install.sh (server) and agent-install.sh, also served by the server at /install/{server,agent}.sh
Dockerfile, compose.yaml   server image (dashboard + agent binary + freshclam)
docs/                 architecture and these guides
```

## Quickstart

Requirements: .NET 10 SDK. For a real agent: a Linux box with systemd and root.

```bash
# server on :8080, data in ./data (SQLite, WAL)
ALASTOR_DATADIR=./data ALASTOR_ADMINPASSWORD='change-me-please' ALASTOR_SECURECOOKIES=false \
  dotnet run --project src/Alastor.Server

# log in, create a single-use enrollment token
curl -c cj -X POST localhost:8080/api/auth/login -H 'content-type: application/json' \
  -d '{"username":"admin","password":"change-me-please"}'
curl -b cj -X POST localhost:8080/api/enrollment-tokens -H 'content-type: application/json' \
  -H 'X-Alastor-Request: 1' -d '{"note":"my vps"}'

# on the target host (root): enroll, then run
sudo ./alastor-agent enroll --server http://SERVER:8080 --token sve_... --insecure   # https:// in production
sudo ./alastor-agent run
```

## Dashboard

With the server running on :8080, `cd src/alastor-web && npm install && npm run dev` serves the SPA with hot reload on
:5173 and proxies `/api` and `/hubs` to the server. `npm run build` writes the production bundle into
`src/Alastor.Server/wwwroot` (Release builds of the server run it automatically).

## Build and test

```bash
dotnet test
dotnet publish src/Alastor.Server -c Release -r linux-x64 -o artifacts/server   # one file, SPA embedded
dotnet publish src/Alastor.Agent  -c Release -r linux-x64 -o artifacts/agent    # Native AOT (needs clang, zlib1g-dev)
dotnet publish src/Alastor.Agent  -c Release -r linux-x64 -p:AgentAot=false -o artifacts/agent-jit
```

Internals (event model, integration interface, API surface, policy model) are in [architecture.md](architecture.md).

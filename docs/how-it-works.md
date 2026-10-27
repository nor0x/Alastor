[← Alastor](../README.md) · How it works

# How it works

Alastor is one server (API, dashboard, database and background workers in a single binary) and one lightweight agent
per host. The agent installs or adopts the security tools on its host, configures them from your policy and reports
what they find.

```mermaid
flowchart LR
    browser([Browser]) -- "REST /api · SignalR" --> server

    subgraph server["alastor-server (one binary)"]
        direction TB
        spa[Svelte dashboard] --- api[REST API + SignalR hubs]
        api --- db[(SQLite / PostgreSQL)]
        api --- workers[Workers: presence, retention,<br/>threat feed, blocklists,<br/>vuln DB mirror, alerts]
    end

    subgraph host["each VPS: alastor-agent"]
        direction TB
        sup[Supervisor<br/>heartbeat → reconcile → commands]
        sup --> f2b[fail2ban or CrowdSec]
        sup --> nft[nftables / ipset]
        sup --> pkg[apt · dnf · apk<br/>unattended-upgrades]
        sup --> scan[Trivy / Grype]
        sup --> lynis[Lynis]
        sup --> clam[ClamAV]
        sup --> net[SSH & service exposure<br/>ss · systemd-analyze<br/>Tailscale · ufw / nft]
        sup --> base[Baseline checks<br/>sshd · sysctl · ufw …]
    end

    host -- "HTTPS pull: policy, blocklists,<br/>vuln DB, ClamAV signatures ·<br/>push: events, reports" --> server
    server -. "SignalR wake-up" .-> host
    workers -- fetch --> internet[(NVD · CISA KEV · RSS<br/>blocklists · trivy-db / grype-db ·<br/>ClamAV via freshclam)]
    workers -- alerts --> channels([Email · Webhook · ntfy])
```

## Agents only talk to your server

Everything that comes from the internet (threat intel, IP blocklists, vulnerability databases, ClamAV signatures) is
fetched once by the server and handed to agents, so hosts need no outbound access beyond it, apart from their
distribution's package mirrors for installs and updates. CrowdSec's Central API (signal sharing and its community
blocklist) stays off unless you set `banning.crowdsecCentralApi: true`.

## One event stream

Every tool's output is normalized into one event stream that feeds the timeline, live dashboard and alerts:

```mermaid
flowchart LR
    tools[fail2ban log · scan reports ·<br/>Lynis report.dat · package managers] --> norm[Agent normalizes<br/>to SecurityEvent]
    norm --> store[(Server stores event)]
    store --> live[Dashboard via SignalR]
    store --> thr{Severity ≥ channel<br/>threshold?}
    thr -- no --> done([timeline only])
    thr -- yes --> dedup{Leaky-bucket dedup<br/>per host + event}
    dedup -- suppressed --> count([counted, reported<br/>with next alert])
    dedup -- send --> out([Email · Webhook · ntfy<br/>or periodic digest])
```

## Policy in, reconciled hosts out

Configuration flows the other way: you edit a layered policy (global → group → host) in the dashboard, and each
agent reconciles its host to match:

```mermaid
sequenceDiagram
    participant D as Dashboard
    participant S as Server
    participant A as Agent
    participant T as Tool (e.g. fail2ban)
    D->>S: save policy (YAML / form)
    S-->>A: SignalR "wake"
    A->>S: heartbeat, GET merged policy
    A->>T: install or adopt, write owned config slice
    A->>T: validate (fail2ban-client -t, nft -c), reload
    T-->>A: events / reports
    A->>S: POST events, reports, command results
    S-->>D: live update
```

For example, the agent adopts an existing fail2ban, or installs it from the distro repos, writes
`/etc/fail2ban/jail.d/alastor.local` from the policy, validates it with `fail2ban-client -t`, reloads, and starts
streaming ban events.

The event model, integration interface and API surface are described in [architecture.md](architecture.md).

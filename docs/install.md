[← Alastor](../README.md) · Install

# Install

Supported: x86_64 and arm64 Linux with systemd and glibc (Debian, Ubuntu, RHEL/Alma/Rocky, Fedora).

## Server

One command on the machine that runs the dashboard (a VPS, or any Linux box at home), as root:

```bash
# Tailscale running on this machine: the dashboard is on your tailnet only (HTTPS through tailscale serve
# when the tailnet has HTTPS certificates). Without Tailscale: this machine only, open it through an SSH tunnel.
curl -fsSL https://raw.githubusercontent.com/nor0x/Alastor/main/install/install.sh | sudo bash -s -- --with-agent

# VPS with a domain pointing at it: HTTPS on the internet through Caddy
curl -fsSL https://raw.githubusercontent.com/nor0x/Alastor/main/install/install.sh | sudo bash -s -- --domain alastor.example.com --with-agent
```

It prints the dashboard URL, a generated admin password and the server's own
[security check](security.md).

## Who can reach it

Installing Alastor doesn't open anything new: no public port, no firewall change, unless you ask for one. `--access`
picks how browsers and agents reach the server (an upgrade without it keeps what it had):

| | Listens on | Dashboard URL | Firewall | Reachable from |
|---|---|---|---|---|
| `auto` (default) | `tailscale` when Tailscale is running, else `local` | | | |
| `tailscale` | `127.0.0.1` behind `tailscale serve`, or the tailnet address when the tailnet has no HTTPS certificates | `https://<machine>.<tailnet>.ts.net`, or `http://<machine>.<tailnet>.ts.net:8080` | ufw: the port on `tailscale0` only | your tailnet |
| `local` | `127.0.0.1` | `http://localhost:8080` through `ssh -L 8080:127.0.0.1:8080 you@server` | unchanged | this machine (other servers can't enroll until you re-run with `--access tailscale` or `--domain`) |
| `--domain NAME` | `127.0.0.1` behind Caddy | `https://NAME` | 80 and 443 | the internet, over HTTPS |
| `public` | `0.0.0.0` | `http://<server IP>:8080` | the port, from anywhere | every network, over plain HTTP: trusted networks only |

Each mode also sets who may connect (`ALASTOR_DASHBOARDALLOWFROM`, `ALASTOR_AGENTALLOWFROM`, see
[configuration](configuration.md)): `loopback,tailnet` for `tailscale`, `loopback` for `local`, `any` for `--domain`
and `public`. Servers installed before these settings existed keep answering everyone until you re-run the installer
with `--access`. Agents refuse plain HTTP unless enrolled with `--insecure`, except for loopback and Tailscale addresses
(`100.64.0.0/10`, `fd7a:115c:a1e0::/48`, `*.ts.net`), where WireGuard already encrypts the traffic.

## Start and stop

Both installers add an `alastor` command for the services on that machine:

```bash
alastor status                    # server and agent: running?, starts at boot?, URL
sudo alastor stop                 # everything Alastor on this machine; or: sudo alastor stop agent
sudo alastor start server
sudo alastor restart
sudo alastor disable agent        # stop it and keep it off after reboots (enable to undo)
alastor logs server               # follow the journal
```

The dashboard does the same for its own machine under **Settings → Server → This machine**: restart or stop the
server, and start, stop or restart the local agent. The server runs unprivileged, so it never touches services
itself: it drops a request that a small root unit (`alastor-control.path`) carries out, and only these five are
accepted. A server stopped from the dashboard starts again with `sudo alastor start server` (or at the next boot).

## Adding hosts

Open **Settings → Enrollment → New token** in the dashboard and run the command it shows on that server. That command
comes from your own Alastor server, which also hands out the agent binary:

```bash
curl -fsSL https://alastor.example.com/install/agent.sh | sudo bash -s -- --server https://alastor.example.com --token sve_…
```

## Upgrade and uninstall

Run either script again to upgrade; settings, data and enrollment are kept. `--uninstall` removes the server or agent
(`--uninstall --purge` also deletes the server's database). `--help` lists all options.

## Where things live

| Path | |
|---|---|
| `/opt/alastor/` | server binary, plus `agent/` with the agent binaries it serves |
| `/etc/alastor/server.env` | server settings ([env vars](configuration.md)); `sudo alastor restart server` after editing |
| `/var/lib/alastor/` | database and keys; `control/` holds start/stop requests from the dashboard |
| `/usr/local/bin/alastor-agent`, `/etc/alastor-agent/agent.json` | agent binary and enrollment |
| `/usr/local/bin/alastor` | the start/stop command; `alastor-control.path` and `.service` in `/etc/systemd/system` carry out the dashboard's requests |

## While the repository is private

The script and the release binaries need a GitHub token with read access (`gh auth token` prints yours):

```bash
export GITHUB_TOKEN=$(gh auth token)   # or a fine-grained PAT with Contents: read
curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" https://raw.githubusercontent.com/nor0x/Alastor/main/install/install.sh \
  | sudo GITHUB_TOKEN="$GITHUB_TOKEN" bash
```

Agents need no token: they download the agent from your server. Binaries come from GitHub releases, built by
`.github/workflows/release.yml` when a `v*` tag is pushed. `ALASTOR_DOWNLOAD_BASE=https://…` makes both scripts download
`<base>/<version>/<asset>` instead, for a mirror or a future website.

## From a clone

The script builds and installs that checkout instead of downloading a release (needs the .NET 10 SDK and Node.js 22+;
clang and zlib1g-dev give a Native AOT agent, otherwise it builds a JIT one). The build runs as the checkout's owner,
into `artifacts/install/`. All options work the same, and `--version vX.Y.Z` installs that release instead:

```bash
git clone https://github.com/nor0x/Alastor && cd Alastor
sudo ./install/install.sh --with-agent
```

Prebuilt binaries can also be passed in directly:
`sudo ./install/install.sh --binary path/to/alastor-server --agent-dir <dir with alastor-agent-linux-x64>`.

## Docker

The server also runs as a container. The image holds the dashboard, the agent binary it hands out to hosts (for the
image's architecture) and `freshclam` for the ClamAV mirror. Agents still run on each VPS under systemd: install them
with the command from **Settings → Enrollment**.

```bash
git clone https://github.com/nor0x/Alastor && cd Alastor
ALASTOR_ADMINPASSWORD='a long passphrase' ALASTOR_PUBLICURL=https://alastor.example.com docker compose up -d
```

Data lives in the `alastor-data` volume (`/data`). Compose publishes the port on the host's loopback only
(`127.0.0.1:8080`), because Docker's published ports bypass ufw. For browsers and agents elsewhere, put HTTPS in front
of it on the host: a reverse proxy with TLS, or `tailscale serve --bg --https=443 http://127.0.0.1:8080` for your
tailnet. For a quick local try without TLS, also set `ALASTOR_SECURECOOKIES=false`. Start and stop it with
`docker compose stop` / `start` (the dashboard's start/stop and the `alastor` command are for the systemd install).

For PostgreSQL: `docker compose --profile postgres up -d` with `ALASTOR_DATABASEPROVIDER=postgres` and
`ALASTOR_CONNECTIONSTRING="Host=postgres;Database=alastor;Username=alastor;Password=…"`.

`docker build --build-arg WITH_AGENT=false .` skips the Native AOT agent build (hosts then download the agent from
GitHub releases).

## Next steps

- [configuration.md](configuration.md): server settings
- [security.md](security.md): how the server protects itself, and what to check after installing

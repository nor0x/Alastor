[← Alastor](../README.md) · Install

# Install

Supported: x86_64 and arm64 Linux with systemd and glibc (Debian, Ubuntu, RHEL/Alma/Rocky, Fedora).

## Server

One command on the machine that runs the dashboard (a VPS, or any Linux box at home), as root:

```bash
# VPS with a domain pointing at it: HTTPS through Caddy, and protect this server too
curl -fsSL https://raw.githubusercontent.com/nor0x/Alastor/main/install/install.sh | sudo bash -s -- --domain alastor.example.com --with-agent

# local machine or LAN, plain HTTP on :8080
curl -fsSL https://raw.githubusercontent.com/nor0x/Alastor/main/install/install.sh | sudo bash
```

It prints the dashboard URL and a generated admin password.

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
| `/etc/alastor/server.env` | server settings ([env vars](configuration.md)); `systemctl restart alastor-server` after editing |
| `/var/lib/alastor/` | database and keys |
| `/usr/local/bin/alastor-agent`, `/etc/alastor-agent/agent.json` | agent binary and enrollment |

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

Data lives in the `alastor-data` volume (`/data`). Put a reverse proxy with TLS in front of port 8080; for a quick
local try without TLS, also set `ALASTOR_SECURECOOKIES=false` and enroll agents with `--insecure`.

For PostgreSQL: `docker compose --profile postgres up -d` with `ALASTOR_DATABASEPROVIDER=postgres` and
`ALASTOR_CONNECTIONSTRING="Host=postgres;Database=alastor;Username=alastor;Password=…"`.

`docker build --build-arg WITH_AGENT=false .` skips the Native AOT agent build (hosts then download the agent from
GitHub releases).

## Next steps

- [configuration.md](configuration.md): server settings
- [security.md](security.md): how the server protects itself, and what to check after installing

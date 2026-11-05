#!/usr/bin/env bash
# Alastor server installer.
#
#   curl -fsSL https://raw.githubusercontent.com/nor0x/Alastor/main/install/install.sh | sudo bash
#   curl -fsSL …/install.sh | sudo bash -s -- --domain alastor.example.com --with-agent
#   sudo ./install/install.sh            # from a clone: builds and installs that checkout
#
# Installs (or upgrades, when run again) the alastor-server binary, the agent binaries it hands out to
# new hosts, a systemd unit, the `alastor` command (status, start, stop, restart on this machine), and optionally
# Caddy for automatic HTTPS. Data and settings survive upgrades.
# Run from a clone of the repository, it builds the server and agent from that checkout instead of downloading a
# release (needs the .NET 10 SDK and Node.js; clang and zlib1g-dev for a Native AOT agent, else a JIT build).
#
# Installing Alastor does not expose anything new by default: the server is reachable only over your tailnet when
# Tailscale is up, else only from this machine. Choose with --access, or --domain for HTTPS on the internet.
#
# Options:
#   --access MODE        who can reach the dashboard and the agent API (default: auto)
#                          auto       tailscale when Tailscale is running on this machine, else local
#                          tailscale  your tailnet only: https://<machine>.<tailnet>.ts.net through `tailscale serve`
#                                     when the tailnet has HTTPS certificates, else http://<tailnet name or IP>:PORT
#                          local      this machine only (127.0.0.1); open the dashboard through an SSH tunnel
#                          public     plain HTTP on every interface, port opened in the firewall: not for the internet
#                        An upgrade without --access or --domain keeps how the server is reached.
#   --domain NAME        serve https://NAME through Caddy (installed from the distro repos); needs ports 80/443 and DNS
#   --port N             port the server listens on (default 8080)
#   --public-url URL     URL agents and browsers use (default: follows from --access or --domain)
#   --with-agent         also install the agent on this machine and enroll it with the new server
#   --version vX.Y.Z     release to install (default: latest); from a clone, download this release instead of building
#   --binary PATH        install this alastor-server binary instead of downloading one
#   --agent-dir DIR      take alastor-agent-linux-{x64,arm64} from DIR instead of downloading them
#   --uninstall          remove the service and binaries; keeps data and settings
#   --purge              with --uninstall: also delete the database and settings
#
# Environment:
#   GITHUB_TOKEN             read access to the repository while it is private
#   ALASTOR_REPO             GitHub repository to download releases from (default nor0x/Alastor)
#   ALASTOR_DOWNLOAD_BASE    download BASE/<version>/<asset> instead of GitHub releases (a mirror or website)
set -euo pipefail

# Everything runs from main(), so a download cut off midway through `curl | bash` executes nothing.
main() {
  REPO="${ALASTOR_REPO:-nor0x/Alastor}"
  PREFIX=/opt/alastor
  CONF_DIR=/etc/alastor
  ENV_FILE="$CONF_DIR/server.env"
  DATA_DIR=/var/lib/alastor
  UNIT=/etc/systemd/system/alastor-server.service
  CADDY_SNIPPET=/etc/caddy/alastor.caddy
  SERVICE_USER=alastor
  SERVE_MARK='# managed: tailscale-serve'
  CONTROL_UNIT=/etc/systemd/system/alastor-control
  AGENT_CONFIG=/etc/alastor-agent/agent.json

  local access="" domain="" port="" public_url="" version="latest" version_set=0 binary="" agent_dir="" with_agent=0 uninstall=0 purge=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --access) access="$(need_arg "$@")"; shift ;;
      --domain) domain="$(need_arg "$@")"; shift ;;
      --port) port="$(need_arg "$@")"; shift ;;
      --public-url) public_url="$(need_arg "$@")"; shift ;;
      --version) version="$(need_arg "$@")"; version_set=1; shift ;;
      --binary) binary="$(need_arg "$@")"; shift ;;
      --agent-dir) agent_dir="$(need_arg "$@")"; shift ;;
      --with-agent) with_agent=1 ;;
      --uninstall) uninstall=1 ;;
      --purge) purge=1 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1 (see --help)" ;;
    esac
    shift
  done

  case "$access" in ''|auto|tailscale|local|public) ;; *) die "--access must be auto, tailscale, local or public." ;; esac
  [ -z "$domain" ] || [ -z "$access" ] || [ "$access" = auto ] || die "--domain already decides access (HTTPS through Caddy); drop --access $access."

  [ "$(uname -s)" = Linux ] || die "Alastor runs on Linux."
  [ "$(id -u)" -eq 0 ] || die "Run as root, e.g.: curl -fsSL … | sudo bash"
  command -v systemctl >/dev/null && [ -d /run/systemd/system ] || die "systemd is required."

  if [ "$uninstall" -eq 1 ]; then do_uninstall "$purge"; return; fi

  local rid; rid="$(detect_rid)"
  need_cmd curl
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

  # Settings from a previous install are kept unless overridden on the command line.
  local upgrade=0 mode
  if [ -f "$ENV_FILE" ]; then
    upgrade=1
    [ -n "$port" ] || port="$(env_port)"
  fi
  port="${port:-8080}"
  case "$port" in ''|*[!0-9]*) die "--port must be a number." ;; esac

  # How browsers and agents reach the server. Without --access or --domain an upgrade keeps what it had.
  if [ -n "$domain" ]; then mode=domain
  elif [ "$upgrade" -eq 1 ] && [ -z "$access" ]; then mode=keep
  else mode="${access:-auto}"; fi
  if [ "$mode" = auto ]; then
    if tailscale_up; then mode=tailscale; else mode=local; fi
  elif [ "$mode" = tailscale ] && ! tailscale_up; then
    die "--access tailscale: Tailscale is not running here. Start it (tailscale up) or choose --access local."
  fi
  # listen: bind address; allow: ALLOWFROM for the dashboard and agents; serve: put `tailscale serve` in front.
  local listen allow="" serve=0 cert_domain="" default_url
  case "$mode" in
    domain) listen=127.0.0.1; allow=any; default_url="https://$domain" ;;
    tailscale)
      allow=loopback,tailnet
      cert_domain="$(ts_cert_domain)"
      if [ -n "$cert_domain" ] && ts_serve_free "$port"; then
        listen=127.0.0.1; serve=1; default_url="https://$cert_domain"
      else
        [ -z "$cert_domain" ] || warn "tailscale serve already uses port 443 here; serving Alastor on its tailnet address instead."
        listen="$(ts_ipv4)"
        [ -n "$listen" ] || die "Tailscale has no IPv4 address on this machine; choose --access local."
        default_url="http://$(ts_dns_name || echo "$listen"):$port"
      fi ;;
    local) listen=127.0.0.1; allow=loopback; default_url="http://localhost:$port" ;;
    public) listen=0.0.0.0; allow=any; default_url="http://$(primary_ip):$port" ;;
    keep)
      listen="$(env_host)"; listen="${listen:-127.0.0.1}"
      [ -n "$public_url" ] || public_url="$(env_get ALASTOR_PUBLICURL)"
      # Re-applied on every upgrade, so a changed --port reaches tailscale serve too.
      if serve_managed; then serve=1; fi
      if [ "$listen" = 127.0.0.1 ]; then default_url="http://localhost:$port"; else default_url="http://$(primary_ip):$port"; fi ;;
  esac

  # From a clone, install what is checked out rather than a release, unless one was asked for.
  local src=""
  if [ -z "$binary" ] && [ "$version_set" -eq 0 ] && [ -z "${ALASTOR_DOWNLOAD_BASE:-}" ]; then src="$(checkout_dir)"; fi
  if [ -n "$src" ]; then
    build_from_source "$src" "$rid" "$([ -n "$agent_dir" ] && echo 0 || echo 1)"
    binary="$src/artifacts/install/server/alastor-server"
    [ -n "$agent_dir" ] || agent_dir="$src/artifacts/install/agent"
    version="$(build_version "$src")"
  elif [ -n "$binary" ]; then
    version="local build"
  else
    step "Downloading Alastor ($version, $rid)"
  fi
  if [ -n "$binary" ]; then
    [ -f "$binary" ] || die "--binary: $binary not found."
    cp "$binary" "$TMP/alastor-server"
  else
    fetch_asset "alastor-server-$rid" "$TMP/alastor-server" "$version"
  fi
  chmod 755 "$TMP/alastor-server"
  mkdir -p "$TMP/agent"
  local arch
  for arch in x64 arm64; do
    if [ -n "$agent_dir" ]; then
      [ -f "$agent_dir/alastor-agent-linux-$arch" ] && cp "$agent_dir/alastor-agent-linux-$arch" "$TMP/agent/"
    elif [ -z "$binary" ]; then
      fetch_asset "alastor-agent-linux-$arch" "$TMP/agent/alastor-agent-linux-$arch" "$version" || warn "No agent binary for linux-$arch in this release."
    fi
  done
  if ! ls "$TMP"/agent/alastor-agent-* >/dev/null 2>&1; then
    warn "No agent binaries bundled: hosts will download the agent from GitHub releases instead of this server."
  fi

  step "Installing to $PREFIX"
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
      || useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /sbin/nologin "$SERVICE_USER"
  fi
  systemctl stop alastor-server 2>/dev/null || true
  mkdir -p "$PREFIX/agent"
  install -m 755 "$TMP/alastor-server" "$PREFIX/alastor-server"
  rm -f "$PREFIX"/agent/alastor-agent-* "$PREFIX/agent/SHA256SUMS"
  if ls "$TMP"/agent/alastor-agent-* >/dev/null 2>&1; then
    install -m 755 "$TMP"/agent/alastor-agent-* "$PREFIX/agent/"
    (cd "$PREFIX/agent" && sha256sum alastor-agent-* > SHA256SUMS)
  fi
  ln -sf "$PREFIX/alastor-server" /usr/local/bin/alastor-server

  if [ "$serve" -eq 1 ]; then
    step "Serving Alastor on your tailnet through tailscale serve (HTTPS, port 443)"
    if ! tailscale serve --bg --https=443 "http://127.0.0.1:$port" >/dev/null; then
      if [ "$mode" = keep ]; then
        warn "tailscale serve failed: $public_url is unreachable until it runs. Re-run with --access to choose again."
      else
        # Older Tailscale releases have a different `serve` syntax: fall back to the tailnet address.
        warn "tailscale serve failed; serving Alastor on its tailnet address instead."
        serve=0
        listen="$(ts_ipv4)"
        [ -n "$listen" ] || die "Tailscale has no IPv4 address on this machine; choose --access local."
        default_url="http://$(ts_dns_name || echo "$listen"):$port"
      fi
    fi
  elif [ "$mode" != keep ] && serve_managed; then
    tailscale serve --https=443 off >/dev/null 2>&1 || warn "Could not turn off tailscale serve on port 443; check: tailscale serve status"
  fi
  [ -n "$public_url" ] || public_url="$default_url"
  public_url="${public_url%/}"

  local secure=true; case "$public_url" in http://*) secure=false ;; esac
  local password="" legacy=0
  install -d -m 750 -o root -g "$SERVICE_USER" "$CONF_DIR"
  if [ "$upgrade" -eq 0 ]; then
    password="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20)"
    cat > "$ENV_FILE" <<EOF
# Alastor server settings. All options: https://github.com/$REPO#configuration-server
# Apply changes with: systemctl restart alastor-server
ALASTOR_DATADIR=$DATA_DIR
ALASTOR_PUBLICURL=$public_url
ALASTOR_SECURECOOKIES=$secure
ASPNETCORE_URLS=http://$listen:$port
# Who may connect, comma-separated: any, loopback, private, tailnet or CIDRs.
ALASTOR_DASHBOARDALLOWFROM=$allow
ALASTOR_AGENTALLOWFROM=$allow
# Read on first start only, then removed by the installer.
ALASTOR_ADMINPASSWORD=$password
EOF
  else
    env_set ALASTOR_PUBLICURL "$public_url"
    env_set ALASTOR_SECURECOOKIES "$secure"
    env_set ASPNETCORE_URLS "http://$listen:$port"
    if [ "$mode" != keep ]; then
      env_set ALASTOR_DASHBOARDALLOWFROM "$allow"
      env_set ALASTOR_AGENTALLOWFROM "$allow"
    else
      # Installs from before the allowlists were reachable from anywhere; keep that until asked otherwise.
      local key
      for key in ALASTOR_DASHBOARDALLOWFROM ALASTOR_AGENTALLOWFROM; do
        grep -q "^$key=" "$ENV_FILE" || { env_set "$key" any; legacy=1; }
      done
    fi
  fi
  if [ "$mode" != keep ]; then
    sed -i "/^$SERVE_MARK\$/d" "$ENV_FILE"
    [ "$serve" -eq 0 ] || echo "$SERVE_MARK" >> "$ENV_FILE"
  fi
  chown root:"$SERVICE_USER" "$ENV_FILE"; chmod 640 "$ENV_FILE"

  cat > "$UNIT" <<EOF
[Unit]
Description=Alastor server
Documentation=https://github.com/$REPO
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
User=$SERVICE_USER
Group=$SERVICE_USER
EnvironmentFile=$ENV_FILE
Environment=DOTNET_BUNDLE_EXTRACT_BASE_DIR=/var/cache/alastor
Environment=ALASTOR_CONTROLDIR=$DATA_DIR/control
ExecStart=$PREFIX/alastor-server
WorkingDirectory=$DATA_DIR
StateDirectory=alastor
StateDirectoryMode=0700
CacheDirectory=alastor
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  # Sandboxing lives in a drop-in: container-based VPSes (LXC, OpenVZ) often cannot set up the namespaces it needs.
  mkdir -p "$UNIT.d"
  cat > "$UNIT.d/hardening.conf" <<EOF
[Service]
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
EOF
  systemctl daemon-reload
  systemctl enable alastor-server >/dev/null 2>&1
  systemctl restart alastor-server || true
  sleep 2
  # Exit statuses 200+ mean systemd itself failed to set up the process, i.e. the sandbox is not supported here.
  if [ "$(systemctl show -p ExecMainStatus --value alastor-server)" -ge 200 ] 2>/dev/null; then
    warn "This machine does not support systemd sandboxing (container VPS?); running without it."
    rm -f "$UNIT.d/hardening.conf"
    systemctl daemon-reload
    systemctl restart alastor-server || true
  fi
  # The server answers on the address it is bound to: loopback, or the tailnet address.
  local api="http://$(reach_host "$listen"):$port"
  wait_healthy "$api/healthz" || die "The server did not start. See: journalctl -u alastor-server -n 50"
  # The admin now exists in the database; the password must not stay on disk.
  [ -n "$password" ] && sed -i '/^# Read on first start only/d;/^ALASTOR_ADMINPASSWORD=/d' "$ENV_FILE"

  case "$mode" in
    domain) setup_caddy "$domain" "$port"; open_firewall 80 443 ;;
    public) open_firewall "$port" ;;
    tailscale) [ "$serve" -eq 1 ] || allow_tailnet_port "$port" ;;
  esac
  install_control "$api"

  local agent_url; agent_url="$([ "$mode" = domain ] && echo "$public_url" || echo "$api")"
  if [ "$upgrade" -eq 1 ]; then repoint_local_agent "$agent_url" "$rid"; fi
  if [ "$with_agent" -eq 1 ]; then
    if [ -n "$password" ]; then
      install_local_agent "$agent_url" "$api" "$password"
    elif [ ! -f "$AGENT_CONFIG" ]; then
      warn "--with-agent on an upgrade needs a token: create one under Settings → Enrollment and run the command it shows."
    fi
  fi

  printf '\n\033[1;32m✔ Alastor server %s\033[0m (%s)\n\n' "$([ "$upgrade" -eq 1 ] && echo upgraded || echo installed)" "$version"
  printf '  Dashboard   %s\n' "$public_url"
  if [ -n "$password" ]; then
    printf '  Username    admin\n'
    printf '  Password    \033[1m%s\033[0m   (shown once; change it under Settings)\n' "$password"
  fi
  printf '  Access      %s\n' "$(access_summary "$mode" "$serve" "$listen")"
  printf '  Settings    %s\n' "$ENV_FILE"
  printf '  Logs        journalctl -u alastor-server -f\n'
  [ -x /usr/local/bin/alastor ] && printf '  Control     alastor status | start | stop | restart   (or Settings → Server in the dashboard)\n'
  printf '\n'
  case "$mode" in
    local)
      printf '  Open the dashboard from your computer through an SSH tunnel, then browse to %s:\n' "$public_url"
      printf '    ssh -L %s:127.0.0.1:%s %s@%s\n\n' "$port" "$port" "${SUDO_USER:-root}" "$(primary_ip)"
      printf '  Other servers cannot reach this one yet. To enroll them, re-run this installer with\n'
      printf '  --access tailscale (after installing Tailscale) or --domain your.domain (HTTPS through Caddy).\n' ;;
    *) printf '  Next: in the dashboard, Settings → Enrollment → New token, then run the command it shows on each server.\n' ;;
  esac
  if [ "$mode" = public ]; then
    printf '\n\033[1;31m  ! The dashboard and the agent API are open to every network over plain HTTP: passwords and agent\n'
    printf '    credentials cross the network unencrypted. Only do this on a trusted network. On a VPS, re-run with\n'
    printf '    --access tailscale or --domain your.domain instead.\033[0m\n'
  elif [ "$mode" = keep ] && [ "$secure" = false ] && [ "$(reach_host "$listen")" != "$listen" ]; then
    printf '\n\033[33m  Plain HTTP on every interface. For a VPS on the internet, re-run with --access tailscale,\n'
    printf '  --access local or --domain your.domain.\033[0m\n'
  fi
  if [ "$legacy" -eq 1 ]; then
    printf '\n\033[33m  This server stays reachable from anywhere, as before. To limit it to your tailnet, re-run with --access tailscale.\033[0m\n'
  fi
  security_check
}

do_uninstall() {
  step "Removing Alastor server"
  if serve_managed; then
    tailscale serve --https=443 off >/dev/null 2>&1 || warn "Could not turn off tailscale serve on port 443; check: tailscale serve status"
  fi
  systemctl disable --now alastor-server alastor-control.path 2>/dev/null || true
  rm -rf "$UNIT" "$UNIT.d" /usr/local/bin/alastor-server "$CONTROL_UNIT.path" "$CONTROL_UNIT.service" "$DATA_DIR/control"
  # The `alastor` command stays while the agent still uses it.
  [ -f /etc/systemd/system/alastor-agent.service ] || rm -f /usr/local/bin/alastor
  rm -rf "$PREFIX" /var/cache/alastor
  systemctl daemon-reload
  if [ -f "$CADDY_SNIPPET" ]; then
    rm -f "$CADDY_SNIPPET"
    sed -i '/^import alastor.caddy$/d' /etc/caddy/Caddyfile 2>/dev/null || true
    systemctl reload caddy 2>/dev/null || true
  fi
  if [ "$1" -eq 1 ]; then
    rm -rf "$DATA_DIR" "$CONF_DIR"
    userdel "$SERVICE_USER" 2>/dev/null || true
    ok "Removed, including the database and settings."
  else
    ok "Removed. Data kept in $DATA_DIR and settings in $CONF_DIR (use --uninstall --purge to delete them)."
  fi
}

setup_caddy() {
  local domain="$1" port="$2"
  step "Setting up HTTPS for $domain with Caddy"
  if ! command -v caddy >/dev/null; then
    install_pkg caddy || die "Could not install Caddy from the distro repos. Install it (https://caddyserver.com/docs/install) and re-run."
  fi
  mkdir -p /etc/caddy
  cat > "$CADDY_SNIPPET" <<EOF
# Managed by the Alastor installer.
$domain {
	encode zstd gzip
	reverse_proxy 127.0.0.1:$port
}
EOF
  local cf=/etc/caddy/Caddyfile
  # The packaged Caddyfile only serves a placeholder page on :80; replace it rather than run beside it.
  if [ ! -s "$cf" ] || grep -q 'The Caddyfile is an easy way to configure' "$cf"; then
    [ -s "$cf" ] && cp "$cf" "$cf.orig"
    echo "import alastor.caddy" > "$cf"
  elif ! grep -qx 'import alastor.caddy' "$cf"; then
    printf '\nimport alastor.caddy\n' >> "$cf"
  fi
  caddy validate --config "$cf" --adapter caddyfile >/dev/null 2>&1 || die "Caddy rejected $cf. Check it with: caddy validate --config $cf"
  systemctl enable caddy >/dev/null 2>&1 || true
  systemctl reload caddy 2>/dev/null || systemctl restart caddy
  ok "Caddy serves https://$domain (the certificate is issued on first request; DNS must point here)."
}

# open_firewall PORT...: allow these TCP ports from everywhere (--domain and --access public only).
open_firewall() {
  local ports="$*" p
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    for p in $ports; do ufw allow "$p/tcp" >/dev/null; done
    ok "ufw: allowed $ports/tcp"
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    for p in $ports; do firewall-cmd --permanent --add-port="$p/tcp" >/dev/null; done
    firewall-cmd --reload >/dev/null
    ok "firewalld: allowed $ports/tcp"
  fi
}

# install_control API: the `alastor` command (served by the new server), and the root path unit that carries out the
# dashboard's start/stop requests for this machine. The server itself runs unprivileged and only drops a request file.
install_control() {
  if ! curl -fsS --max-time 10 -o "$TMP/alastor" "$1/install/alastor.sh" 2>/dev/null; then
    warn "This server version has no alastor command: start and stop it with systemctl."
    return 0
  fi
  install -m 755 "$TMP/alastor" /usr/local/bin/alastor
  install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 700 "$DATA_DIR/control"
  cat > "$CONTROL_UNIT.path" <<EOF
[Unit]
Description=Alastor start/stop requests from the dashboard

[Path]
PathExists=$DATA_DIR/control/request

[Install]
WantedBy=multi-user.target
EOF
  cat > "$CONTROL_UNIT.service" <<EOF
[Unit]
Description=Carry out an Alastor start/stop request from the dashboard

[Service]
Type=oneshot
# Accepts only: server stop|restart, agent start|stop|restart.
ExecStart=/usr/local/bin/alastor apply-request
EOF
  systemctl daemon-reload
  systemctl enable --now alastor-control.path >/dev/null 2>&1 \
    || warn "Could not enable alastor-control.path: start and stop from the dashboard won't work."
}

# allow_tailnet_port PORT: let tailnet peers through ufw to PORT, on the tailscale0 interface only.
allow_tailnet_port() {
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow in on tailscale0 to any port "$1" proto tcp >/dev/null
    ok "ufw: allowed $1/tcp on tailscale0 only"
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    warn "firewalld is active: if tailnet peers cannot reach port $1, allow it for the zone of tailscale0."
  fi
}

# install_local_agent URL API PASSWORD: enroll this machine with the server at URL. API is the address the server is
# bound to (loopback or the tailnet address), used for the login and the installer download.
install_local_agent() {
  local url="$1" api="$2" password="$3"
  step "Installing the agent on this machine"
  if [ "${url#https://}" != "$url" ] && ! wait_healthy "$url/healthz" 30; then
    warn "$url is not reachable yet (DNS or certificate). Enroll this machine later from Settings → Enrollment."
    return 0
  fi
  local hdrs body cookie secret
  # Secrets go through stdin, not argv, where any local user could read them in ps.
  hdrs="$(printf '{"username":"admin","password":"%s"}' "$password" | curl -fsS -D - -o /dev/null -X POST "$api/api/auth/login" \
    -H 'content-type: application/json' --data @-)" || { warn "Login failed; enroll this machine from the dashboard."; return 0; }
  cookie="$(printf '%s' "$hdrs" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(alastor_session=[^;]*\).*/\1/p' | head -n1)"
  body="$(printf 'Cookie: %s\n' "$cookie" | curl -fsS -X POST "$api/api/enrollment-tokens" -H 'content-type: application/json' \
    -H 'X-Alastor-Request: 1' -H @- -d "{\"note\":\"$(hostname) (server)\",\"ttlHours\":1}")" || { warn "Could not create an enrollment token."; return 0; }
  secret="$(printf '%s' "$body" | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p')"
  [ -n "$secret" ] || { warn "Could not read the enrollment token."; return 0; }
  local args=(--server "$url" --token "$secret")
  # Agents from before plain HTTP over loopback and the tailnet was accepted still need --insecure for it.
  [ "${url#http://}" != "$url" ] && args+=(--insecure)
  # Not fatal: the summary below holds the admin password, shown only once.
  curl -fsSL "$api/install/agent.sh" | bash -s -- "${args[@]}" \
    || warn "The agent was not set up; enroll this machine from Settings → Enrollment."
}

# repoint_local_agent URL RID: an agent on this machine keeps its URL when the server's address changes, and would
# report to an address nothing answers on any more. Moves it to URL, unless its old address still works. `set-server`
# only goes through when this server knows the agent, so one enrolled with another server is left alone.
repoint_local_agent() {
  local url="$1" old bin="$PREFIX/agent/alastor-agent-$2"
  [ -f "$AGENT_CONFIG" ] || return 0
  old="$(sed -n 's/.*"serverUrl": *"\([^"]*\)".*/\1/p' "$AGENT_CONFIG" | head -n1)"
  old="${old%/}"
  [ "$old" != "$url" ] || return 0
  curl -fsS -o /dev/null --max-time 5 "$old/healthz" 2>/dev/null && return 0
  # The installed agent may predate `set-server`; the one just unpacked for new hosts has it.
  [ -x "$bin" ] || bin=/usr/local/bin/alastor-agent
  if "$bin" set-server --server "$url" >/dev/null; then
    systemctl try-restart alastor-agent
    ok "The agent on this machine now reports to $url (was $old)."
  else
    warn "The agent on this machine reports to $old, which does not answer, and could not be moved to $url."
    warn "If this is the server it enrolled with, run: sudo alastor-agent set-server --server $url"
  fi
}

# ---- building from a checkout ------------------------------------------------------------------

# Prints the repository root when this script runs from a clone (not when piped from curl).
checkout_dir() {
  local script="${BASH_SOURCE[0]:-}" dir
  [ -f "$script" ] || return 0
  dir="$(cd "$(dirname "$script")/.." && pwd)"
  if [ -f "$dir/Alastor.slnx" ] && [ -d "$dir/src/Alastor.Server" ]; then echo "$dir"; fi
}

# build_from_source SRC RID WITH_AGENT: publish the server (and agent) into SRC/artifacts/install. The build runs as
# the owner of the checkout, so sudo leaves no root-owned bin/, obj/ or node_modules/ behind.
build_from_source() {
  local src="$1" rid="$2" with_agent="$3" out="$1/artifacts/install"
  BUILD_USER="$(stat -c %U "$src")"
  local home; home="$(getent passwd "$BUILD_USER" | cut -d: -f6)"
  BUILD_PATH="$PATH:$home/.dotnet:$home/.dotnet/tools:$home/.local/bin"
  local dotnet; dotnet="$(find_dotnet "$home")" \
    || die "Building from $src needs the .NET 10 SDK (https://dot.net/download), or install a release with --version latest."
  as_build_user sh -c 'command -v npm' >/dev/null \
    || die "Building the dashboard needs Node.js 22+ with npm, or install a release with --version latest."
  local aot=true
  if [ "$with_agent" -eq 1 ] && { ! command -v clang >/dev/null || [ ! -f /usr/include/zlib.h ]; }; then
    aot=false
    warn "clang or zlib1g-dev missing: building the agent without Native AOT (larger, uses more memory)."
  fi

  step "Building Alastor from $src ($rid)"
  local log="$TMP/build.log"
  rm -rf "$out"
  as_build_user "$dotnet" publish "$src/src/Alastor.Server" -c Release -r "$rid" -o "$out/server" >"$log" 2>&1 \
    || { tail -n 40 "$log" >&2; die "Building the server failed."; }
  ok "Server built"
  if [ "$with_agent" -eq 1 ]; then
    as_build_user "$dotnet" publish "$src/src/Alastor.Agent" -c Release -r "$rid" -p:AgentAot="$aot" -o "$out/agent-build" >"$log" 2>&1 \
      || { tail -n 40 "$log" >&2; die "Building the agent failed."; }
    as_build_user mkdir -p "$out/agent"
    as_build_user cp "$out/agent-build/alastor-agent" "$out/agent/alastor-agent-$rid"
    ok "Agent built ($([ "$aot" = true ] && echo "Native AOT" || echo JIT))"
  fi
}

# The .NET 10 SDK on PATH, in the build user's ~/.dotnet, or in the usual system locations.
find_dotnet() {
  local d
  for d in "$(as_build_user sh -c 'command -v dotnet' 2>/dev/null)" "${DOTNET_ROOT:+$DOTNET_ROOT/dotnet}" "$1/.dotnet/dotnet" \
      /usr/share/dotnet/dotnet /usr/lib/dotnet/dotnet /usr/local/share/dotnet/dotnet; do
    [ -n "$d" ] && [ -x "$d" ] && as_build_user "$d" --list-sdks 2>/dev/null | grep -q '^10\.' && { echo "$d"; return 0; }
  done
  return 1
}

as_build_user() {
  local env=(env PATH="$BUILD_PATH" DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1)
  if [ "$BUILD_USER" = root ]; then "${env[@]}" "$@"
  else runuser -u "$BUILD_USER" -- "${env[@]}" HOME="$(getent passwd "$BUILD_USER" | cut -d: -f6)" "$@"; fi
}

build_version() {
  local rev; rev="$(as_build_user git -C "$1" describe --tags --always --dirty 2>/dev/null || true)"
  echo "built from source${rev:+ at $rev}"
}

# ---- downloads ---------------------------------------------------------------------------------

# fetch_asset NAME DEST VERSION: download a release asset and check it against the release's SHA256SUMS.
fetch_asset() {
  local name="$1" dest="$2" version="$3"
  download "$name" "$dest" "$version" || return 1
  if [ ! -f "$TMP/SHA256SUMS" ]; then
    download SHA256SUMS "$TMP/SHA256SUMS" "$version" 2>/dev/null || : > "$TMP/SHA256SUMS"
  fi
  local want; want="$(awk -v n="$name" '$2 == n || $2 == "*"n { print $1 }' "$TMP/SHA256SUMS")"
  if [ -n "$want" ]; then
    [ "$(sha256sum "$dest" | cut -d' ' -f1)" = "$want" ] || die "Checksum mismatch for $name."
  else
    warn "No checksum published for $name; skipping verification."
  fi
}

download() {
  local name="$1" dest="$2" version="$3"
  if [ -n "${ALASTOR_DOWNLOAD_BASE:-}" ]; then
    curl -fsSL --retry 3 -o "$dest" "${ALASTOR_DOWNLOAD_BASE%/}/$version/$name"
  elif [ -n "${GITHUB_TOKEN:-}" ]; then
    # Private repositories: assets are only reachable through the API.
    local api="https://api.github.com/repos/$REPO/releases" release asset
    if [ "$version" = latest ]; then release="$api/latest"; else release="$api/tags/$version"; fi
    if [ ! -f "$TMP/release.json" ]; then
      curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -H 'Accept: application/vnd.github+json' "$release" -o "$TMP/release.json" \
        || die "Could not read release '$version' of $REPO. Check GITHUB_TOKEN and that a release exists."
    fi
    asset="$(asset_url "$name" < "$TMP/release.json")"
    [ -n "$asset" ] || return 1
    curl -fsSL --retry 3 -H "Authorization: Bearer $GITHUB_TOKEN" -H 'Accept: application/octet-stream' -o "$dest" "$asset"
  else
    local base="https://github.com/$REPO/releases"
    if [ "$version" = latest ]; then base="$base/latest/download"; else base="$base/download/$version"; fi
    curl -fsSL --retry 3 -o "$dest" "$base/$name" \
      || { [ "$name" = SHA256SUMS ] || warn "Download of $name failed. While the repository is private, set GITHUB_TOKEN (see --help)."; return 1; }
  fi
}

# Reads a GitHub release JSON on stdin and prints the API URL of the asset called $1. Each asset lists
# its "url" before its "name", so remember the last asset URL and print it when the name matches.
asset_url() {
  tr ',' '\n' | awk -v n="\"$1\"" '
    /"url": *"https:\/\/api\.github\.com\/repos\/.*\/releases\/assets\/[0-9]+"/ { u = $0; sub(/.*"url": *"/, "", u); sub(/".*/, "", u) }
    /"name":/ { v = $0; sub(/.*"name": */, "", v); sub(/ *}*$/, "", v); if (v == n && u != "") { print u; exit } }'
}

# ---- access ------------------------------------------------------------------------------------

# `tailscale status --json` on one line, read without jq: Self, with its DNSName, comes before the peers.
ts_status() { if command -v tailscale >/dev/null; then { tailscale status --json 2>/dev/null || true; } | tr -d '\n\r\t'; fi; }
tailscale_up() { [[ "$(ts_status)" =~ \"BackendState\":\ *\"Running\" ]]; }
# The tailnet's HTTPS certificate name for this machine, when the tailnet has HTTPS certificates turned on.
ts_cert_domain() { ts_status | sed -n 's/.*"CertDomains": *\[ *"\([^"]*\)".*/\1/p'; }
# This machine's MagicDNS name without the trailing dot; fails when MagicDNS is off.
ts_dns_name() {
  local status name; status="$(ts_status)"
  [[ "$status" =~ \"MagicDNSEnabled\":\ *true ]] || return 1
  name="$(printf '%s' "$status" | sed -n 's/.*"Self": *{[^}]*"DNSName": *"\([^"]*\)".*/\1/p')"
  [ -n "${name%.}" ] && echo "${name%.}"
}
ts_ipv4() { { tailscale ip -4 2>/dev/null || true; } | head -n1; }
# Port 443 of `tailscale serve` is unused, or already proxies to this server (an upgrade).
ts_serve_free() {
  serve_managed && return 0
  local status; status="$(tailscale serve status --json 2>/dev/null | tr -d ' \n\r\t')" || true
  case "$status" in
    *"\"Proxy\":\"http://127.0.0.1:$1\""*) return 0 ;;
    *':443"'*) return 1 ;;
  esac
}
serve_managed() { grep -qx "$SERVE_MARK" "$ENV_FILE" 2>/dev/null; }

# The address to reach a server bound to $1 from this machine.
reach_host() { case "$1" in 0.0.0.0|'*'|+|'[::]') echo 127.0.0.1 ;; *) echo "$1" ;; esac; }

access_summary() {
  local mode="$1" serve="$2" listen="$3"
  if [ "$mode" = domain ]; then echo "the internet, HTTPS through Caddy"
  elif [ "$serve" -eq 1 ]; then echo "your tailnet only, HTTPS through tailscale serve"
  elif [ "$listen" = 127.0.0.1 ]; then echo "this machine only ($listen)"
  elif [ "$(reach_host "$listen")" != "$listen" ]; then echo "every network ($listen)"
  else case "$listen" in 100.*) echo "your tailnet only ($listen)" ;; *) echo "$listen only" ;; esac
  fi
}

# Prints the server's own configuration checks. Servers from before `alastor-server security-check` existed
# would start up instead (and fail on the busy port): only output in the check's format is shown.
security_check() {
  local vars=() line out
  # The service's environment, read literally like systemd's EnvironmentFile rather than sourced.
  while IFS= read -r line; do case "$line" in [A-Za-z_]*=*) vars+=("$line") ;; esac; done < "$ENV_FILE"
  # From the service's working directory: the server watches its content root, and / would take forever.
  out="$(cd "$DATA_DIR" && timeout 30 runuser -u "$SERVICE_USER" -- env "${vars[@]}" DOTNET_BUNDLE_EXTRACT_BASE_DIR=/var/cache/alastor \
    "$PREFIX/alastor-server" security-check 2>&1)" || true
  printf '%s\n' "$out" | grep -Eq '^(pass|info|warn|fail) ' || return 0
  printf '\n  Security check (alastor-server security-check):\n'
  printf '%s\n' "$out" | sed 's/^/    /'
}

# ---- helpers -----------------------------------------------------------------------------------

detect_rid() {
  case "$(uname -m)" in
    x86_64|amd64) echo linux-x64 ;;
    aarch64|arm64) echo linux-arm64 ;;
    *) die "Unsupported CPU architecture $(uname -m). Alastor ships for x86_64 and arm64." ;;
  esac
}

primary_ip() {
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
  [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "${ip:-127.0.0.1}"
}

wait_healthy() {
  local url="$1" tries="${2:-60}"
  while [ "$tries" -gt 0 ]; do
    curl -fsS -o /dev/null --max-time 3 "$url" 2>/dev/null && return 0
    sleep 1; tries=$((tries - 1))
  done
  return 1
}

install_pkg() {
  if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/dev/null || { apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/dev/null; }
  elif command -v dnf >/dev/null; then dnf install -y -q "$@"
  elif command -v yum >/dev/null; then yum install -y -q "$@"
  else return 1
  fi
}

env_get() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | tail -n1; }
env_port() { env_get ASPNETCORE_URLS | sed -n 's#.*:\([0-9][0-9]*\).*#\1#p'; }
env_host() { env_get ASPNETCORE_URLS | sed -n 's#^[a-z]*://\(.*\):[0-9][0-9]*/*$#\1#p'; }
env_set() {
  if grep -q "^$1=" "$ENV_FILE"; then sed -i "s#^$1=.*#$1=$2#" "$ENV_FILE"; else echo "$1=$2" >> "$ENV_FILE"; fi
}

need_arg() { [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value."; echo "$2"; }
need_cmd() { command -v "$1" >/dev/null || die "$1 is required."; }
usage() {
  if [ -f "${BASH_SOURCE[0]:-}" ]; then sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d;s/^# \{0,1\}//'
  else echo "Options are listed at the top of the script; view it with: curl -fsSL <url>/install.sh | less"; fi
}
step() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok() { printf '\033[32m  ✔\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  !\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

main "$@"

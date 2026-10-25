#!/usr/bin/env bash
# Alastor server installer.
#
#   curl -fsSL https://raw.githubusercontent.com/nor0x/Alastor/main/install/install.sh | sudo bash
#   curl -fsSL …/install.sh | sudo bash -s -- --domain alastor.example.com --with-agent
#
# Installs (or upgrades, when run again) the alastor-server binary, the agent binaries it hands out to
# new hosts, a systemd unit, and optionally Caddy for automatic HTTPS. Data and settings survive upgrades.
#
# Options:
#   --domain NAME        serve https://NAME through Caddy (installed from the distro repos); needs ports 80/443 and DNS
#   --port N             port the server listens on (default 8080; loopback only when --domain is set)
#   --public-url URL     URL agents and browsers use (default: https://DOMAIN, else http://<primary IP>:PORT)
#   --with-agent         also install the agent on this machine and enroll it with the new server
#   --version vX.Y.Z     release to install (default: latest)
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

  local domain="" port="" public_url="" version="latest" binary="" agent_dir="" with_agent=0 uninstall=0 purge=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --domain) domain="$(need_arg "$@")"; shift ;;
      --port) port="$(need_arg "$@")"; shift ;;
      --public-url) public_url="$(need_arg "$@")"; shift ;;
      --version) version="$(need_arg "$@")"; shift ;;
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

  [ "$(uname -s)" = Linux ] || die "Alastor runs on Linux."
  [ "$(id -u)" -eq 0 ] || die "Run as root, e.g.: curl -fsSL … | sudo bash"
  command -v systemctl >/dev/null && [ -d /run/systemd/system ] || die "systemd is required."

  if [ "$uninstall" -eq 1 ]; then do_uninstall "$purge"; return; fi

  local rid; rid="$(detect_rid)"
  need_cmd curl
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

  # Settings from a previous install are kept unless overridden on the command line.
  local upgrade=0
  if [ -f "$ENV_FILE" ]; then
    upgrade=1
    [ -n "$port" ] || port="$(env_port)"
    [ -n "$public_url" ] || public_url="$(env_get ALASTOR_PUBLICURL)"
  fi
  port="${port:-8080}"
  case "$port" in ''|*[!0-9]*) die "--port must be a number." ;; esac
  if [ -z "$public_url" ]; then
    if [ -n "$domain" ]; then public_url="https://$domain"; else public_url="http://$(primary_ip):$port"; fi
  fi
  public_url="${public_url%/}"

  [ -n "$binary" ] && version="local build"
  step "Downloading Alastor ($version, $rid)"
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

  local listen="0.0.0.0"; [ -n "$domain" ] && listen="127.0.0.1"
  local secure=true; case "$public_url" in http://*) secure=false ;; esac
  local password=""
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
# Read on first start only, then removed by the installer.
ALASTOR_ADMINPASSWORD=$password
EOF
  else
    env_set ALASTOR_PUBLICURL "$public_url"
    env_set ALASTOR_SECURECOOKIES "$secure"
    env_set ASPNETCORE_URLS "http://$listen:$port"
  fi
  chown root:"$SERVICE_USER" "$ENV_FILE"; chmod 640 "$ENV_FILE"

  cat > "$UNIT" <<EOF
[Unit]
Description=Alastor server
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
User=$SERVICE_USER
Group=$SERVICE_USER
EnvironmentFile=$ENV_FILE
Environment=DOTNET_BUNDLE_EXTRACT_BASE_DIR=/var/cache/alastor
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
  wait_healthy "http://127.0.0.1:$port/healthz" || die "The server did not start. See: journalctl -u alastor-server -n 50"
  # The admin now exists in the database; the password must not stay on disk.
  [ -n "$password" ] && sed -i '/^# Read on first start only/d;/^ALASTOR_ADMINPASSWORD=/d' "$ENV_FILE"

  if [ -n "$domain" ]; then setup_caddy "$domain" "$port"; fi
  open_firewall "$domain" "$port"

  if [ "$with_agent" -eq 1 ]; then
    if [ -n "$password" ]; then
      install_local_agent "$public_url" "$password"
    else
      warn "--with-agent on an upgrade needs a token: create one under Settings → Enrollment and run the command it shows."
    fi
  fi

  printf '\n\033[1;32m✔ Alastor server %s\033[0m (%s)\n\n' "$([ "$upgrade" -eq 1 ] && echo upgraded || echo installed)" "$version"
  printf '  Dashboard   %s\n' "$public_url"
  if [ -n "$password" ]; then
    printf '  Username    admin\n'
    printf '  Password    \033[1m%s\033[0m   (shown once; change it under Settings)\n' "$password"
  fi
  printf '  Settings    %s\n' "$ENV_FILE"
  printf '  Logs        journalctl -u alastor-server -f\n\n'
  printf '  Next: in the dashboard, Settings → Enrollment → New token, then run the command it shows on each server.\n'
  if [ "$secure" = false ]; then
    printf '\n\033[33m  Plain HTTP: fine on a trusted network or for a try-out. For a VPS on the internet, re-run with\n'
    printf '  --domain your.domain to get HTTPS.\033[0m\n'
  fi
}

do_uninstall() {
  step "Removing Alastor server"
  systemctl disable --now alastor-server 2>/dev/null || true
  rm -rf "$UNIT" "$UNIT.d" /usr/local/bin/alastor-server
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

open_firewall() {
  local domain="$1" port="$2" ports
  if [ -n "$domain" ]; then ports="80 443"; else ports="$port"; fi
  local p
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    for p in $ports; do ufw allow "$p/tcp" >/dev/null; done
    ok "ufw: allowed $ports/tcp"
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    for p in $ports; do firewall-cmd --permanent --add-port="$p/tcp" >/dev/null; done
    firewall-cmd --reload >/dev/null
    ok "firewalld: allowed $ports/tcp"
  fi
}

install_local_agent() {
  local url="$1" password="$2"
  step "Installing the agent on this machine"
  if [ "${url#https://}" != "$url" ] && ! wait_healthy "$url/healthz" 30; then
    warn "$url is not reachable yet (DNS or certificate). Enroll this machine later from Settings → Enrollment."
    return 0
  fi
  local hdrs body cookie secret
  hdrs="$(curl -fsS -D - -o /dev/null -X POST "$url/api/auth/login" -H 'content-type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$password\"}")" || { warn "Login failed; enroll this machine from the dashboard."; return 0; }
  cookie="$(printf '%s' "$hdrs" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(alastor_session=[^;]*\).*/\1/p' | head -n1)"
  body="$(curl -fsS -X POST "$url/api/enrollment-tokens" -H 'content-type: application/json' -H 'X-Alastor-Request: 1' \
    -H "Cookie: $cookie" -d "{\"note\":\"$(hostname) (server)\",\"ttlHours\":1}")" || { warn "Could not create an enrollment token."; return 0; }
  secret="$(printf '%s' "$body" | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p')"
  [ -n "$secret" ] || { warn "Could not read the enrollment token."; return 0; }
  local args=(--server "$url" --token "$secret")
  [ "${url#http://}" != "$url" ] && args+=(--insecure)
  curl -fsSL "http://127.0.0.1:$(env_port)/install/agent.sh" | bash -s -- "${args[@]}"
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

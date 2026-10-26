#!/usr/bin/env bash
# Alastor agent installer. The dashboard shows the exact command for each new host
# (Settings → Enrollment → New token), served by your own Alastor server:
#
#   curl -fsSL https://alastor.example.com/install/agent.sh | sudo bash -s -- --server https://alastor.example.com --token sve_…
#
# Run it again without --token to upgrade the agent in place; the enrollment is kept.
#
# Options:
#   --server URL       your Alastor server
#   --token TOKEN      single-use enrollment token (needed for the first install, or with --force)
#   --insecure         allow a plain-HTTP server URL (trusted networks and local testing only). Not needed for
#                      loopback or Tailscale addresses (100.64.0.0/10, fd7a:115c:a1e0::/48, *.ts.net): WireGuard encrypts those
#   --pin SHA256       accept only this TLS certificate (hex SHA-256 of the DER certificate), e.g. for self-signed
#   --force            enroll again as a new host even if this machine is already enrolled
#   --version vX.Y.Z   agent release to download from GitHub when the server has no agent binaries (default: latest)
#   --binary PATH      install this alastor-agent binary instead of downloading one
#   --uninstall        stop the agent, remove what it manages (its fail2ban jail file, applied fixes, config, state)
#                      and the agent itself; tools it installed stay installed
#
# Environment:
#   GITHUB_TOKEN, ALASTOR_REPO, ALASTOR_DOWNLOAD_BASE   as for install.sh (only used for the GitHub fallback)
set -euo pipefail

# Everything runs from main(), so a download cut off midway through `curl | bash` executes nothing.
main() {
  REPO="${ALASTOR_REPO:-nor0x/Alastor}"
  BIN=/usr/local/bin/alastor-agent
  UNIT=/etc/systemd/system/alastor-agent.service
  CONFIG=/etc/alastor-agent/agent.json

  local server="" token="" pin="" version="latest" binary="" insecure=0 force=0 uninstall=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --server) server="$(need_arg "$@")"; shift ;;
      --token) token="$(need_arg "$@")"; shift ;;
      --pin) pin="$(need_arg "$@")"; shift ;;
      --version) version="$(need_arg "$@")"; shift ;;
      --binary) binary="$(need_arg "$@")"; shift ;;
      --insecure) insecure=1 ;;
      --force) force=1 ;;
      --uninstall) uninstall=1 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1 (see --help)" ;;
    esac
    shift
  done
  server="${server%/}"

  [ "$(uname -s)" = Linux ] || die "The Alastor agent runs on Linux."
  [ "$(id -u)" -eq 0 ] || die "Run as root, e.g.: curl -fsSL … | sudo bash -s -- …"
  command -v systemctl >/dev/null && [ -d /run/systemd/system ] || die "systemd is required."

  if [ "$uninstall" -eq 1 ]; then do_uninstall; return; fi

  local enrolled=0; [ -f "$CONFIG" ] && enrolled=1
  local enroll=0
  if [ "$enrolled" -eq 0 ] || [ "$force" -eq 1 ]; then
    [ -n "$server" ] && [ -n "$token" ] || die "--server and --token are required to enroll. Create a token in the dashboard: Settings → Enrollment."
    enroll=1
  fi
  if [ -n "$server" ]; then
    case "$server" in
      https://*) ;;
      http://*) [ "$insecure" -eq 1 ] || private_transport "$server" \
        || die "Refusing plain HTTP ($server). Use https://, or pass --insecure on a trusted network." ;;
      *) die "--server must start with https:// (or http:// with --insecure)." ;;
    esac
  fi

  local rid; rid="$(detect_rid)"
  need_cmd curl
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  CURL=(curl -fsSL --retry 3)
  if [ -n "$pin" ] && [ "${server#https://}" != "$server" ]; then
    check_pin "$server" "$pin"
    # The certificate was just checked against the pin, which is the point of a pin with a self-signed certificate.
    CURL+=(--insecure)
  fi

  step "Downloading the agent ($rid)"
  local got=0
  if [ -n "$binary" ]; then
    [ -f "$binary" ] || die "--binary: $binary not found."
    cp "$binary" "$TMP/alastor-agent"; got=1
  elif [ -n "$server" ] && "${CURL[@]}" -o "$TMP/alastor-agent" "$server/install/agent/alastor-agent-$rid" 2>/dev/null; then
    verify "$TMP/alastor-agent" "alastor-agent-$rid" "$("${CURL[@]}" "$server/install/agent/SHA256SUMS" 2>/dev/null || true)"
    ok "from $server"; got=1
  fi
  if [ "$got" -eq 0 ]; then
    download "alastor-agent-$rid" "$TMP/alastor-agent" "$version" || die "Could not download the agent for $rid."
    verify "$TMP/alastor-agent" "alastor-agent-$rid" "$(download SHA256SUMS /dev/stdout "$version" 2>/dev/null || true)"
    ok "from GitHub release $version"
  fi
  chmod 755 "$TMP/alastor-agent"
  local ver; ver="$("$TMP/alastor-agent" version 2>/dev/null)" || die "The downloaded agent does not run on this machine ($(uname -m), $(ldd --version 2>&1 | head -n1))."

  step "Installing alastor-agent $ver"
  systemctl stop alastor-agent 2>/dev/null || true
  install -m 755 "$TMP/alastor-agent" "$BIN"
  cat > "$UNIT" <<EOF
[Unit]
Description=Alastor agent
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
# Root is required: the agent installs and configures fail2ban, firewall and update tooling.
Type=notify
ExecStart=$BIN run
Restart=always
RestartSec=10
# 2 = usage error, 3 = not enrolled or refusing an insecure URL: restarting will not help.
RestartPreventExitStatus=2 3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload

  if [ "$enroll" -eq 1 ]; then
    step "Enrolling with $server"
    local args=(enroll --server "$server" --token "$token")
    [ "$insecure" -eq 1 ] && args+=(--insecure)
    [ -n "$pin" ] && args+=(--pin "$pin")
    [ "$force" -eq 1 ] && args+=(--force)
    "$BIN" "${args[@]}" || die "Enrollment failed. Tokens work once and expire; create a new one if needed."
  fi

  # The `alastor` command (status, start, stop), from the same server; older servers don't have it.
  local cli_from="$server"
  [ -n "$cli_from" ] || cli_from="$(sed -n 's/.*"serverUrl": *"\([^"]*\)".*/\1/p' "$CONFIG" 2>/dev/null | head -n1)"
  if [ -n "$cli_from" ] && "${CURL[@]}" -o "$TMP/alastor" "$cli_from/install/alastor.sh" 2>/dev/null; then
    install -m 755 "$TMP/alastor" /usr/local/bin/alastor
  fi

  systemctl enable alastor-agent >/dev/null 2>&1
  systemctl restart alastor-agent
  sleep 2
  systemctl is-active --quiet alastor-agent || die "The agent did not start. See: journalctl -u alastor-agent -n 50"

  printf '\n\033[1;32m✔ Alastor agent %s %s\033[0m\n\n' "$ver" "$([ "$enroll" -eq 1 ] && echo "installed and enrolled" || echo "upgraded")"
  printf '  This host appears in the dashboard within a minute.\n'
  printf '  Status      alastor-agent status\n'
  [ -x /usr/local/bin/alastor ] && printf '  Control     alastor status | start | stop | restart\n'
  printf '  Logs        journalctl -u alastor-agent -f\n'
  printf '  Remove      curl -fsSL %s/install/agent.sh | sudo bash -s -- --uninstall\n' "${server:-<server>}"
}

do_uninstall() {
  step "Removing the Alastor agent"
  systemctl disable --now alastor-agent 2>/dev/null || true
  # Removes only what the agent manages; the tools themselves stay installed.
  [ -x "$BIN" ] && "$BIN" uninstall || true
  rm -f "$UNIT" "$BIN"
  # The `alastor` command stays while the server on this machine still uses it.
  [ -f /etc/systemd/system/alastor-server.service ] || rm -f /usr/local/bin/alastor
  rm -rf /etc/alastor-agent /var/lib/alastor-agent
  systemctl daemon-reload
  ok "Removed. Delete the host in the dashboard to drop its history."
}

check_pin() {
  local server="$1" want hostport host got
  need_cmd openssl
  want="$(printf '%s' "$2" | tr -d ':' | tr '[:lower:]' '[:upper:]')"
  hostport="${server#https://}"; hostport="${hostport%%/*}"
  host="${hostport%:*}"; [ "$host" = "$hostport" ] && hostport="$hostport:443"
  got="$(openssl s_client -connect "$hostport" -servername "$host" </dev/null 2>/dev/null \
    | openssl x509 -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')"
  [ "$got" = "$want" ] || die "The certificate of $hostport does not match --pin (got $got)."
}

# private_transport URL: the host is loopback or on the tailnet, so plain HTTP never crosses a network unencrypted.
# Kept in sync with IsPrivateTransport in the agent, which checks again.
private_transport() {
  local host="${1#*://}"; host="${host%%/*}"; host="${host##*@}"
  case "$host" in
    \[*) host="${host#\[}"; host="${host%%\]*}" ;;
    *) host="${host%:*}" ;;
  esac
  host="$(printf '%s' "${host%.}" | tr '[:upper:]' '[:lower:]')"
  case "$host" in
    localhost|::1|*.ts.net|fd7a:115c:a1e0:*) return 0 ;;
    *[!0-9.]*|'') return 1 ;;
    127.*) return 0 ;;
    100.*) local b="${host#100.}"; b="${b%%.*}"; [ -n "$b" ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ] ;;
    *) return 1 ;;
  esac
}

# verify FILE NAME SUMS: check FILE against NAME's line in a SHA256SUMS text, when one is published.
verify() {
  local want; want="$(printf '%s\n' "$3" | awk -v n="$2" '$2 == n || $2 == "*"n { print $1 }')"
  if [ -z "$want" ]; then warn "No checksum published for $2; skipping verification."; return 0; fi
  [ "$(sha256sum "$1" | cut -d' ' -f1)" = "$want" ] || die "Checksum mismatch for $2."
}

# ---- GitHub release fallback (kept in sync with install.sh) ------------------------------------

download() {
  local name="$1" dest="$2" version="$3"
  if [ -n "${ALASTOR_DOWNLOAD_BASE:-}" ]; then
    curl -fsSL --retry 3 -o "$dest" "${ALASTOR_DOWNLOAD_BASE%/}/$version/$name"
  elif [ -n "${GITHUB_TOKEN:-}" ]; then
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
      || { [ "$name" = SHA256SUMS ] || warn "Download of $name failed. While the repository is private, set GITHUB_TOKEN."; return 1; }
  fi
}

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
    *) die "Unsupported CPU architecture $(uname -m). The agent ships for x86_64 and arm64." ;;
  esac
}

need_arg() { [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value."; echo "$2"; }
need_cmd() { command -v "$1" >/dev/null || die "$1 is required."; }
usage() {
  if [ -f "${BASH_SOURCE[0]:-}" ]; then sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d;s/^# \{0,1\}//'
  else echo "Options are listed at the top of the script; view it with: curl -fsSL <server>/install/agent.sh | less"; fi
}
step() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok() { printf '\033[32m  ✔\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  !\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

main "$@"

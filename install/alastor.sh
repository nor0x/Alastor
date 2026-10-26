#!/usr/bin/env bash
# alastor: start, stop and check Alastor on this machine (the server, the agent, or both).
#
#   alastor status                                 what runs here, whether it starts at boot, and where
#   alastor start|stop|restart [server|agent]      default: everything installed on this machine
#   alastor enable|disable [server|agent]          start now and at boot / stop now and stay off at boot
#   alastor logs [server|agent]                    follow the journal
#
# install.sh and agent-install.sh put it at /usr/local/bin/alastor (the server serves it at /install/alastor.sh).
# `stop` leaves a service enabled, so it starts again at the next boot; `disable` keeps it off.
set -euo pipefail

SERVER_ENV=/etc/alastor/server.env
AGENT_CONFIG=/etc/alastor-agent/agent.json
# Written by the server (Settings → Server → This machine), read by alastor-control.service as root.
CONTROL_REQUEST=/var/lib/alastor/control/request

main() {
  local cmd="${1:-status}" which="${2:-}"
  case "$cmd" in
    status) status ;;
    start|stop|restart|enable|disable)
      [ "$(id -u)" -eq 0 ] || exec_root "$@"
      local units; units="$(units "$which")"
      # shellcheck disable=SC2086 # one word per unit
      case "$cmd" in
        enable|disable) systemctl "$cmd" --now $units ;;
        *) systemctl "$cmd" $units ;;
      esac
      status ;;
    logs)
      local list args=() u; list="$(units "$which")"
      for u in $list; do args+=(-u "$u"); done
      exec journalctl "${args[@]}" -f ;;
    apply-request) apply_request ;;
    -h|--help|help) usage ;;
    *) die "Unknown command '$cmd' (see alastor --help)." ;;
  esac
}

# units [server|agent]: the systemd units to act on; without an argument, every Alastor unit installed here.
units() {
  case "$1" in
    server) installed alastor-server || die "The Alastor server is not installed on this machine."; echo alastor-server ;;
    agent) installed alastor-agent || die "The Alastor agent is not installed on this machine."; echo alastor-agent ;;
    '')
      local found=""
      installed alastor-server && found="alastor-server"
      installed alastor-agent && found="${found:+$found }alastor-agent"
      [ -n "$found" ] || die "Neither the Alastor server nor the agent is installed on this machine."
      echo "$found" ;;
    *) die "Use server or agent, or nothing for both." ;;
  esac
}
installed() { [ -f "/etc/systemd/system/$1.service" ]; }

status() {
  local u state boot where
  for u in alastor-server alastor-agent; do
    installed "$u" || continue
    state="$(systemctl is-active "$u" 2>/dev/null || true)"
    boot="$(systemctl is-enabled "$u" 2>/dev/null || true)"
    where=""
    if [ "$u" = alastor-server ]; then
      [ -r "$SERVER_ENV" ] && where="$(sed -n 's/^ALASTOR_PUBLICURL=//p' "$SERVER_ENV" | tail -n1)"
    else
      [ -r "$AGENT_CONFIG" ] && where="$(sed -n 's/.*"serverUrl": *"\([^"]*\)".*/reports to \1/p' "$AGENT_CONFIG" | head -n1)"
    fi
    printf '  %-7s %s%-9s\033[0m %-22s %s\n' "${u#alastor-}" "$(color "$state")" "${state:-unknown}" \
      "$([ "$boot" = enabled ] && echo "starts at boot" || echo "off at boot")" "$where"
  done
  installed alastor-server || installed alastor-agent || echo "  Alastor is not installed on this machine."
}
color() { case "$1" in active) printf '\033[32m' ;; failed) printf '\033[31m' ;; *) printf '\033[33m' ;; esac; }

# Runs as root from alastor-control.service when the dashboard asks to start, stop or restart something here. The
# request file belongs to the server's user, so it is only matched against a fixed list, never echoed or executed.
apply_request() {
  local f="$CONTROL_REQUEST" req=""
  [ -e "$f" ] || [ -L "$f" ] || return 0
  if [ -f "$f" ] && [ ! -L "$f" ]; then req="$(head -c 32 "$f" | tr -d '\r\n')"; fi
  rm -f "$f"
  case "$req" in
    "server stop"|"server restart"|"agent start"|"agent stop"|"agent restart") ;;
    *) echo "Ignored a request that is not on the list." >&2; return 0 ;;
  esac
  local target="alastor-${req%% *}" action="${req#* }"
  installed "$target" || { echo "Ignored '$req': $target is not installed." >&2; return 0; }
  echo "Dashboard request: $action $target"
  systemctl "$action" "$target" || echo "systemctl $action $target failed." >&2
}

exec_root() {
  command -v sudo >/dev/null || die "Run as root."
  exec sudo "$0" "$@"
}
usage() {
  if [ -f "${BASH_SOURCE[0]:-}" ]; then sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d;s/^# \{0,1\}//'; fi
}
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

main "$@"

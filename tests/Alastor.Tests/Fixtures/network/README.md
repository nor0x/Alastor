# Network fixtures

Captured on this repo's Ubuntu 26.04 dev container, exactly as the commands print them (MAC address and container
hostname replaced):

| File | Command |
|---|---|
| `sshd-T.default.txt` | `sshd -T` on a stock openssh-server 10.2p1 (passwords allowed, root by key only) |
| `proc-net-tcp.txt`, `proc-net-tcp6.txt` | `cat /proc/net/tcp{,6}` with sshd listening on `0.0.0.0:22` and `[::]:22` |
| `ip-addr.container.json` | `ip -j addr show` (loopback and one private address) |
| `ts-status.not-running.txt` | `tailscale status --json` (stderr, exit 1) with tailscaled stopped, Tailscale 1.104.2 |
| `ts-needs-login.json` | `tailscale status --json` with tailscaled running but logged out |
| `ts-running.json` | `tailscale status --json` joined to a tailnet with one online peer |
| `ts-prefs.json`, `ts-prefs.ssh.json` | `tailscale debug prefs` with Tailscale SSH off and on |
| `ss-tulpn.txt` | `ss -tulpnH` (iproute2 6.1.0) with test listeners on 443, 6379, 51820/udp, loopback 5432 and 53/udp; two unrelated processes renamed to `node` and `containerd`, and the test process's pid replaced |
| `proc-net-udp.txt` | `cat /proc/net/udp` with those UDP sockets bound |

For the running captures, tailscaled ran in userspace mode (`--tun=userspace-networking`) against a throwaway local
[headscale](https://github.com/juanfont/headscale) control server, so `CurrentTailnet.Name` is the control server's
address rather than a tailnet name, and there is no `KeyExpiry` (headscale's default). The node keys are from that
throwaway tailnet. Against tailscale.com the same fields hold the tailnet name and the key's expiry date.

The container has no CAP_NET_ADMIN, so these were written by hand from the documented formats (ufw(8),
libnftables-json(5), `ip -j`), using the structure the tools emit:

| File | What it shows |
|---|---|
| `ip-addr.vps.json` | a VPS with a public IPv4 and IPv6 address on eth0 and a `tailscale0` interface |
| `ufw-verbose.open.txt` | `ufw status verbose`: OpenSSH rate-limited from anywhere |
| `ufw-verbose.tailnet.txt` | everything allowed on `tailscale0`, only 443 from anywhere |
| `ufw-verbose.admin-ip.txt` | SSH allowed from one admin address only |
| `nft-ruleset.tailnet-only.json` | inet filter with policy drop: tailscale0 accepted, 22 only from 198.51.100.0/24 |
| `nft-ruleset.ufw-jump.json` | ufw's chains as iptables-nft writes them: INPUT jumps to `ufw-user-input`, which accepts 22 |

Public addresses use the documentation ranges (203.0.113.0/24, 198.51.100.0/24, 2001:db8::/32).
| `ss-tulpn.v6.txt` | `ss -tulpnH` address forms the container can't produce (it has no IPv6): `[::]:22`, `*:80`, a link-local `%eth0` scope, a v4-mapped address, a socket without a process column, and two processes on one socket |
| `cgroup.v2.txt`, `cgroup.v1.txt`, `cgroup.session.txt` | `/proc/<pid>/cgroup` for a service on the unified hierarchy, on a hybrid v1 host, and for a login session |
| `systemd-analyze-security.json` | `systemd-analyze security --json=short` (systemd(1) 250+; this container doesn't boot systemd): scores as strings and as a number, since versions differ |

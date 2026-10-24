# Baseline fixtures

Captured from a real Ubuntu 26.04 container (OpenSSH 10.2p1), exactly as the commands print them:

| File | Command |
|---|---|
| `sshd-T.ubuntu-default.txt` | `sshd -T` on a stock openssh-server install |
| `sysctl.container.txt` | `sysctl -e <the baseline keys>` |
| `apt-config-periodic.txt` | `apt-config dump APT::Periodic` (with `APT::Periodic::Enable "0"` set) |
| `timedatectl-show.txt` | `timedatectl show` |
| `getent-passwd.txt` | `getent passwd` |
| `passwd-S-a.txt` | `passwd -S -a` |
| `ufw-status.no-permission.txt` | `ufw status` without CAP_NET_ADMIN |
| `nft-ruleset.no-permission.txt` | `nft -j list ruleset` without CAP_NET_ADMIN |

The container has no CAP_NET_ADMIN, so the files below were written by hand from the documented formats
(ufw(8), libnftables-json(5), iptables(8) `-S`), using the same structure the tools emit:

`ufw-status.active.txt`, `ufw-status.inactive.txt`, `nft-ruleset.drop-policy.json`, `nft-ruleset.trailing-drop.json`,
`nft-ruleset.debian-stock.json` (Debian's stock `/etc/nftables.conf`: all policies accept), `iptables-S-INPUT.drop.txt`,
`iptables-S-INPUT.accept.txt`.

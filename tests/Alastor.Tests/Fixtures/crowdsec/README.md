# CrowdSec fixtures

Captured on this repo's Ubuntu 26.04 dev container with the distro packages `crowdsec` 1.4.6-10.1 and
`crowdsec-firewall-bouncer` 0.0.25, exactly as `cscli` prints them. The only change is the replayed log path, shortened
to `/var/log/auth.log`.

| File | Command |
|---|---|
| `version.txt` | `cscli version` |
| `decisions-list.json` | `cscli decisions list -o json` after two `cscli decisions add` calls (one IP, one range) and a replayed SSH brute force |
| `decisions-empty.json` | `cscli decisions list -o json --ip 10.9.9.9`: cscli prints `null`, not `[]`, when nothing matches |
| `alerts-list.json` | `cscli alerts list -o json` with the same three alerts |
| `alerts-empty.json` | `cscli alerts list -o json --since 1s` |
| `decisions-delete.txt`, `decisions-delete-none.txt` | stderr of `cscli decisions delete --ip …` for a banned and an unbanned address |

The `crowdsecurity/ssh-bf` alert came from replaying eight `Failed password` lines from 198.51.100.23 through
`crowdsec -dsn file://… -type syslog -no-api`, which sends the alert to the running Local API like the live daemon does.

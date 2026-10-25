# Login fixtures

| File | Origin |
|---|---|
| `sshd-E.log` | **Captured** 2026-10-25 from OpenSSH 9.6p1 (Ubuntu 24.04) run with `-E`: one key login and one password login over 127.0.0.1. These are the exact `Accepted …` messages sshd logs. |
| `journal-sshd.json` | **Documented format** (`journalctl -o json`, systemd.journal-fields(7)): the captured messages wrapped in journal entries, addresses changed to documentation ranges and users to root/alice/deploy; one `sshd-session` identifier (OpenSSH 9.8+ logs from that binary), one IPv6 keyboard-interactive login, and one `MESSAGE` as a byte array, which journald uses for non-UTF-8 text. Cursors are illustrative. |
| `auth.log` | **Documented format**: Debian/Ubuntu rsyslog with RFC 3339 timestamps (the Ubuntu 24.04 default), the same messages plus unrelated pam and sudo lines. |
| `secure` | **Documented format**: RHEL's `/var/log/secure` with traditional syslog timestamps. |

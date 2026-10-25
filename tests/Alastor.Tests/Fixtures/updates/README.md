# Update fixtures

| File | Origin |
|---|---|
| `apt-get-s-dist-upgrade.ubuntu.txt` | **Captured** 2026-10-24 on Ubuntu 26.04 (`apt-get -s -o Debug::NoLocking=1 dist-upgrade` as a regular user, hence the simulation note). `gpgv` comes from both resolute-updates and resolute-security. |
| `uu-dry-run.txt` | **Captured** 2026-10-24 on Ubuntu 26.04: `unattended-upgrade --dry-run -v`. The real run prints the same "Packages that will be upgraded" line. |
| `apt-get-s-dist-upgrade.debian12.txt` | **Documented format** (apt-get(8) simulation lines, Debian's `Debian-Security:` origin label), versions illustrative. |
| `dnf-check-update*.txt` | **Documented format** (dnf(8) `check-update`: name.arch, version, repo; "Obsoleting Packages" section), versions illustrative. |
| `apk-list-upgradable.txt` | **Documented format** (apk-list(8) `--upgradable`), versions illustrative. |
| `needrestart-b.clean.txt` | **Captured** 2026-10-25 on Ubuntu 24.04 (needrestart 3.6-7ubuntu4.5): `needrestart -b -r l` stdout in a container with nothing to restart and an unknown kernel status (KSTA 0). |
| `needrestart-b.pending.txt` | **Documented format** (needrestart(1) batch mode, `NEEDRESTART-*` lines): a newer kernel installed (KSTA 3), three services on deleted libraries, a container and sessions. |
| `needs-restarting-s.txt` | **Documented format** (dnf-utils needs-restarting(1) `-s`: one systemd unit per line). |

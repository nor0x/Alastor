# Software inventory fixtures

| File | Origin |
|---|---|
| `dpkg-query.ubuntu2404.txt` | **Captured** 2026-10-26 on Ubuntu 24.04.1 (WSL): `dpkg-query -W -f=` with `SoftwareParsers.DpkgFormat`. |
| `apt-mark-showmanual.ubuntu2404.txt` | **Captured** 2026-10-26 on the same host: `apt-mark showmanual`. |
| `apt-get-s-upgrade.ubuntu2404.txt` | **Captured** 2026-10-26: `apt-get -s -o Debug::NoLocking=1 install --only-upgrade apparmor` as a regular user (hence the simulation note); pulls `libapparmor1` along. |
| `apt-get-s-remove.ubuntu2404.txt` | **Captured** 2026-10-26: `apt-get -s -o Debug::NoLocking=1 remove curl`, which also removes the `ubuntu-wsl` metapackage. |
| `apt-get-s-remove-broken.ubuntu2404.txt` | **Captured** 2026-10-26: `apt-get -s ... remove libssl3t64`, which apt refuses (exit 100) because essential packages pre-depend on it. stdout and stderr interleaved. |
| `rpm-qa.rocky9.txt` | **Documented format** (rpm(8) `--queryformat` with `SoftwareParsers.RpmFormat`, including a `gpg-pubkey` pseudo-package), versions illustrative. |
| `dnf-repoquery-userinstalled.dnf4.txt` | **Documented format**: dnf 4 prints the `\n` in `--qf %{name}\n` literally. |
| `dnf-assumeno-remove.dnf4.txt` | **Documented format** (dnf 4 transaction table before "Operation aborted."), including a package name long enough to wrap onto its own line. |
| `dnf-assumeno-upgrade.dnf5.txt` | **Documented format** (dnf 5 transaction table with an indented `replacing` line), versions illustrative. |
| `apk-list-installed.txt`, `apk-world.txt` | **Documented format** (apk-list(8) `--installed`, `/etc/apk/world` with a version constraint and an `so:` dependency). |
| `apk-del-simulate.txt`, `apk-upgrade-simulate.txt` | **Documented format** (apk `--simulate` progress lines). |
| `osv-querybatch.json` | **Captured** 2026-10-26 from `POST https://api.osv.dev/v1/querybatch`: openssl and curl on `Ubuntu:24.04:LTS`, openssl on `Debian:12`, and an unknown package (empty result). |
| `osv-vuln.ubuntu-cve.json`, `osv-vuln.debian-cve.json` | **Captured** 2026-10-26 from `GET https://api.osv.dev/v1/vulns/{id}` for UBUNTU-CVE-2025-15467 and DEBIAN-CVE-2025-15467. |

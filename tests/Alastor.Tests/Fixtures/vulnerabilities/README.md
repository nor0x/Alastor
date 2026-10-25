# Vulnerability scan fixtures

All captured 2026-10-24 with the scanners' official release binaries (Trivy 0.76.1, Grype 0.121.0), each running offline
against a database fetched the way the server mirrors it (Trivy's OCI layer from `ghcr.io/aquasecurity/trivy-db:2`,
Grype's v6 archive via `grype db import`). Local paths were replaced with `/srv/...` and `/var/lib/alastor-agent/...`.

| File | Origin |
|---|---|
| `trivy-alpine.json` | **Captured**: `trivy rootfs --scanners vuln --format json` on an Alpine 3.17.0 minirootfs with two old npm packages installed under `/srv/app/node_modules` (lodash 4.17.15, minimist 1.2.5). Every finding has a fix; includes `lang-pkgs` results. The `Packages` inventory was removed (the agent passes `--list-all-pkgs=false`). |
| `trivy-ubuntu-excerpt.json` | **Captured**: `trivy rootfs --pkg-types os /` on this Ubuntu 26.04 container, then **trimmed** to 175 of 3741 findings (the first 150 non-kernel-header findings, 25 `linux-libc-dev` ones and every Critical). All have `Status: affected` (no fix yet). |
| `grype-alpine.json` | **Captured**: `grype dir:<rootfs> -o json` on the same Alpine rootfs (Grype also reads `package-lock.json`). Includes GHSA ids with related CVEs and empty `fix.state`. |
| `docker-ps.json-lines.txt` | **Documented format**: `docker ps --format '{{json .}}'` (one object per running container, docker CLI 24+ field names), two containers on the same image. |
| `podman-ps.json` | **Documented format**: `podman ps --format json` (a JSON array; `Names` is a list). |

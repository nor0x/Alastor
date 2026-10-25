# Hardening fixtures

| File | Origin |
|---|---|
| `lynis-report.ubuntu.dat` | **Captured** 2026-10-24: `lynis audit system --cronjob --quiet --report-file …` (Lynis 3.1.6 from Ubuntu's repository) on an Ubuntu 26.04 container. Identifying values were replaced: `hostname`, `hostid`/`hostid2`, the MAC and private IPv4 address, and a user name. Hardening index 62, 1 warning, 40 suggestions (including empty details, a `text:` solution and an empty details field). |

# ClamAV fixtures

Captured on this repo's Ubuntu 26.04 dev container with the distro's ClamAV 1.5.4 and signatures mirrored by
`freshclam` (daily 28164, main 63, bytecode 339). Scanned paths were moved from a scratch directory to `/srv/…`.

| File | Command |
|---|---|
| `version.txt` | `clamscan --version` |
| `clamscan-infected.txt` | `clamscan --database=DIR -r --infected --stdout /srv/www` over the EICAR test file, a zip of it, a copy in a path with spaces, and an unreadable clean file (exit 1) |
| `clamscan-clean-with-error.txt` / `.stderr.txt` | stdout and stderr of `clamscan --database=DIR -r --infected --stdout /srv/clean /nonexistent/path` (exit 2) |
| `daily.cvd.header` | the first 512 bytes of `daily.cvd`: the documented `ClamAV-VDB:` header |

[← Alastor](../README.md) · Security

# Secure by default

Alastor shouldn't add exposure to the machine it runs on.

- **Loopback first.** The server listens on loopback (`ASPNETCORE_URLS=http://127.0.0.1:8080`). Put Caddy/nginx with
  TLS or `tailscale serve` in front, or listen on the tailnet address.
- **Network allowlists.** The dashboard and the agent API only answer private and tailnet addresses unless told
  otherwise (`ALASTOR_DASHBOARDALLOWFROM`, `ALASTOR_AGENTALLOWFROM`, see [configuration.md](configuration.md)).
  Everyone else gets a bare 404 before sign-in.
- **Hardened responses.** CSP and frame-blocking headers on every page; the API schema and the exact version stay
  behind sign-in.
- **Sign-in lockout.** An account locks after 5 failures (1 minute, doubling up to an hour).
- **Revocable sessions.** Signing out, a password change, or *Settings → Account* revokes sessions.
- **Two-factor sign-in.** Optional per user, with an authenticator app.
- **Self-check.** *Settings → Security* checks the server's own exposure (listening address, encryption, allowlists,
  file permissions, initial password, agents on plain HTTP), and the overview shows a banner while any check fails.
  `alastor-server security-check` prints the configuration checks from the shell.
- **Its own data, kept tidy.** *Settings → Alastor data* shows what the database and mirrors take up, removes old rows
  and unused mirrors, and compacts SQLite.

Agents refuse plain HTTP unless enrolled with `--insecure` (loopback and Tailscale addresses excepted: WireGuard
already encrypts those), and support certificate pinning (`--pin <sha256>`) for self-signed servers. The installer
opens nothing new by default; see [who can reach it](install.md#who-can-reach-it).

How each secret is stored (passwords, sessions, enrollment tokens, agent credentials, API keys), the exact headers,
and what isn't hardened yet are in [architecture.md](architecture.md#6-security-model).

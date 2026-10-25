# Firewall fixtures

| File | Origin |
|---|---|
| `ufw-show-added.txt` | **Captured** 2026-10-25 with ufw 0.36.2 (Ubuntu 24.04): `ufw show added` after adding rules with and without `comment 'alastor'`, including an interface rule and an app profile. |
| `ufw-status.inactive.txt` | **Captured**: `ufw status` while disabled. |

Probed on the same install: `ufw delete <rule>` removes a rule whether or not the comment is repeated;
`ufw --dry-run allow …` exits 1 on a bad rule ("ERROR: Bad source address") and 0 otherwise; rules can be added and
deleted while ufw is disabled.

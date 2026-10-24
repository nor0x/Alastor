# Blocklist fixtures

| File | Origin |
|---|---|
| `firehol_level1.netset` | **Captured** 2026-10-24 from iplists.firehol.org: the full header and the first 40 entries, plus the bogon entries (10/8, 100.64/10, 127/8, 172.16/12, 192.168/16, 224/3) that SentinelVPS must take out. |
| `spamhaus_drop_v4.json`, `spamhaus_drop_v6.json` | **Captured** 2026-10-24 from spamhaus.org/drop: the first records and the trailing metadata record. |
| `feodo_recommended.txt` | **Captured** 2026-10-24 from feodotracker.abuse.ch, complete. |
| `blocklist_de_all.txt` | **Captured** 2026-10-24 from lists.blocklist.de: the first 30 lines and the first 5 IPv6 lines. |
| `nft-no-permission.txt` | **Captured**: `nft -f` stderr in a container without CAP_NET_ADMIN. |
| `nft-list-chain.json` | **Documented format** (libnftables-json(5)): `nft -j list chain inet sentinel_vps prerouting` for the table the agent renders. Could not be captured here because the build container has no netlink access. |

# Authored IPv6 nested-service fixture

Synthetic fixture created for this project, not a production export. Two IPv6 assets; top → bundle → MySQL + HTTPS service references. Destination TCP/3306 and TCP/443 only.

Run from repository root:

```bash
python3 migrate.py --snapshot advanced-samples/ipv6-nested-snapshot.json --mapping advanced-samples/ipv6-mapping.json --out advanced-samples/result --bounded
```

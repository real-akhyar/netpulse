# Bundled data (offline — never fetched at runtime)

| File | Source | Snapshot | License |
|---|---|---|---|
| `dbip-country-lite.mmdb` | [DB-IP IP to Country Lite](https://db-ip.com/db/download/ip-to-country-lite) | 2026-10 | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — "IP Geolocation by DB-IP" |
| `dbip-asn-lite.mmdb` | [DB-IP IP to ASN Lite](https://db-ip.com/db/download/ip-to-asn-lite) | 2026-10 | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — "IP Geolocation by DB-IP" |
| `trackers.txt` | [OISD small](https://oisd.nl) (`domainswild2`, 59,447 entries) | 2026-10-28 | [GPL-3.0](https://github.com/sjhgvr/oisd/blob/main/LICENSE) — redistributed unmodified as a separate data file |
| `trackers_extra.txt` | netpulse curated supplement — major analytics/ad/telemetry domains OISD small omits (it's tuned not to break sites; we detect, not block) | 2026-10-28 | MIT (part of netpulse) |
| `tracker_companies.txt` | netpulse curated map of tracker domains to the companies behind them (privacy report) | 2026-10-28 | MIT (part of netpulse) |
| `country_centroids.csv` | [Google DSPL countries.csv](https://developers.google.com/public-data/docs/canonical/countries_csv) | 2026-10-28 | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) |

| `threat_domains.txt` | [HaGeZi Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists) "mini" domains + [URLhaus](https://urlhaus.abuse.ch) hosts via [malware-filter](https://gitlab.com/malware-filter/urlhaus-filter) (213,714 domains) | 2026-10-27 / 2026-10-28 | HaGeZi: GPL-3.0 (redistributed as data); URLhaus: CC0 |
| `threat_ips.txt` | HaGeZi TIF IPs + [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch) botnet C2s (32,550 IPs; 3,669 IPs on shared cloud/CDN networks left out) | 2026-10-27 / 2026-10-28 | HaGeZi: GPL-3.0; Feodo: CC0 |

To refresh the tracker list and GeoIP data: re-download the same files, replace them here, and
update the snapshot dates. To refresh the malware lists: `python scripts/update_threat_lists.py`
(abuse.ch's URLhaus/ThreatFox direct downloads now need an API key, hence the mirror and HaGeZi).

## Dashboard vendor files (`netpulse/web/vendor/`)

| File | Source | Version | License |
|---|---|---|---|
| `globe.gl.min.js` | [globe.gl](https://github.com/vasturiano/globe.gl) UMD build (includes three.js) | 2.46.2 | MIT |
| `world.geojson` | [Natural Earth](https://www.naturalearthdata.com/) 1:110m admin-0 countries, properties trimmed, coords rounded | 2026-10-28 | Public domain |

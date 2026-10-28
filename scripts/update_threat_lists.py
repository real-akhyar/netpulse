"""Rebuild netpulse's bundled known-malware lists (netpulse/data/threat_*.txt).

Maintainer tool, run by hand to refresh the snapshot — netpulse itself never downloads anything.

    python scripts/update_threat_lists.py              # download fresh copies
    python scripts/update_threat_lists.py --from DIR   # rebuild from files already in DIR

Sources (all free, no API key):
  - HaGeZi Threat Intelligence Feeds "mini" domains + TIF IPs (GPL-3.0)
  - malware-filter's URLhaus hosts mirror (CC0 data from abuse.ch URLhaus)
  - abuse.ch Feodo Tracker botnet C2 IPs (CC0; tiny, but hand-verified and labelled with the family)

Threat IPs owned by big shared cloud/CDN networks are dropped: their front-door IPs are shared
by countless sites and recycled between customers, so an IP match there would flag innocent
traffic. Domain matching still catches malware hosted on those clouds by name.
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from netpulse.detect.threats import is_shared_network  # noqa: E402
from netpulse.monitor.geoip import GeoIP  # noqa: E402

DATA = ROOT / "netpulse" / "data"
SOURCES = {
    "hagezi_tif_mini.txt": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
    "hagezi_tif_ips.txt": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt",
    "mf_urlhaus.txt": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
    "feodo.csv": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
}
_HOST = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")


def fetch(name: str, src_dir: Path | None) -> str:
    if src_dir:
        return (src_dir / name).read_text(encoding="utf-8", errors="replace")
    print(f"downloading {SOURCES[name]}")
    with urllib.request.urlopen(SOURCES[name], timeout=120) as resp:
        return resp.read().decode("utf-8", errors="replace")


def data_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="src", type=Path, help="use already-downloaded source files from this folder")
    src = ap.parse_args().src
    built = time.strftime("%Y-%m-%d")

    domains: dict[str, str] = {}
    for line in data_lines(fetch("hagezi_tif_mini.txt", src)):
        d = line.lower().removeprefix("*.")
        if _HOST.match(d):
            domains.setdefault(d, "hagezi")
    for line in data_lines(fetch("mf_urlhaus.txt", src)):
        d = line.split()[-1].lower()
        if _HOST.match(d):
            domains[d] = "urlhaus"  # more specific source wins

    geo = GeoIP()
    ips: dict[str, tuple[str, str]] = {}
    dropped = 0
    for line in data_lines(fetch("hagezi_tif_ips.txt", src)):
        try:
            ip = str(ipaddress.ip_address(line.split()[0]))
        except ValueError:
            continue
        if is_shared_network(geo.lookup(ip).org):
            dropped += 1
            continue
        ips[ip] = ("hagezi", "")
    feodo = [r for r in csv.reader(io.StringIO(fetch("feodo.csv", src))) if r and not r[0].startswith("#")]
    for row in feodo[1:]:  # header: first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware
        try:
            ips[str(ipaddress.ip_address(row[1]))] = ("feodo", row[5])
        except (ValueError, IndexError):
            continue

    header = [
        f"# netpulse known-malware {{kind}} — built {built} by scripts/update_threat_lists.py",
        "# Sources: HaGeZi Threat Intelligence Feeds (GPL-3.0), malware-filter URLhaus mirror (CC0),",
        "#          abuse.ch Feodo Tracker (CC0). See netpulse/data/SOURCES.md.",
    ]
    out = DATA / "threat_domains.txt"
    out.write_text("\n".join(h.format(kind="domains") for h in header)
                   + "\n# format: domain<TAB>source   (matches the domain and its subdomains)\n"
                   + "".join(f"{d}\t{s}\n" for d, s in sorted(domains.items())), encoding="utf-8")
    print(f"wrote {out.name}: {len(domains)} domains")
    out = DATA / "threat_ips.txt"
    out.write_text("\n".join(h.format(kind="IPs") for h in header)
                   + f"\n# {dropped} IPs owned by shared cloud/CDN networks were left out (see script docstring).\n"
                   + "# format: ip<TAB>source<TAB>malware family (when known)\n"
                   + "".join(f"{ip}\t{s}\t{fam}\n" for ip, (s, fam) in sorted(ips.items())), encoding="utf-8")
    print(f"wrote {out.name}: {len(ips)} IPs ({dropped} shared-network IPs dropped)")


if __name__ == "__main__":
    main()

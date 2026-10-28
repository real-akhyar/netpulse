"""Block-rule generation (SPEC §6): hosts-file entries, Windows Firewall rules, pf snippets.

MVP generates text only - nothing is applied. Every value is validated before it lands in the
output, because hostnames come from DNS (attacker-controllable) and the user pastes this into an
elevated PowerShell / their hosts file: a crafted name must never become a command.
"""

from __future__ import annotations

import ipaddress
import re
import sys
import time
from dataclasses import dataclass
from typing import Iterable, Optional

from netpulse.detect.rank import BlockTarget
from netpulse.detect.threats import is_shared_network

FORMATS = ("hosts", "windows_fw", "pf")
FILENAMES = {"hosts": "netpulse-hosts.txt", "windows_fw": "netpulse-firewall.ps1", "pf": "netpulse-pf.conf"}
FW_GROUP = "netpulse"

_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
_SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ._()-]")


@dataclass
class BlockResult:
    text: str
    filename: str
    domains: int
    ips: int


def safe_hostname(host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    return host if _HOSTNAME.match(host) else None


def safe_public_ip(ip: Optional[str]) -> Optional[str]:
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.is_global else None  # never emit rules for LAN/loopback


def _label(text: str) -> str:
    """For comments / DisplayNames: plain characters only."""
    return _SAFE_LABEL.sub("", text)[:60] or "app"


def _ps_quote(text: str) -> Optional[str]:
    if any(ord(ch) < 32 for ch in text):
        return None
    return "'" + text.replace("'", "''") + "'"


def _is_os_binary(exe: Optional[str]) -> bool:
    return bool(exe) and exe.lower().replace("/", "\\").startswith("c:\\windows\\")


def _clean(values: Iterable[Optional[str]], check) -> list[str]:
    return sorted({v for v in (check(x) for x in values) if v})


def _header(title: str) -> list[str]:
    return [f"# netpulse - {title}", f"# generated {time.strftime('%Y-%m-%d %H:%M')} | review before applying"]


def generate(targets: list[BlockTarget], fmt: str, extra_domains: Iterable[str] = ()) -> BlockResult:
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; expected one of {FORMATS}")
    if fmt == "hosts":
        return _hosts(targets, extra_domains)
    if fmt == "windows_fw":
        return _windows_fw(targets)
    return _pf(targets)


def _hosts(targets: list[BlockTarget], extra_domains: Iterable[str]) -> BlockResult:
    path = r"C:\Windows\System32\drivers\etc\hosts" if sys.platform == "win32" else "/etc/hosts"
    lines = _header("hosts-file blocklist") + [
        f"# 1. Open {path} as Administrator (Notepad -> Run as administrator)",
        "# 2. Paste these lines at the end and save",
        "# 3. Flush DNS: ipconfig /flushdns  (browsers may need a restart)",
        "# Note: apps using Secure DNS / DNS-over-HTTPS bypass the hosts file.",
    ]
    seen: set[str] = set()
    ips_without_name: list[str] = []

    def section(title: str, domains: list[str]) -> None:
        fresh = [d for d in domains if d not in seen]
        if not fresh:
            return
        lines.extend(["", f"# --- {title}"])
        for d in fresh:
            seen.add(d)
            lines.append(f"0.0.0.0 {d}")

    extra = _clean(extra_domains, safe_hostname)
    if extra:
        section("selected domains", extra)
    for t in targets:
        section(f"{_label(t.name)} - trackers", _clean(t.tracker_domains, safe_hostname))
        section(f"{_label(t.name)} - suspicious endpoints", _clean(t.suspicious.values(), safe_hostname))
        ips_without_name += [
            ip for ip in _clean(t.suspicious, safe_public_ip) if not safe_hostname(t.suspicious.get(ip))
        ]
    if ips_without_name:
        lines += ["", "# These suspicious IPs have no hostname, so the hosts file can't block them -",
                  "# use the Windows Firewall export instead: " + ", ".join(ips_without_name)]
    if not seen:
        lines += ["", "# Nothing to block yet - no tracker or suspicious domains caught."]
    return BlockResult("\n".join(lines) + "\n", FILENAMES["hosts"], len(seen), 0)


def _windows_fw(targets: list[BlockTarget]) -> BlockResult:
    lines = _header("Windows Firewall rules") + [
        "# Run in an elevated PowerShell (right-click -> Run as administrator).",
        "# Tracker *domains* are blocked via the hosts-file export (their IPs are shared CDNs -",
        "# blocking those would break unrelated sites). These rules block suspicious raw IPs.",
    ]
    total = 0
    if not targets:
        lines += ["", "# Nothing to block yet."]
    for t in targets:
        name = _label(t.name)
        ips, shared = _blockable_ips(t)
        lines += ["", f"# --- {name}"]
        for ip in ips:
            lines.append(
                f"New-NetFirewallRule -DisplayName 'netpulse: block {ip} ({name})' -Group '{FW_GROUP}' "
                f"-Direction Outbound -Action Block -RemoteAddress {ip}"
            )
        lines += _shared_notes(shared)
        total += len(ips)
        if not ips and not shared:
            lines.append(f"# No suspicious raw IPs for {name} - block its trackers with the hosts-file export.")
        program = _ps_quote(t.exe) if t.exe else None
        if program and not _is_os_binary(t.exe):
            lines += [
                f"# Optional - cut {name} off the internet entirely (the app may stop working):",
                f"# New-NetFirewallRule -DisplayName 'netpulse: block app {name}' -Group '{FW_GROUP}' "
                f"-Direction Outbound -Action Block -Program {program}",
            ]
    lines += ["", "# Undo everything netpulse added:", f"# Remove-NetFirewallRule -Group '{FW_GROUP}'"]
    return BlockResult("\n".join(lines) + "\n", FILENAMES["windows_fw"], 0, total)


def _applies(t: BlockTarget, ip: str) -> bool:
    """One-click blocking is conservative: trackers and known malware always, but a beacon or
    bare-IP endpoint only when the app itself is flagged critical. Legit apps reconnect on a timer
    too (update checks, sync), and blocking their server breaks them — the exports still list
    every suspicious endpoint for the user to review."""
    return t.kinds.get(ip) == "known_malware" or t.critical


def plan(targets: list[BlockTarget]) -> tuple[dict[str, str], dict[str, str]]:
    """What a one-click block would apply: {domain: app name} for the hosts file and
    {ip: app name} for the firewall (validated values only, shared CDN/cloud IPs left to the
    hosts file)."""
    domains: dict[str, str] = {}
    ips: dict[str, str] = {}
    for t in targets:
        hosts = list(t.tracker_domains) + [h for ip, h in t.suspicious.items() if h and _applies(t, ip)]
        for d in _clean(hosts, safe_hostname):
            domains.setdefault(d, t.name)
        for ip in _blockable_ips(t)[0]:
            if _applies(t, ip):
                ips.setdefault(ip, t.name)
    return domains, ips


def _blockable_ips(t: BlockTarget) -> tuple[list[str], list[tuple[str, str]]]:
    """Split a target's IPs into ones safe to firewall and ones on shared CDN/cloud networks,
    where one IP fronts thousands of unrelated sites (those are left to the hosts file)."""
    ips, shared = [], []
    for ip in _clean(t.suspicious, safe_public_ip):
        org = t.orgs.get(ip)
        if is_shared_network(org):
            shared.append((ip, _label(org or "")))
        else:
            ips.append(ip)
    return ips, shared


def _shared_notes(shared: list[tuple[str, str]]) -> list[str]:
    return [
        f"# Skipped {ip}: it belongs to {org}, shared by many unrelated sites - blocking it would break them."
        " Its hostname is in the hosts-file export." for ip, org in shared
    ]


def _pf(targets: list[BlockTarget]) -> BlockResult:
    ips, shared = set(), []
    for t in targets:
        safe, skipped = _blockable_ips(t)
        ips.update(safe)
        shared += skipped
    ips = sorted(ips)
    lines = _header("pf rules (macOS)") + [
        "# Add to /etc/pf.conf (or an anchor), then: sudo pfctl -f /etc/pf.conf -e",
        "# Tracker domains: use the hosts-file export.",
        "",
    ]
    if ips:
        lines += [f"table <netpulse_block> {{ {', '.join(ips)} }}", "block drop out quick to <netpulse_block>"]
    elif not shared:
        lines.append("# No suspicious raw IPs to block.")
    lines += _shared_notes(shared)
    return BlockResult("\n".join(lines) + "\n", FILENAMES["pf"], 0, len(ips))

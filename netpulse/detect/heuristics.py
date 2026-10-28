"""Flags that bite even fully offline / on raw IPs (SPEC §2.2, as amended by DECISIONS:
beaconing is keyed on repeated NEW connections per (app, remote_ip, rport); unusual_port is
info-only and never makes a connection suspicious)."""

from __future__ import annotations

import ntpath
import os
import statistics
from typing import Optional

from netpulse.models import Connection, Flag, ProcessInfo

BEACON_MIN_ARRIVALS = 4
# Regularity = median absolute deviation / median of inter-arrival gaps. Median-based so one
# outlier gap (a missed poll, or deliberate beacon jitter) doesn't hide a beacon.
BEACON_MAX_SPREAD = 0.25
BEACON_MIN_PERIOD = 3.0  # seconds; faster than this is a connection pool, not a beacon
RAW_IP_MIN_ARRIVALS = 3
MANY_TRACKERS_K = 3

# Ports normal apps use to public hosts. Anything else gets an info-only `unusual_port`.
COMMON_PORTS = {
    80, 443, 53, 853, 123,  # web, DNS, DoT, NTP
    25, 465, 587, 110, 995, 143, 993,  # mail
    22, 5222, 5223, 5228, 5229, 5230,  # ssh, XMPP / Apple push / Google FCM
    3478, 3479, 3480, 3481, 19302,  # STUN/TURN (Teams, Meet, WebRTC)
    8801, 8802, 8803, 8804, 8805, 8806, 8807, 8808, 8809, 8810,  # Zoom
    4070,  # Spotify
    1935, 8080, 8443,
}


def beacon_period(arrivals: list[float]) -> Optional[float]:
    """Median period if arrivals are regular enough to be a beacon, else None."""
    if len(arrivals) < BEACON_MIN_ARRIVALS:
        return None
    gaps = [b - a for a, b in zip(arrivals, arrivals[1:])]
    period = statistics.median(gaps)
    if period < BEACON_MIN_PERIOD:
        return None
    spread = statistics.median(abs(g - period) for g in gaps) / period
    if spread > BEACON_MAX_SPREAD:
        return None
    return period


def _where(conn: Connection) -> str:
    return conn.country or "unknown country"


def connection_flags(conn: Connection, arrivals: list[float], resolved: bool) -> list[Flag]:
    """Per-connection flags. `resolved` = hostname lookup has finished (so a missing host is real)."""
    if conn.scope != "public":
        return []
    flags: list[Flag] = []
    host = conn.remote_host or conn.raddr
    if conn.tracker_rule:
        flags.append(Flag(
            id="tracker_contact", severity="medium",
            title=f"Contacted ad/tracker domain {conn.tracker_rule}",
            detail=f"{conn.process_name} connected to {host}, which is on the bundled tracker blocklist.",
        ))
    period = beacon_period(arrivals)
    if period is not None:
        flags.append(Flag(
            id="beaconing", severity="medium",
            title=f"Regular beaconing to {conn.raddr} ({_where(conn)})",
            detail=f"{conn.process_name} opened {len(arrivals)} new connections to {host}:{conn.rport} about every {period:.0f}s.",
        ))
    if resolved and not conn.remote_host and len(arrivals) >= RAW_IP_MIN_ARRIVALS:
        org = f", owned by {conn.org}" if conn.org else ""
        flags.append(Flag(
            id="raw_ip", severity="low",
            title=f"Talks to a bare IP with no hostname ({conn.raddr})",
            detail=f"{conn.process_name} keeps reconnecting to {conn.raddr} ({_where(conn)}{org}) with no DNS name behind it.",
        ))
    if conn.rport not in COMMON_PORTS:
        flags.append(Flag(
            id="unusual_port", severity="info",
            title=f"Non-standard port {conn.rport} to {host}",
            detail="Informational only — many apps legitimately use their own ports.",
        ))
    return flags


def categorize(conn: Connection) -> str:
    if conn.scope != "public":
        return "local"
    ids = {f.id for f in conn.flags}
    if "known_malware" in ids:
        return "malware"
    if "tracker_contact" in ids:
        return "tracker"
    if ids & {"beaconing", "raw_ip", "suspicious_process"}:
        return "suspicious"
    return "normal"


# ---- suspicious processes ------------------------------------------------
# Who the app is matters as much as where it connects: the real malware netpulse caught on its
# own dev laptop was code running inside cmd.exe. These rules need the ProcessInfo (path,
# signature, parent) and only fire for apps that actually talk to the public internet.

# Built-in Windows tools that have no reason to open internet connections themselves. When one
# does, code is usually running inside it ("living off the land").
SILENT_TOOLS = {
    "cmd.exe": "the Windows command prompt",
    "rundll32.exe": "a Windows DLL loader",
    "regsvr32.exe": "a Windows component registrar",
    "mshta.exe": "the Windows HTML-application host",
    "wscript.exe": "the Windows script host",
    "cscript.exe": "the Windows console script host",
    "msbuild.exe": "the .NET build tool",
    "installutil.exe": "a .NET installer utility",
    "regasm.exe": "a .NET registration tool",
    "regsvcs.exe": "a .NET services tool",
    "cmstp.exe": "the Connection Manager profile installer",
    "mavinject.exe": "a Windows app-compatibility injector",
    "odbcconf.exe": "the ODBC configuration tool",
    "notepad.exe": "Notepad",
    "calc.exe": "Calculator",
    "conhost.exe": "the console window host",
}
# Tools with legitimate internet uses that malware also loves: worth a look, not a verdict.
DUAL_USE_TOOLS = {
    "powershell.exe": "Windows PowerShell",
    "powershell_ise.exe": "the PowerShell ISE",
    "pwsh.exe": "PowerShell",
    "certutil.exe": "the Windows certificate tool",
    "bitsadmin.exe": "the Windows background-transfer tool",
    "wmic.exe": "the WMI command line",
}
# Names malware borrows to blend in. The real ones only ever live under the Windows folder.
SYSTEM_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
    "explorer.exe", "spoolsv.exe", "dllhost.exe", "taskhostw.exe", "runtimebroker.exe", "conhost.exe",
    "cmd.exe", "rundll32.exe", "regsvr32.exe", "powershell.exe", "lsm.exe", "sihost.exe", "ctfmon.exe",
}
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe",
                  "acrord32.exe", "acrobat.exe"}
# Folders legitimate software rarely runs from.
RISKY_DIRS = {
    "\\appdata\\local\\temp\\": ("a temporary folder", "high"),
    "\\windows\\temp\\": ("a temporary folder", "high"),
    "\\$recycle.bin\\": ("the Recycle Bin", "critical"),
    "\\users\\public\\": ("the shared Public folder", "high"),
    "\\downloads\\": ("your Downloads folder", "medium"),
}


def _windows_dir() -> str:
    return (os.environ.get("SystemRoot") or "C:\\Windows").lower().rstrip("\\") + "\\"


def process_flags(
    name: str,
    tracker_domains: set[str],
    info: Optional[ProcessInfo] = None,
    online: bool = False,
    remote: Optional[str] = None,
) -> list[Flag]:
    """App-level flags. `online` = the app has public-internet connections; `remote` = one of
    them, for the plain-English detail. Each detail is a sentence the verdict can lead with."""
    flags: list[Flag] = []
    if len(tracker_domains) >= MANY_TRACKERS_K:
        flags.append(Flag(
            id="many_trackers", severity="high",
            title=f"{name} contacted {len(tracker_domains)} trackers",
            detail=", ".join(sorted(tracker_domains)[:8]),
        ))
    if info is None or not online:
        return flags

    lname = name.lower()
    exe = (info.exe or "").lower().replace("/", "\\")
    folder = ntpath.dirname(info.exe) if info.exe else "an unknown folder"
    where = f" ({remote})" if remote else ""
    parent = (info.parent_name or "").lower()
    in_windows = exe.startswith(_windows_dir())

    if exe and lname in SYSTEM_NAMES and not in_windows:
        flags.append(Flag(
            id="masquerading", severity="critical",
            title=f"Fake system file: {name} outside the Windows folder",
            detail=f"{name} is named like a core Windows file but runs from {folder} — the real one only "
                   f"lives in the Windows folder. This is a classic malware disguise, and it's online{where}.",
        ))
    if lname in SILENT_TOOLS:
        launched = f" It was started by {info.parent_name}, a document app — a common attack pattern." \
            if parent in OFFICE_PARENTS else (" Whatever started it has already exited." if info.parent_pid and not info.parent_name else "")
        flags.append(Flag(
            id="silent_tool_online", severity="critical",
            title=f"{name} is talking to the internet",
            detail=f"{name} is {SILENT_TOOLS[lname]}, which never needs the internet on its own — yet it's "
                   f"connecting out{where}. Something is probably running inside it.{launched}",
        ))
    elif lname in DUAL_USE_TOOLS:
        severity = "critical" if parent in OFFICE_PARENTS else "high"
        launched = f" It was started by {info.parent_name}, a document app — a common attack pattern." \
            if parent in OFFICE_PARENTS else ""
        flags.append(Flag(
            id="dual_use_tool_online", severity=severity,
            title=f"{name} is downloading or calling out",
            detail=f"{name} is {DUAL_USE_TOOLS[lname]}, which is connecting out{where}. Installers and scripts "
                   f"do this legitimately, but it's also a favourite of malware — check what started it.{launched}",
        ))
    for marker, (label, severity) in RISKY_DIRS.items():
        if marker in exe:
            flags.append(Flag(
                id="risky_location", severity=severity,
                title=f"Runs from {label}",
                detail=f"{name} runs from {label} ({folder}) and talks to the internet{where}. Installed software "
                       f"doesn't normally live there; dropped malware often does.",
            ))
            break
    if info.signature == "invalid":
        claims = f" by {info.signer}" if info.signer else ""
        flags.append(Flag(
            id="bad_signature", severity="critical",
            title="Tampered or untrusted signature",
            detail=f"{name}'s digital signature is broken — the file was changed after it was signed{claims}, "
                   f"or the signer isn't trusted. Tampered programs shouldn't be online{where}.",
        ))
    elif info.signature == "unsigned" and not any(f.id != "many_trackers" for f in flags):
        flags.append(Flag(
            id="unsigned", severity="low",
            title="No verified publisher",
            detail=f"{name} has no digital signature, so there's no verified publisher behind it. Common for "
                   f"small and developer tools; worth knowing for anything you didn't install yourself.",
        ))
    return flags

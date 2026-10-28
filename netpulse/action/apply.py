"""One-click blocking (Windows): apply and undo hosts-file entries and firewall rules.

Safety model:
- netpulse only ever edits its own clearly marked section of the hosts file and its own firewall
  rules (group "netpulse"). Everything else in the hosts file is left byte-for-byte as it was, and
  a one-time backup is made before the first change.
- Changes need admin rights, so each apply/undo runs a short PowerShell helper elevated (one
  Windows admin prompt; none if netpulse already runs as admin). The helper is passed inline
  (-EncodedCommand) — there is no script file on disk to tamper with — and it reads its data from
  a JSON file only after checking that file's SHA-256 against the hash baked into the command.
  It then re-validates every hosts line and IP itself before writing anything.
- After every change the hosts file is read back to confirm what's actually there.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from netpulse.action.block import FW_GROUP, _label, safe_hostname, safe_public_ip

log = logging.getLogger(__name__)

SECTION_START = "# >>> netpulse blocks (managed by netpulse - edit with `netpulse watch`, not by hand) >>>"
SECTION_END = "# <<< netpulse blocks <<<"
MAX_ENTRIES = 2000
ELEVATION_TIMEOUT = 180  # seconds to wait for the admin prompt + work
# Windows Defender treats hosts entries that block Microsoft's own domains as a "hosts file hijack".
MICROSOFT_SUFFIXES = ("microsoft.com", "windows.com", "windowsupdate.com", "msn.com", "live.com", "office.com",
                      "office.net", "bing.com", "msftncsi.com", "azure.com", "skype.com", "xboxlive.com")

# The elevated helper. Contains no data: paths/hash are substituted as base64 / hex only.
_HELPER = r"""
$ErrorActionPreference = 'Stop'
$result = @{ ok = $false; error = $null; fw_added = 0; fw_removed = 0 }
try {
  $dataPath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@DATA_PATH@'))
  $bytes = [IO.File]::ReadAllBytes($dataPath)
  $hash = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
  if ($hash -ne '@DATA_SHA256@') { throw 'request file was changed after netpulse wrote it - refusing' }
  $d = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
  $start = '# >>> netpulse blocks'; $end = '# <<< netpulse blocks'
  $section = @($d.section)
  foreach ($l in $section) {
    if ($l.StartsWith('#')) { continue }
    if ($l -cnotmatch '^0\.0\.0\.0 [a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9])?$') { throw "refusing unexpected hosts line: $l" }
  }
  # Same encoding in and out, so the user's own lines (and any non-English comments) round-trip unchanged.
  $enc = [Text.Encoding]::Default
  $lines = @(); if (Test-Path -LiteralPath $d.hosts_path) { $lines = @([IO.File]::ReadAllLines($d.hosts_path, $enc)) }
  $out = New-Object System.Collections.Generic.List[string]; $inside = $false
  foreach ($l in $lines) {
    if ($l.StartsWith($start)) { $inside = $true; continue }
    if ($inside -and $l.StartsWith($end)) { $inside = $false; continue }
    if (-not $inside) { $out.Add($l) }
  }
  while ($out.Count -gt 0 -and $out[$out.Count - 1].Trim() -eq '') { $out.RemoveAt($out.Count - 1) }
  if ($section.Count -gt 0) { $out.Add(''); foreach ($l in $section) { $out.Add($l) } }
  $bak = $d.hosts_path + '.netpulse.bak'
  if ((Test-Path -LiteralPath $d.hosts_path) -and -not (Test-Path -LiteralPath $bak)) { Copy-Item -LiteralPath $d.hosts_path -Destination $bak }
  [IO.File]::WriteAllLines($d.hosts_path, [string[]]$out.ToArray(), $enc)
  foreach ($name in @($d.remove)) {
    if ($name -cnotmatch '^netpulse: block [0-9a-fA-F.:]+ \([A-Za-z0-9 ._()-]*\)$') { throw 'bad rule name' }
    if (-not $d.dry) { Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
    $result.fw_removed++
  }
  foreach ($a in @($d.add)) {
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse([string]$a.ip, [ref]$ip)) { throw "bad ip $($a.ip)" }
    if ($a.name -cnotmatch '^netpulse: block [0-9a-fA-F.:]+ \([A-Za-z0-9 ._()-]*\)$') { throw 'bad rule name' }
    if (-not $d.dry) {
      New-NetFirewallRule -DisplayName $a.name -Group '@GROUP@' -Direction Outbound -Action Block -RemoteAddress $ip.ToString() | Out-Null
    }
    $result.fw_added++
  }
  if (-not $d.dry) { ipconfig /flushdns | Out-Null }
  $result.ok = $true
} catch { $result.error = $_.Exception.Message }
$resultPath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@RESULT_PATH@'))
$result | ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
"""


def hosts_path() -> Path:
    return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def rule_name(ip: str, app: str) -> str:
    return f"netpulse: block {ip} ({_label(app)})"


def read_managed_domains(path: Path) -> set[str]:
    """Domains currently in netpulse's section of the hosts file (readable without admin)."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return set()
    inside, found = False, set()
    for line in lines:
        if line.startswith("# >>> netpulse blocks"):
            inside = True
        elif inside and line.startswith("# <<< netpulse blocks"):
            inside = False
        elif inside and line.startswith("0.0.0.0 "):
            found.add(line.split()[1])
    return found


@dataclass
class ApplyResult:
    ok: bool
    error: Optional[str] = None
    fw_added: int = 0
    fw_removed: int = 0
    warnings: list[str] = field(default_factory=list)


class Applier:
    """Runs the helper. Tests point it at a scratch hosts file with dry-run firewall changes."""

    def __init__(self, hosts: Optional[Path] = None, dry_firewall: bool = False, elevate: Optional[bool] = None):
        self.hosts = Path(hosts) if hosts else hosts_path()
        self.dry_firewall = dry_firewall
        self.elevate = (not is_admin()) if elevate is None else elevate

    @property
    def supported(self) -> bool:
        return sys.platform == "win32"

    def apply(self, domains: list[str], add_ips: dict[str, str], remove_rules: list[str]) -> ApplyResult:
        """Make netpulse's hosts section exactly `domains`, add firewall rules {ip: app}, remove
        rules by name. Blocking: may wait for the user to answer the admin prompt."""
        if not self.supported:
            return ApplyResult(False, "one-click blocking is Windows-only for now - use the export instead")
        clean = sorted({d for d in (safe_hostname(x) for x in domains) if d})[:MAX_ENTRIES]
        section = [SECTION_START, *[f"0.0.0.0 {d}" for d in clean], SECTION_END] if clean else []
        add = [{"ip": ip, "name": rule_name(ip, app)} for ip, app in add_ips.items() if safe_public_ip(ip)]
        remove = [n for n in remove_rules if re.fullmatch(r"netpulse: block [0-9a-fA-F.:]+ \([A-Za-z0-9 ._()-]*\)", n)]
        payload = json.dumps({"hosts_path": str(self.hosts), "section": section, "add": add, "remove": remove,
                              "dry": self.dry_firewall}).encode("utf-8")

        work = Path(tempfile.mkdtemp(prefix="netpulse-apply-"))
        data, result = work / "request.json", work / "result.json"
        data.write_bytes(payload)
        script = (_HELPER.replace("@DATA_PATH@", base64.b64encode(str(data).encode()).decode())
                  .replace("@RESULT_PATH@", base64.b64encode(str(result).encode()).decode())
                  .replace("@DATA_SHA256@", hashlib.sha256(payload).hexdigest())
                  .replace("@GROUP@", FW_GROUP))
        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        try:
            if self.elevate:
                # One admin prompt; -Wait so we know when it's done. Declining raises in Start-Process.
                launcher = ("try { $p = Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait -PassThru "
                            f"-ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','{encoded}'; exit $p.ExitCode }} "
                            "catch { exit 1223 }")
                cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", launcher]
            else:
                cmd = ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
            run = subprocess.run(cmd, capture_output=True, text=True, timeout=ELEVATION_TIMEOUT,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if run.returncode == 1223:
                return ApplyResult(False, "the Windows admin prompt was declined - nothing was changed")
            try:
                out = json.loads(result.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError):
                return ApplyResult(False, "the admin helper didn't report back - nothing confirmed")
            res = ApplyResult(bool(out.get("ok")), out.get("error"), int(out.get("fw_added") or 0),
                              int(out.get("fw_removed") or 0))
        except subprocess.TimeoutExpired:
            return ApplyResult(False, "timed out waiting for the admin prompt")
        finally:
            for f in (data, result):
                try:
                    f.unlink()
                except OSError:
                    pass
            try:
                work.rmdir()
            except OSError:
                pass
        # Trust, but verify: the hosts file must now hold exactly what we asked for.
        if res.ok and read_managed_domains(self.hosts) != set(clean):
            res.ok, res.error = False, "the hosts file doesn't match what was written (antivirus may have reverted it)"
        ms = sorted(d for d in clean if d.endswith(MICROSOFT_SUFFIXES))
        if ms:
            res.warnings.append(f"Windows Defender may flag hosts entries that block Microsoft domains "
                                f"({', '.join(ms[:3])}{'…' if len(ms) > 3 else ''}) and remove them.")
        return res


@dataclass
class BlockEntry:
    kind: str  # "domain" | "ip"
    value: str
    apps: list[str]  # app names it was blocked for
    added: float

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.value}"


class BlockStore:
    """Which blocks netpulse has applied (blocks.json next to the history file)."""

    def __init__(self, path: Optional[Path] = None, applier: Optional[Applier] = None):
        from netpulse.store import default_path

        self.path = Path(path) if path else default_path().with_name("blocks.json")
        self.applier = applier or Applier()
        self.entries: dict[str, BlockEntry] = {}
        try:
            for e in json.loads(self.path.read_text(encoding="utf-8")).get("blocks", []):
                entry = BlockEntry(e["kind"], e["value"], list(e.get("apps", [])), float(e.get("added", 0)))
                self.entries[entry.id] = entry
        except FileNotFoundError:
            pass
        except (OSError, ValueError, KeyError):
            log.warning("blocks file unreadable (%s); starting empty", self.path)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"blocks": [e.__dict__ for e in self.entries.values()]}, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def _domains(self, entries: dict[str, BlockEntry]) -> list[str]:
        return [e.value for e in entries.values() if e.kind == "domain"]

    def add(self, domains: dict[str, str], ips: dict[str, str]) -> ApplyResult:
        """Block more {domain: app} / {ip: app}. Applies everything in one admin prompt."""
        new = dict(self.entries)
        now = time.time()
        for kind, values in (("domain", domains), ("ip", ips)):
            for value, app in values.items():
                key = f"{kind}:{value}"
                if key in new:
                    if app not in new[key].apps:
                        new[key] = BlockEntry(kind, value, new[key].apps + [app], new[key].added)
                else:
                    new[key] = BlockEntry(kind, value, [app], now)
        add_ips = {e.value: e.apps[0] for k, e in new.items() if e.kind == "ip" and k not in self.entries}
        res = self.applier.apply(self._domains(new), add_ips, [])
        if res.ok:
            self.entries = new
            self._save()
        return res

    def remove(self, ids: Optional[list[str]] = None) -> ApplyResult:
        """Undo some blocks (or all, with ids=None)."""
        gone = set(self.entries) if ids is None else {i for i in ids if i in self.entries}
        keep = {k: e for k, e in self.entries.items() if k not in gone}
        rules = [rule_name(self.entries[k].value, self.entries[k].apps[0]) for k in gone if self.entries[k].kind == "ip"]
        res = self.applier.apply(self._domains(keep), {}, rules)
        if res.ok:
            self.entries = keep
            self._save()
        return res

    def summary(self) -> dict:
        present = read_managed_domains(self.applier.hosts)
        return {
            "supported": self.applier.supported,
            "admin_prompt": self.applier.elevate,
            "entries": [
                {"id": e.id, "kind": e.kind, "value": e.value, "apps": e.apps, "added": e.added,
                 "active": e.kind == "ip" or e.value in present}
                for e in sorted(self.entries.values(), key=lambda e: -e.added)
            ],
        }

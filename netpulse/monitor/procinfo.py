"""Process insight: who an app is (code-signing publisher, path) and how it was started (parent,
command line, user, start time).

Each pid is inspected once; each exe's signature is checked once and cached. Signatures come from
PowerShell's Get-AuthenticodeSignature, batched (one call for many files, ~0.5s), which also
understands catalog-signed Windows binaries such as cmd.exe. Everything degrades to "unknown".
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
from typing import Optional

import psutil

from netpulse.models import ProcessInfo
from netpulse.monitor.connections import normalize_exe

log = logging.getLogger(__name__)

SIGNATURE_BATCH_DELAY = 0.5  # gather requests this long, then check them in one PowerShell call
CMDLINE_MAX = 500
_STATUS = {"Valid": "valid", "NotSigned": "unsigned", "HashMismatch": "invalid", "NotTrusted": "invalid"}
# Redact obvious secrets in command lines (--token=abc, password abc, api_key:abc ...).
_SECRET = re.compile(r"(?i)((?:token|secret|passw(?:or)?d|pwd|api[_-]?key|auth)[\w-]*[=: ]\s*)(\S+)")

_PS_SCRIPT = (
    "$ErrorActionPreference='SilentlyContinue'; "
    "$paths = [Console]::In.ReadToEnd() | ConvertFrom-Json; "
    "Get-AuthenticodeSignature -LiteralPath $paths | ForEach-Object { [pscustomobject]@{ "
    "Path=$_.Path; Status=[string]$_.Status; "
    "Signer=if($_.SignerCertificate){$_.SignerCertificate.GetNameInfo('SimpleName',$false)}else{$null} } } "
    "| ConvertTo-Json -Compress"
)


def path_key(path: str) -> str:
    """Case/separator-insensitive key so 'C:/x/A.exe' and 'c:\\x\\a.exe' match."""
    return os.path.normcase(os.path.normpath(path))


def redact(cmdline: str) -> str:
    return _SECRET.sub(lambda m: m.group(1) + "***", cmdline)


def inspect_pid(pid: int) -> Optional[ProcessInfo]:
    """Blocking psutil reads; every field is best-effort (AccessDenied leaves it empty)."""
    try:
        proc = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return None
    info = ProcessInfo(pid=pid)

    def attempt(fn):
        try:
            return fn()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError, ValueError):
            return None

    info.exe = normalize_exe(attempt(proc.exe)) or None
    args = attempt(proc.cmdline)
    if args:
        info.cmdline = redact(subprocess.list2cmdline(args))[:CMDLINE_MAX]
    info.started = attempt(proc.create_time)
    info.user = attempt(proc.username)
    parent = attempt(proc.parent)
    if parent is not None:
        info.parent_pid = parent.pid
        info.parent_name = attempt(parent.name)
    else:
        info.parent_pid = attempt(proc.ppid)  # parent already exited — keep its pid, no name
    return info


def check_signatures(paths: list[str]) -> dict[str, tuple[str, Optional[str]]]:
    """Blocking: {path_key(path): (status, signer)} for each path PowerShell could read."""
    if sys.platform != "win32" or not paths:
        return {}
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_SCRIPT],
            input=json.dumps(paths), capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout.strip()
        rows = json.loads(out) if out else []
    except Exception:
        log.debug("signature check failed", exc_info=True)
        return {}
    if isinstance(rows, dict):  # ConvertTo-Json unwraps single-item arrays
        rows = [rows]
    return {
        path_key(str(r["Path"])): (_STATUS.get(r.get("Status"), "unknown"), r.get("Signer") or None)
        for r in rows if r.get("Path")
    }


class ProcessInspector:
    def __init__(self) -> None:
        self._signatures: dict[str, tuple[str, Optional[str]]] = {}
        self._waiting: dict[str, list[asyncio.Future]] = {}
        self._flush_task: Optional[asyncio.Task] = None

    async def inspect(self, pid: int, on_update=None) -> Optional[ProcessInfo]:
        """Process details right away (reported via on_update), then again once the signature
        check finishes — a slow PowerShell call never hides the rest."""
        info = await asyncio.to_thread(inspect_pid, pid)
        if info is None:
            return None
        if info.exe:
            info.signature = "checking"
        if on_update:
            on_update(info)
        if info.exe:
            signature, signer = await self.signature(info.exe)
            info = info.model_copy(update={"signature": signature, "signer": signer})
            if on_update:
                on_update(info)
        return info

    async def signature(self, exe: str) -> tuple[str, Optional[str]]:
        key = path_key(exe)
        if key in self._signatures:
            return self._signatures[key]
        fut = asyncio.get_running_loop().create_future()
        self._waiting.setdefault(key, []).append(fut)
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._flush())
        return await fut

    async def _flush(self) -> None:
        await asyncio.sleep(SIGNATURE_BATCH_DELAY)
        batch, self._waiting = self._waiting, {}
        results = await asyncio.to_thread(check_signatures, list(batch))
        for key, futures in batch.items():
            self._signatures[key] = results.get(key, ("unknown", None))
            for fut in futures:
                if not fut.done():
                    fut.set_result(self._signatures[key])
        # Requests that arrived while this (possibly slow) batch ran need their own batch.
        if self._waiting:
            self._flush_task = asyncio.create_task(self._flush())

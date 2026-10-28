"""Shared test setup.

Every test runs against throwaway data: netpulse's data folder (history, trust, blocks, settings)
points at a temp dir, and any block store a test doesn't build itself edits a scratch hosts file
with firewall changes in dry-run mode. The real hosts file must never change during a run.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

import netpulse.action.apply as apply_mod
from netpulse.models import Connection, Flag

HERE = Path(__file__).parent
PROBE = HERE / "probe.py"
REAL_HOSTS = apply_mod.hosts_path()


class _SandboxApplier(apply_mod.Applier):
    def __init__(self, hosts=None, dry_firewall=True, elevate=False):
        super().__init__(hosts=hosts, dry_firewall=dry_firewall, elevate=elevate)


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    data = tmp_path / "appdata"
    data.mkdir()
    # Windows reads LOCALAPPDATA, Linux XDG_DATA_HOME, macOS HOME. HOME/USERPROFILE stay put on
    # Windows: child PowerShells would lose their profile folders and write caches into the cwd.
    for var in ("LOCALAPPDATA", "XDG_DATA_HOME") + (() if sys.platform == "win32" else ("HOME",)):
        monkeypatch.setenv(var, str(data))
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"127.0.0.1 localhost\r\n# my own comment\r\n")
    monkeypatch.setattr(apply_mod, "hosts_path", lambda: hosts)
    monkeypatch.setattr(apply_mod, "Applier", _SandboxApplier)
    return data


@pytest.fixture(scope="session", autouse=True)
def real_hosts_untouched():
    before = REAL_HOSTS.read_bytes() if REAL_HOSTS.exists() else None
    yield
    after = REAL_HOSTS.read_bytes() if REAL_HOSTS.exists() else None
    assert after == before, "the real hosts file changed during the test run"


@pytest.fixture
def sandbox_hosts(tmp_path) -> Path:
    h = tmp_path / "sandbox" / "hosts"
    h.parent.mkdir()
    h.write_bytes(b"127.0.0.1 localhost\r\n# my own comment\r\n")
    return h


windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only feature")

TRACKER = Flag(id="tracker_contact", severity="medium", title="tracker")


def feed(pipeline, conn: Connection, arrivals: list[float] | None = None) -> Connection:
    """Push a connection through the pipeline's resolve -> detect -> rank -> history path, as if
    the OS connection table had shown it and its hostname came from the DNS cache. No network."""
    from netpulse.monitor.resolve import Resolution

    pipeline._inspected_pids.add(conn.pid)  # skip the (async) process inspection
    if arrivals is not None:
        key = (conn.app, conn.raddr, conn.rport)
        pipeline.monitor.arrivals[key] = list(arrivals)
    host = conn.remote_host
    conn.remote_host = conn.tracker_rule = conn.threat_indicator = None
    conn.flags = []
    pipeline._apply(conn, Resolution(host=host, source="dns_cache" if host else None, names=[host] if host else []))
    return conn


def make_conn(i: int, app: str, ip: str, host: str | None = None, rule: str | None = None,
              threat: str | None = None, flags=(), port: int = 443, pid: int | None = 10) -> Connection:
    """A classified public connection, as the pipeline would hand it to the ranker."""
    now = time.time()
    return Connection(
        id=f"{app}|{i}", pid=pid, process_name=app.replace("/", "\\").split("\\")[-1], process_exe=app,
        laddr="", lport=i, raddr=ip, rport=port, status="ESTABLISHED", scope="public", remote_host=host,
        country="US", tracker_rule=rule, threat_indicator=threat,
        threat="listed as malware infrastructure by X" if threat else None,
        flags=list(flags), first_seen=now, last_seen=now,
    )

"""One-click block (Windows): the admin helper, the block store and undo.
Sandbox only: scratch hosts files, firewall changes in dry-run mode."""

from pathlib import Path
from unittest import mock

import pytest

import netpulse.action.apply as apply_mod
from netpulse.action.apply import BlockStore, is_admin, read_managed_domains

from conftest import windows_only

pytestmark = windows_only


def applier(hosts, elevate=False):
    return apply_mod.Applier(hosts=hosts, dry_firewall=True, elevate=elevate)


def test_tampered_request_file_is_refused(sandbox_hosts):
    real_write = Path.write_bytes

    def tampering_write(self, data):
        if self.name == "request.json":
            data = data.replace(b'"section": [', b'"section": ["0.0.0.0 bank.com", ', 1)
        return real_write(self, data)
    with mock.patch.object(Path, "write_bytes", tampering_write):
        r = applier(sandbox_hosts).apply(["tracker.example.com"], {}, [])
    assert not r.ok and "changed after" in (r.error or "")
    assert b"bank.com" not in sandbox_hosts.read_bytes()


def test_helper_revalidates_hosts_lines(sandbox_hosts):
    with mock.patch.object(apply_mod, "safe_hostname", lambda x: x):
        r = applier(sandbox_hosts).apply(["evil.com\r\n1.2.3.4 bank.com"], {}, [])
    assert not r.ok and "refusing" in (r.error or "")
    assert b"bank.com" not in sandbox_hosts.read_bytes()


def test_helper_revalidates_ips(sandbox_hosts):
    with mock.patch.object(apply_mod, "safe_public_ip", lambda x: x):
        r = applier(sandbox_hosts).apply([], {"1.2.3.4; Remove-Item C:\\": "x"}, [])
    assert not r.ok and "bad ip" in (r.error or "")


@pytest.mark.skipif(not is_admin(), reason="needs an elevated shell, or Windows would show an admin prompt")
def test_elevation_launcher(sandbox_hosts):
    r = applier(sandbox_hosts, elevate=True).apply(["www.google-analytics.com"], {"31.7.60.154": "cmd.exe"}, [])
    assert r.ok and read_managed_domains(sandbox_hosts) == {"www.google-analytics.com"} and r.fw_added == 1


def test_block_store_add_reload_undo(sandbox_hosts):
    path = sandbox_hosts.parent / "blocks.json"
    st = BlockStore(path, applier(sandbox_hosts))
    r = st.add({"www.google-analytics.com": "chrome.exe", "stats.g.doubleclick.net": "chrome.exe"}, {"31.7.60.154": "cmd.exe"})
    assert r.ok and len(st.entries) == 3
    assert st.add({"www.google-analytics.com": "spotify.exe"}, {}).ok
    assert st.entries["domain:www.google-analytics.com"].apps == ["chrome.exe", "spotify.exe"]

    st2 = BlockStore(path, applier(sandbox_hosts))
    assert set(st2.entries) == set(st.entries)
    r = st2.remove(["ip:31.7.60.154"])
    assert r.ok and r.fw_removed == 1 and "ip:31.7.60.154" not in st2.entries

    sandbox_hosts.write_text(sandbox_hosts.read_text().replace("0.0.0.0 stats.g.doubleclick.net\n", ""))
    inactive = [e["value"] for e in st2.summary()["entries"] if not e["active"]]
    assert inactive == ["stats.g.doubleclick.net"]

    r = st2.remove(None)
    text = sandbox_hosts.read_text()
    assert r.ok and not st2.entries and read_managed_domains(sandbox_hosts) == set()
    assert "my own comment" in text and "netpulse blocks" not in text


def test_warns_about_microsoft_domains(sandbox_hosts):
    r = applier(sandbox_hosts).apply(["v10.events.data.microsoft.com"], {}, [])
    assert r.ok and r.warnings and "Defender" in r.warnings[0]

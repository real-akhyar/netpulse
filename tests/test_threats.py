"""Bundled known-malware lists (URLhaus, HaGeZi TIF, Feodo): load, match, and no false alarms."""

import pytest

from netpulse.detect.threats import ThreatIntel


@pytest.fixture(scope="module")
def ti():
    return ThreatIntel()


def test_lists_load(ti):
    assert len(ti.domains) > 200_000
    assert len(ti.ips) > 30_000


def test_feodo_ip_labelled_with_family(ti):
    hit = ti.match_ip("50.16.16.211")
    assert hit and hit.family == "QakBot"


def test_domain_and_subdomain_match_but_not_lookalikes(ti):
    sample = next(iter(ti.domains))
    assert ti.match_host(sample) is not None
    assert ti.match_host("deep.sub." + sample) is not None
    assert ti.match_host("not" + sample) is None or ("not" + sample) in ti.domains


@pytest.mark.parametrize("host", [
    "www.google.com", "github.com", "raw.githubusercontent.com", "login.microsoftonline.com", "api.anthropic.com",
    "www.youtube.com", "cdn.discordapp.com", "dl.dropboxusercontent.com", "s3.amazonaws.com", "d1.cloudfront.net",
])
def test_popular_domains_not_flagged(ti, host):
    assert ti.match_host(host) is None


@pytest.mark.parametrize("ip", ["142.250.143.138", "8.8.8.8", "1.1.1.1", "160.79.104.10", "20.207.73.82"])
def test_popular_ips_not_flagged(ti, ip):
    assert ti.match_ip(ip) is None

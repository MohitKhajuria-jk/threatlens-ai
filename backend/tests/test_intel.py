import asyncio
import json

import httpx
import pytest

from app.db import Database
from app.intel.feeds import FEEDS, FeedStore, parse_feed
from app.intel.providers import ProviderError, VirusTotal
from app.intel.service import IntelService, combine, indicator_type

FEED_TEXT = {
    "lists.blocklist.de": "# comment\n45.10.20.30\n45.10.20.31\nnot-an-ip\n",
    "cinsscore.com": "103.1.2.3\n",
    "rules.emergingthreats.net": "91.200.1.1\n",
    "www.spamhaus.org": '{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}\n{"cidr":"2.56.192.0/22","sblid":"SBL459831","rir":"ripencc"}\n{"type":"metadata","timestamp":1793952000}\n',
    "check.torproject.org": "185.220.101.5\n",
}


def feed_transport(calls: list[str]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.host)
        return httpx.Response(200, text=FEED_TEXT[request.url.host])
    return httpx.MockTransport(handler)


def test_parse_feed_formats():
    spamhaus = next(f for f in FEEDS if f.id == "spamhaus_drop")
    ips, nets = parse_feed(spamhaus, FEED_TEXT["www.spamhaus.org"])
    assert not ips and [str(n) for n in nets] == ["1.10.16.0/20", "2.56.192.0/22"]
    plain = next(f for f in FEEDS if f.id == "blocklist_de")
    ips, nets = parse_feed(plain, FEED_TEXT["lists.blocklist.de"])
    assert ips == {"45.10.20.30", "45.10.20.31"} and not nets


def test_feed_refresh_lookup_and_polite_intervals(tmp_path):
    calls: list[str] = []
    store = FeedStore(tmp_path)
    http = httpx.AsyncClient(transport=feed_transport(calls))
    assert asyncio.run(store.refresh(http)) == len(FEEDS)
    hits = store.lookup("1.10.20.5")  # inside a Spamhaus DROP network
    assert [h["feed"] for h in hits] == ["spamhaus_drop"]
    assert [h["verdict"] for h in store.lookup("185.220.101.5")] == ["suspicious"]
    assert store.lookup("8.8.8.8") == []
    assert store.lookup("203.0.113.45")[0]["demo"] is True
    # A second refresh within the hour downloads nothing, even when forced.
    assert asyncio.run(store.refresh(http, force=True)) == 0 and len(calls) == len(FEEDS)
    # Cached copies load from disk on restart.
    again = FeedStore(tmp_path)
    assert again.lookup("45.10.20.30")[0]["feed"] == "blocklist_de"
    assert {r["id"]: r["entries"] for r in again.status()}["spamhaus_drop"] == 2


def test_failed_feed_is_recorded_not_raised(tmp_path):
    def handler(request):
        return httpx.Response(503) if "spamhaus" in request.url.host else httpx.Response(200, text=FEED_TEXT[request.url.host])
    store = FeedStore(tmp_path)
    updated = asyncio.run(store.refresh(httpx.AsyncClient(transport=httpx.MockTransport(handler))))
    assert updated == len(FEEDS) - 1
    status = {r["id"]: r for r in store.status()}
    assert "Couldn't download" in status["spamhaus_drop"]["error"] and status["blocklist_de"]["error"] is None


def test_combine_verdicts():
    assert combine([], None, None)[0] == "unknown"
    assert combine([], {"score": 0, "reports": 0}, None)[0] == "clean"
    assert combine([], {"score": 40, "reports": 3}, None)[0] == "suspicious"
    assert combine([{"verdict": "suspicious", "name": "Tor", "category": "exit"}], {"score": 90, "reports": 50}, None)[0] == "malicious"
    assert combine([], None, {"found": True, "malicious": 5, "suspicious": 0})[0] == "malicious"
    level, reasons = combine([{"verdict": "malicious", "name": "X", "category": "bad"}], None, None)
    assert level == "malicious" and "Listed by X" in reasons[0]


def test_indicator_types():
    assert indicator_type("8.8.8.8") == "ip" and indicator_type("2001:db8::1") == "ip"
    assert indicator_type("evil.example.com") == "domain"
    assert indicator_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"
    assert indicator_type("hello") is None


def provider_service(tmp_path, settings, handler):
    settings.abuseipdb_api_key = "abuse-key"
    settings.virustotal_api_key = "vt-key"
    db = Database(tmp_path / "intel.db")
    return IntelService(settings, db, httpx.AsyncClient(transport=httpx.MockTransport(handler)))


def test_lookup_uses_apis_caches_and_never_sends_private_or_example_ips(tmp_path, settings):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if "abuseipdb" in request.url.host:
            assert request.headers["Key"] == "abuse-key"
            return httpx.Response(200, json={"data": {"abuseConfidenceScore": 100, "totalReports": 812, "countryCode": "NL", "isp": "Bad Hosting", "usageType": "Data Center/Web Hosting/Transit", "isTor": False}})
        assert request.headers["x-apikey"] == "vt-key"
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 50, "undetected": 20}, "as_owner": "Bad Hosting"}}})

    intel = provider_service(tmp_path, settings, handler)
    result = asyncio.run(intel.lookup("45.10.20.30"))
    assert result["verdict"] == "malicious" and result["abuseipdb"]["score"] == 100 and result["virustotal"]["malicious"] == 12
    assert len(seen) == 2
    asyncio.run(intel.lookup("45.10.20.30"))
    assert len(seen) == 2  # served from the cache
    for private in ("10.0.0.5", "203.0.113.45", "update-check.example"):
        r = asyncio.run(intel.lookup(private))
        assert r["abuseipdb"] is None and r["virustotal"] is None
    assert len(seen) == 2
    assert asyncio.run(intel.lookup("203.0.113.45"))["verdict"] == "malicious"  # the demo feed still answers
    with pytest.raises(ValueError):
        asyncio.run(intel.lookup("not an indicator"))


def test_provider_errors_are_friendly(tmp_path, settings):
    def handler(request):
        return httpx.Response(401) if "abuseipdb" in request.url.host else httpx.Response(404)
    intel = provider_service(tmp_path, settings, handler)
    result = asyncio.run(intel.lookup("45.10.20.30"))
    assert "rejected the API key" in result["errors"]["abuseipdb"]
    assert result["virustotal"] == {"found": False, "link": "https://www.virustotal.com/gui/ip-address/45.10.20.30"}


def test_virustotal_rate_limit_is_enforced_locally():
    vt = VirusTotal("k", httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))))
    for i in range(4):
        asyncio.run(vt.lookup("ip", f"45.0.0.{i}"))
    with pytest.raises(ProviderError, match="4 lookups a minute"):
        asyncio.run(vt.lookup("ip", "45.0.0.9"))


def test_enrich_checks_only_public_ips_up_to_the_limit(tmp_path, settings):
    checked = []

    def handler(request):
        checked.append(request.url.params["ipAddress"])
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 10}})
    intel = provider_service(tmp_path, settings, handler)
    intel.settings.abuseipdb_max_per_analysis = 2
    done = asyncio.run(intel.enrich(["10.0.0.1", "203.0.113.5", "45.1.1.1", "45.1.1.2", "45.1.1.3"]))
    assert done == 2 and checked == ["45.1.1.1", "45.1.1.2"]
    assert json.dumps(intel.status()["feeds"])  # serialisable

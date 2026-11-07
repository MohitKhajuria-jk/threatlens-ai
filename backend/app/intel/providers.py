"""Optional reputation APIs: AbuseIPDB (IPs) and VirusTotal (IPs, domains, file hashes).

Both have free keys. Limits: AbuseIPDB 1,000 checks a day; VirusTotal's public API
4 requests a minute and 500 a day, and it must not be used in commercial products.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any

import httpx


class ProviderError(Exception):
    """A lookup problem with a message that can be shown to the user."""


def _get_error(r: httpx.Response, name: str) -> ProviderError:
    if r.status_code in (401, 403):
        return ProviderError(f"{name} rejected the API key. Check it in backend/.env.")
    if r.status_code == 429:
        return ProviderError(f"{name}'s rate limit was reached. Try again later.")
    return ProviderError(f"{name} returned an error ({r.status_code}).")


class AbuseIPDB:
    name = "AbuseIPDB"

    def __init__(self, api_key: str, http: httpx.AsyncClient):
        self.api_key = api_key
        self.http = http

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    async def check(self, ip: str) -> dict[str, Any]:
        try:
            r = await self.http.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                                    headers={"Key": self.api_key, "Accept": "application/json"}, timeout=httpx.Timeout(15.0, connect=10.0))
        except httpx.HTTPError as err:
            raise ProviderError("Couldn't reach AbuseIPDB. Check your internet connection.") from err
        if r.status_code != 200:
            raise _get_error(r, self.name)
        d = r.json().get("data", {})
        return {
            "score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"), "country": d.get("countryCode"),
            "isp": d.get("isp"), "usage": d.get("usageType"), "domain": d.get("domain"), "is_tor": d.get("isTor"),
            "whitelisted": d.get("isWhitelisted"), "last_reported": d.get("lastReportedAt"), "link": f"https://www.abuseipdb.com/check/{ip}",
        }


class VirusTotal:
    name = "VirusTotal"
    PER_MINUTE = 4
    PATHS = {"ip": ("ip_addresses", "ip-address"), "domain": ("domains", "domain"), "hash": ("files", "file")}

    def __init__(self, api_key: str, http: httpx.AsyncClient):
        self.api_key = api_key
        self.http = http
        self.calls: deque[float] = deque()

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def wait_seconds(self) -> int:
        now = time.time()
        while self.calls and now - self.calls[0] > 60:
            self.calls.popleft()
        return 0 if len(self.calls) < self.PER_MINUTE else int(61 - (now - self.calls[0]))

    async def lookup(self, kind: str, value: str) -> dict[str, Any]:
        wait = self.wait_seconds()
        if wait:
            raise ProviderError(f"VirusTotal allows 4 lookups a minute on a free key. Try again in {wait} s.")
        api_path, gui_path = self.PATHS[kind]
        self.calls.append(time.time())
        try:
            r = await self.http.get(f"https://www.virustotal.com/api/v3/{api_path}/{value}", headers={"x-apikey": self.api_key},
                                    timeout=httpx.Timeout(20.0, connect=10.0))
        except httpx.HTTPError as err:
            raise ProviderError("Couldn't reach VirusTotal. Check your internet connection.") from err
        link = f"https://www.virustotal.com/gui/{gui_path}/{value}"
        if r.status_code == 404:
            return {"found": False, "link": link}
        if r.status_code != 200:
            raise _get_error(r, self.name)
        a = r.json().get("data", {}).get("attributes", {})
        stats = a.get("last_analysis_stats", {})
        return {
            "found": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0), "reputation": a.get("reputation"), "owner": a.get("as_owner") or a.get("registrar"),
            "country": a.get("country"), "name": a.get("meaningful_name"), "type": a.get("type_description"), "link": link,
        }

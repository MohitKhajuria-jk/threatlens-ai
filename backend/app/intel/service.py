"""Looks up IPs, domains and file hashes against the feeds and the optional APIs, and combines the answers into one verdict."""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from ..config import Settings
from ..db import Database
from ..models import is_documentation, is_internal, parse_ip
from .feeds import FeedStore
from .providers import AbuseIPDB, ProviderError, VirusTotal

log = logging.getLogger("intel")
LEVELS = ["unknown", "clean", "suspicious", "malicious"]
DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
HASH = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)


def indicator_type(value: str) -> str | None:
    value = value.strip()
    if parse_ip(value):
        return "ip"
    if HASH.match(value):
        return "hash"
    if DOMAIN.match(value):
        return "domain"
    return None


def combine(feed_hits: list[dict[str, Any]], abuse: dict[str, Any] | None, vt: dict[str, Any] | None) -> tuple[str, list[str]]:
    level, reasons = "unknown", []
    for hit in feed_hits:
        if LEVELS.index(hit["verdict"]) > LEVELS.index(level):
            level = hit["verdict"]
        reasons.append(f"Listed by {hit['name']}: {hit['category']}")
    if abuse and abuse.get("score") is not None:
        score = abuse["score"]
        reasons.append(f"AbuseIPDB confidence {score}% from {abuse.get('reports') or 0} report(s)")
        if score >= 75:
            level = "malicious"
        elif score >= 25 and LEVELS.index(level) < LEVELS.index("suspicious"):
            level = "suspicious"
        elif score == 0 and level == "unknown":
            level = "clean"
    if vt and vt.get("found"):
        m, s = vt.get("malicious", 0), vt.get("suspicious", 0)
        reasons.append(f"VirusTotal: {m} engine(s) say malicious, {s} suspicious")
        if m >= 3:
            level = "malicious"
        elif (m or s) and LEVELS.index(level) < LEVELS.index("suspicious"):
            level = "suspicious"
        elif not m and not s and level == "unknown":
            level = "clean"
    return level, reasons


class IntelService:
    def __init__(self, settings: Settings, db: Database, http: httpx.AsyncClient):
        self.settings = settings
        self.db = db
        self.http = http
        self.feeds = FeedStore(settings.data_dir / "intel", enabled=settings.intel_feeds_enabled)
        self.abuseipdb = AbuseIPDB(settings.abuseipdb_api_key, http)
        self.virustotal = VirusTotal(settings.virustotal_api_key, http)

    def status(self) -> dict[str, Any]:
        return {"feeds": self.feeds.status(), "feeds_enabled": self.feeds.enabled, "refreshing": self.feeds.refreshing,
                "abuseipdb": self.abuseipdb.configured, "virustotal": self.virustotal.configured}

    def feed_verdict(self, value: str) -> dict[str, Any]:
        hits = self.feeds.lookup(value)
        cached_abuse = self.db.cached_intel(value, "abuseipdb") if parse_ip(value) else None
        cached_vt = self.db.cached_intel(value, "virustotal")
        level, reasons = combine(hits, cached_abuse, cached_vt)
        return {"indicator": value, "verdict": level, "reasons": reasons, "feeds": hits, "abuseipdb": cached_abuse, "virustotal": cached_vt}

    def lookupable(self, value: str) -> bool:
        """Private and reserved example addresses are never sent to outside services."""
        if indicator_type(value) == "ip":
            return not (is_internal(value) or is_documentation(value))
        return not value.lower().endswith((".example", ".test", ".invalid", ".localhost", ".local"))

    async def abuse_check(self, ip: str) -> dict[str, Any] | None:
        if not self.abuseipdb.configured or not self.lookupable(ip):
            return None
        cached = self.db.cached_intel(ip, "abuseipdb")
        if cached:
            return cached
        result = await self.abuseipdb.check(ip)
        self.db.cache_intel(ip, "abuseipdb", result)
        return result

    async def vt_check(self, kind: str, value: str) -> dict[str, Any] | None:
        if not self.virustotal.configured or not self.lookupable(value):
            return None
        cached = self.db.cached_intel(value, "virustotal")
        if cached:
            return cached
        result = await self.virustotal.lookup(kind, value)
        self.db.cache_intel(value, "virustotal", result)
        return result

    async def lookup(self, value: str, live: bool = True) -> dict[str, Any]:
        value = value.strip().lower() if indicator_type(value.strip()) != "ip" else str(parse_ip(value))
        kind = indicator_type(value)
        if not kind:
            raise ValueError("Enter an IP address, a domain name or an MD5, SHA-1 or SHA-256 file hash.")
        errors: dict[str, str] = {}
        abuse = vt = None
        if live and kind == "ip":
            try:
                abuse = await self.abuse_check(value)
            except ProviderError as err:
                errors["abuseipdb"] = str(err)
        if live:
            try:
                vt = await self.vt_check(kind, value)
            except ProviderError as err:
                errors["virustotal"] = str(err)
        abuse = abuse or (self.db.cached_intel(value, "abuseipdb") if kind == "ip" else None)
        vt = vt or self.db.cached_intel(value, "virustotal")
        hits = self.feeds.lookup(value)
        level, reasons = combine(hits, abuse, vt)
        notes = []
        if kind == "ip" and is_internal(value):
            notes.append("This is a private address inside your network, so outside services weren't asked about it.")
        elif kind == "ip" and is_documentation(value):
            notes.append("This is a reserved example address (used by the demo data), so outside services weren't asked about it.")
        if not self.abuseipdb.configured and kind == "ip":
            notes.append("Add ABUSEIPDB_API_KEY to backend/.env for reputation scores.")
        if not self.virustotal.configured:
            notes.append("Add VIRUSTOTAL_API_KEY to backend/.env to check with VirusTotal.")
        return {"indicator": value, "type": kind, "verdict": level, "reasons": reasons, "feeds": hits, "abuseipdb": abuse, "virustotal": vt,
                "errors": errors, "notes": notes}

    async def enrich(self, ips: list[str]) -> int:
        """Checks up to N alert IPs with AbuseIPDB after an analysis (cached for a day)."""
        if not self.abuseipdb.configured:
            return 0
        done = 0
        for ip in [ip for ip in ips if self.lookupable(ip)][: self.settings.abuseipdb_max_per_analysis]:
            try:
                await self.abuse_check(ip)
                done += 1
            except ProviderError as err:
                log.warning("AbuseIPDB lookup stopped: %s", err)
                break
        return done

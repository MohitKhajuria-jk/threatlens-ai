"""Free threat-intelligence feeds (no API key needed), cached on disk.

Each feed is downloaded at most once per its refresh interval, and never more than once
an hour, as the providers ask. Spamhaus asks for credit when DROP is used in a product.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .. import demo_sample
from ..models import parse_ip

log = logging.getLogger("intel.feeds")
USER_AGENT = "ThreatLens-AI/1.0 (local security analysis tool)"
MIN_INTERVAL = 3600


@dataclass(frozen=True)
class Feed:
    id: str
    name: str
    url: str
    kind: str  # ip | cidr | cidr_jsonl
    category: str
    verdict: str  # malicious | suspicious
    refresh_hours: float
    homepage: str


FEEDS = [
    Feed("blocklist_de", "blocklist.de", "https://lists.blocklist.de/lists/all.txt", "ip",
         "Reported for attacks (SSH, web, mail) in the last 48 hours", "malicious", 12, "https://www.blocklist.de/"),
    Feed("cins_army", "CINS Army", "https://cinsscore.com/list/ci-badguys.txt", "ip",
         "Poor reputation in the CINS Army sensor network", "malicious", 12, "https://cinsscore.com/"),
    Feed("et_compromised", "Emerging Threats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "ip",
         "Known compromised hosts", "malicious", 12, "https://rules.emergingthreats.net/"),
    Feed("spamhaus_drop", "Spamhaus DROP", "https://www.spamhaus.org/drop/drop_v4.json", "cidr_jsonl",
         "Hijacked or criminal networks (Spamhaus Don't Route Or Peer list)", "malicious", 24, "https://www.spamhaus.org/drop/"),
    Feed("tor_exits", "Tor exit nodes", "https://check.torproject.org/torbulkexitlist", "ip",
         "Tor exit node: the real sender is hidden", "suspicious", 12, "https://check.torproject.org/"),
]

# Fictional indicators that only appear in the bundled demo logs (reserved example IPs and the .example domain).
DEMO_INDICATORS: dict[str, dict[str, str]] = {
    "203.0.113.45": {"category": "Reported for SSH brute force and web attacks", "verdict": "malicious"},
    "198.51.100.23": {"category": "Reported for Remote Desktop brute force", "verdict": "malicious"},
    "198.51.100.200": {"category": "Malware command-and-control server", "verdict": "malicious"},
    "update-check.example": {"category": "Malware download site", "verdict": "malicious"},
}
for _hash in (demo_sample.SHA256, demo_sample.SHA1, demo_sample.MD5):
    DEMO_INDICATORS[_hash] = {"category": "Remote-access trojan (svc.exe)", "verdict": "malicious"}
DEMO_FEED = {"id": "demo", "name": "ThreatLens demo feed", "category": "Fictional indicators that only match the bundled demo logs", "homepage": None}


def parse_feed(feed: Feed, text: str) -> tuple[set[str], list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    ips: set[str] = set()
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        if feed.kind == "cidr_jsonl":
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and row.get("cidr"):
                try:
                    nets.append(ipaddress.ip_network(row["cidr"], strict=False))
                except ValueError:
                    pass
            continue
        value = line.split()[0].split(";")[0]
        if "/" in value:
            try:
                nets.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                pass
        elif parse_ip(value):
            ips.add(str(parse_ip(value)))
    return ips, nets


class FeedStore:
    def __init__(self, folder: Path, enabled: bool = True):
        self.folder = folder
        self.enabled = enabled
        folder.mkdir(parents=True, exist_ok=True)
        self.ips: dict[str, set[str]] = {}
        self.nets: dict[str, list] = {}
        self.ranges: dict[str, tuple[list[int], list[int]]] = {}
        self.meta: dict[str, dict[str, Any]] = {}
        self.refreshing = False
        for feed in FEEDS:
            self._load(feed)

    def _paths(self, feed: Feed) -> tuple[Path, Path]:
        return self.folder / f"{feed.id}.txt", self.folder / f"{feed.id}.meta.json"

    def _load(self, feed: Feed) -> None:
        data, meta = self._paths(feed)
        try:
            self.meta[feed.id] = json.loads(meta.read_text("utf-8"))
        except (OSError, ValueError):
            self.meta[feed.id] = {}
        try:
            self.ips[feed.id], self.nets[feed.id] = parse_feed(feed, data.read_text("utf-8", errors="replace"))
        except OSError:
            self.ips[feed.id], self.nets[feed.id] = set(), []
        self._index(feed.id)

    def _index(self, feed_id: str) -> None:
        """Sorted IPv4 ranges, so checking an IP against thousands of networks is a binary search."""
        spans = sorted((int(n.network_address), int(n.broadcast_address)) for n in self.nets.get(feed_id, ()) if n.version == 4)
        self.ranges[feed_id] = ([a for a, _ in spans], [b for _, b in spans])

    def stale(self, feed: Feed, force: bool = False) -> bool:
        meta = self.meta.get(feed.id, {})
        age = time.time() - float(meta.get("attempted_at") or 0)
        if age < MIN_INTERVAL:
            return False
        return force or time.time() - float(meta.get("fetched_at") or 0) > feed.refresh_hours * 3600

    async def refresh(self, http: httpx.AsyncClient, force: bool = False) -> int:
        """Downloads stale feeds. Returns how many were updated. Failures are recorded, not raised."""
        if not self.enabled or self.refreshing:
            return 0
        self.refreshing = True
        updated = 0
        try:
            for feed in FEEDS:
                if not self.stale(feed, force):
                    continue
                data_path, meta_path = self._paths(feed)
                meta = dict(self.meta.get(feed.id, {}))
                meta["attempted_at"] = time.time()
                try:
                    r = await http.get(feed.url, headers={"User-Agent": USER_AGENT}, timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=True)
                    r.raise_for_status()
                    ips, nets = parse_feed(feed, r.text)
                    if not ips and not nets:
                        raise ValueError("the download was empty")
                    data_path.write_text(r.text, "utf-8")
                    self.ips[feed.id], self.nets[feed.id] = ips, nets
                    self._index(feed.id)
                    meta.update(fetched_at=time.time(), count=len(ips) + len(nets), error=None)
                    updated += 1
                    log.info("Feed %s updated: %d entries", feed.name, meta["count"])
                except (httpx.HTTPError, ValueError, OSError) as err:
                    meta["error"] = f"Couldn't download: {err}"[:200]
                    log.warning("Feed %s failed: %s", feed.name, err)
                self.meta[feed.id] = meta
                meta_path.write_text(json.dumps(meta), "utf-8")
        finally:
            self.refreshing = False
        return updated

    def lookup(self, value: str) -> list[dict[str, Any]]:
        hits = []
        demo = DEMO_INDICATORS.get(value.lower())
        if demo:
            hits.append({"feed": "demo", "name": DEMO_FEED["name"], "category": demo["category"], "verdict": demo["verdict"], "demo": True})
        ip = parse_ip(value)
        if not ip:
            return hits
        text = str(ip)
        for feed in FEEDS:
            if text in self.ips.get(feed.id, ()) or self._in_ranges(feed.id, ip):
                hits.append({"feed": feed.id, "name": feed.name, "category": feed.category, "verdict": feed.verdict, "demo": False})
        return hits

    def _in_ranges(self, feed_id: str, ip) -> bool:
        if ip.version == 6:
            return any(ip in net for net in self.nets.get(feed_id, ()) if net.version == 6)
        starts, ends = self.ranges.get(feed_id, ([], []))
        value = int(ip)
        i = bisect.bisect_right(starts, value) - 1
        # Networks can be nested, so check a few earlier ranges too.
        return any(starts[j] <= value <= ends[j] for j in range(max(0, i - 3), i + 1)) if i >= 0 else False

    def status(self) -> list[dict[str, Any]]:
        rows = []
        for feed in FEEDS:
            meta = self.meta.get(feed.id, {})
            rows.append({"id": feed.id, "name": feed.name, "url": feed.url, "homepage": feed.homepage, "category": feed.category,
                         "verdict": feed.verdict, "entries": len(self.ips.get(feed.id, ())) + len(self.nets.get(feed.id, ())),
                         "updated_at": meta.get("fetched_at"), "error": meta.get("error"), "enabled": self.enabled})
        rows.append({"id": "demo", "name": DEMO_FEED["name"], "url": None, "homepage": None, "category": DEMO_FEED["category"], "verdict": "malicious",
                     "entries": len(DEMO_INDICATORS), "updated_at": None, "error": None, "enabled": True})
        return rows

"""
VirusTotal v3 API wrapper.

Endpoints used (all free tier):
  GET /api/v3/ip_addresses/{ip}       — IP reputation
  GET /api/v3/domains/{domain}        — Domain reputation
  GET /api/v3/files/{hash}            — File hash reputation

All calls go through virustotal_limiter (4 req/min) before hitting the network.
Results are cached in Redis for 1 hour to preserve daily quota (500 req/day).
"""

import hashlib
import json
import httpx
from dataclasses import dataclass, field
from typing import Optional
from app.core.config import get_settings
from app.core.redis import get_redis
from app.core.rate_limiter import virustotal_limiter

settings = get_settings()

VT_BASE = "https://www.virustotal.com/api/v3"
CACHE_TTL = 3600  # 1 hour


@dataclass
class VTVerdict:
    """Normalised result returned for any IOC type."""
    ioc: str
    ioc_type: str                        # "ip", "domain", "hash"
    malicious: int = 0                   # engines that flagged as malicious
    suspicious: int = 0                  # engines that flagged as suspicious
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    reputation: int = 0                  # VT community reputation score
    tags: list[str] = field(default_factory=list)
    country: Optional[str] = None        # IP only
    as_owner: Optional[str] = None       # IP only
    categories: dict = field(default_factory=dict)  # domain only
    error: Optional[str] = None          # set if the API call failed

    @property
    def risk_score(self) -> int:
        """
        0–100 risk score derived from engine votes.
        Formula: weighted towards malicious votes, capped at 100.
        """
        if self.error or self.total_engines == 0:
            return 0
        base = (self.malicious * 10) + (self.suspicious * 3)
        return min(100, base)

    @property
    def verdict(self) -> str:
        if self.error:
            return "unknown"
        if self.malicious >= 5:
            return "malicious"
        if self.malicious >= 1 or self.suspicious >= 3:
            return "suspicious"
        return "clean"


class VirusTotalService:

    def __init__(self):
        self.headers = {
            "x-apikey": settings.virustotal_api_key,
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def lookup_ip(self, ip: str) -> VTVerdict:
        return await self._lookup(ip, "ip", f"{VT_BASE}/ip_addresses/{ip}")

    async def lookup_domain(self, domain: str) -> VTVerdict:
        return await self._lookup(domain, "domain", f"{VT_BASE}/domains/{domain}")

    async def lookup_hash(self, file_hash: str) -> VTVerdict:
        return await self._lookup(file_hash, "hash", f"{VT_BASE}/files/{file_hash}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _lookup(self, ioc: str, ioc_type: str, url: str) -> VTVerdict:
        # 1. Check Redis cache first — saves quota
        cached = await self._get_cache(ioc)
        if cached:
            return VTVerdict(**cached)

        # 2. Acquire rate-limit slot (blocks if needed, never raises)
        await virustotal_limiter.acquire()

        # 3. Make the API call
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers=self.headers)

                if resp.status_code == 404:
                    verdict = VTVerdict(ioc=ioc, ioc_type=ioc_type,
                                        error="not_found")
                    await self._set_cache(ioc, verdict)
                    return verdict

                if resp.status_code == 429:
                    return VTVerdict(ioc=ioc, ioc_type=ioc_type,
                                     error="rate_limited")

                resp.raise_for_status()
                data = resp.json()

        except httpx.TimeoutException:
            return VTVerdict(ioc=ioc, ioc_type=ioc_type, error="timeout")
        except httpx.HTTPStatusError as e:
            return VTVerdict(ioc=ioc, ioc_type=ioc_type,
                             error=f"http_error_{e.response.status_code}")
        except Exception as e:
            return VTVerdict(ioc=ioc, ioc_type=ioc_type,
                             error=f"unexpected: {str(e)[:80]}")

        # 4. Parse the response into a normalised VTVerdict
        verdict = self._parse(ioc, ioc_type, data)

        # 5. Cache successful results
        await self._set_cache(ioc, verdict)
        return verdict

    def _parse(self, ioc: str, ioc_type: str, data: dict) -> VTVerdict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        verdict = VTVerdict(
            ioc=ioc,
            ioc_type=ioc_type,
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            reputation=attrs.get("reputation", 0),
            tags=attrs.get("tags", []),
        )
        verdict.total_engines = (
            verdict.malicious + verdict.suspicious +
            verdict.harmless + verdict.undetected
        )

        if ioc_type == "ip":
            verdict.country = attrs.get("country")
            verdict.as_owner = attrs.get("as_owner")

        if ioc_type == "domain":
            verdict.categories = attrs.get("categories", {})

        return verdict

    async def _get_cache(self, ioc: str) -> Optional[dict]:
        redis = await get_redis()
        raw = await redis.get(f"vt:{ioc}")
        if raw:
            return json.loads(raw)
        return None

    async def _set_cache(self, ioc: str, verdict: VTVerdict):
        # Don't cache errors — we want to retry those
        if verdict.error and verdict.error not in ("not_found",):
            return
        redis = await get_redis()
        await redis.setex(
            f"vt:{ioc}",
            CACHE_TTL,
            json.dumps(verdict.__dict__),
        )


# Module-level singleton — import and use directly
virustotal = VirusTotalService()

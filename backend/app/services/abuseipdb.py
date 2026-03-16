"""
AbuseIPDB v2 API wrapper.

Endpoints used (free tier):
  GET /api/v2/check    — IP abuse report lookup (1 000 req/day free)
  GET /api/v2/check-block — CIDR block check (used optionally)

All calls go through abuseipdb_limiter before hitting the network.
Results are cached in Redis for 30 minutes (abuse data updates frequently).
"""

import json
import httpx
from dataclasses import dataclass
from typing import Optional
from app.core.config import get_settings
from app.core.redis import get_redis
from app.core.rate_limiter import abuseipdb_limiter

settings = get_settings()

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
CACHE_TTL = 1800  # 30 minutes — abuse scores update more frequently than VT


@dataclass
class AbuseIPDBResult:
    """Normalised result from AbuseIPDB."""
    ip: str
    is_public: bool = True
    ip_version: int = 4
    is_whitelisted: bool = False
    abuse_confidence_score: int = 0      # 0–100, AbuseIPDB's own score
    country_code: Optional[str] = None
    usage_type: Optional[str] = None     # "Data Center/Web Hosting/Transit", etc.
    isp: Optional[str] = None
    domain: Optional[str] = None
    total_reports: int = 0               # all-time reports
    num_distinct_users: int = 0          # unique reporters
    last_reported_at: Optional[str] = None
    error: Optional[str] = None

    @property
    def risk_level(self) -> str:
        """Human-readable risk level derived from confidence score."""
        if self.error:
            return "unknown"
        s = self.abuse_confidence_score
        if s >= 80:
            return "critical"
        if s >= 50:
            return "high"
        if s >= 25:
            return "medium"
        if s >= 5:
            return "low"
        return "clean"

    @property
    def is_suspicious(self) -> bool:
        return self.abuse_confidence_score >= 25 or self.total_reports > 0


class AbuseIPDBService:

    def __init__(self):
        self.headers = {
            "Key": settings.abuseipdb_api_key,
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def check_ip(self, ip: str, max_age_days: int = 90) -> AbuseIPDBResult:
        """
        Look up an IP address.

        max_age_days: only count reports filed within this many days.
        90 days is the recommended default — reduces false positives from
        old, retired malicious IPs.
        """
        cached = await self._get_cache(ip)
        if cached:
            return AbuseIPDBResult(**cached)

        await abuseipdb_limiter.acquire()

        params = {
            "ipAddress": ip,
            "maxAgeInDays": str(max_age_days),
            "verbose": "",          # includes ISP, usage type, domain
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{ABUSEIPDB_BASE}/check",
                    headers=self.headers,
                    params=params,
                )

                if resp.status_code == 422:
                    # Unprocessable — private IP or invalid format
                    result = AbuseIPDBResult(ip=ip, error="invalid_ip")
                    return result

                if resp.status_code == 429:
                    return AbuseIPDBResult(ip=ip, error="rate_limited")

                resp.raise_for_status()
                data = resp.json()

        except httpx.TimeoutException:
            return AbuseIPDBResult(ip=ip, error="timeout")
        except httpx.HTTPStatusError as e:
            return AbuseIPDBResult(ip=ip,
                                   error=f"http_error_{e.response.status_code}")
        except Exception as e:
            return AbuseIPDBResult(ip=ip, error=f"unexpected: {str(e)[:80]}")

        result = self._parse(ip, data)
        await self._set_cache(ip, result)
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse(self, ip: str, data: dict) -> AbuseIPDBResult:
        d = data.get("data", {})
        return AbuseIPDBResult(
            ip=ip,
            is_public=d.get("isPublic", True),
            ip_version=d.get("ipVersion", 4),
            is_whitelisted=d.get("isWhitelisted", False),
            abuse_confidence_score=d.get("abuseConfidenceScore", 0),
            country_code=d.get("countryCode"),
            usage_type=d.get("usageType"),
            isp=d.get("isp"),
            domain=d.get("domain"),
            total_reports=d.get("totalReports", 0),
            num_distinct_users=d.get("numDistinctUsers", 0),
            last_reported_at=d.get("lastReportedAt"),
        )

    async def _get_cache(self, ip: str) -> Optional[dict]:
        redis = await get_redis()
        raw = await redis.get(f"abuseipdb:{ip}")
        if raw:
            return json.loads(raw)
        return None

    async def _set_cache(self, ip: str, result: AbuseIPDBResult):
        if result.error and result.error not in ("invalid_ip",):
            return
        redis = await get_redis()
        await redis.setex(
            f"abuseipdb:{ip}",
            CACHE_TTL,
            json.dumps(result.__dict__),
        )


# Module-level singleton
abuseipdb = AbuseIPDBService()

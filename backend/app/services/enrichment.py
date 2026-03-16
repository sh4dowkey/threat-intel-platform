"""
IOC Enrichment Service — orchestrates all threat intel sources.

This is the single entry point for the rest of the app.
Call enrich_ioc(value) and get back a unified EnrichedIOC regardless
of whether the input is an IP, domain, or file hash.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional
from app.services.virustotal import virustotal, VTVerdict
from app.services.abuseipdb import abuseipdb, AbuseIPDBResult


# ---------------------------------------------------------------------------
# IOC type detection
# ---------------------------------------------------------------------------

IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_ioc_type(value: str) -> str:
    """Return 'ip', 'domain', 'hash', or 'unknown'."""
    v = value.strip()
    if IPV4_RE.match(v):
        return "ip"
    if MD5_RE.match(v) or SHA1_RE.match(v) or SHA256_RE.match(v):
        return "hash"
    if DOMAIN_RE.match(v):
        return "domain"
    return "unknown"


# ---------------------------------------------------------------------------
# Unified result dataclass
# ---------------------------------------------------------------------------

@dataclass
class EnrichedIOC:
    """
    Single unified threat intelligence result combining all sources.
    This is what gets stored in the database and returned to the frontend.
    """
    ioc: str
    ioc_type: str

    # Composite risk score (0–100) combining all sources
    risk_score: int = 0

    # Human-readable overall verdict
    verdict: str = "unknown"           # clean | suspicious | malicious | unknown

    # VirusTotal data
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_total_engines: int = 0
    vt_reputation: int = 0
    vt_tags: list[str] = field(default_factory=list)
    vt_country: Optional[str] = None
    vt_as_owner: Optional[str] = None
    vt_error: Optional[str] = None

    # AbuseIPDB data (IP only)
    abuse_confidence_score: int = 0
    abuse_total_reports: int = 0
    abuse_num_reporters: int = 0
    abuse_isp: Optional[str] = None
    abuse_usage_type: Optional[str] = None
    abuse_last_reported: Optional[str] = None
    abuse_is_whitelisted: bool = False
    abuse_error: Optional[str] = None

    # Metadata
    sources_queried: list[str] = field(default_factory=list)
    enrichment_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# ---------------------------------------------------------------------------
# Enrichment orchestrator
# ---------------------------------------------------------------------------

class EnrichmentService:

    async def enrich(self, ioc_value: str) -> EnrichedIOC:
        """
        Main entry point. Detects IOC type, fans out to relevant sources
        in parallel, then merges and scores the results.
        """
        ioc_value = ioc_value.strip()
        ioc_type = detect_ioc_type(ioc_value)

        result = EnrichedIOC(ioc=ioc_value, ioc_type=ioc_type)

        if ioc_type == "unknown":
            result.verdict = "unknown"
            result.enrichment_errors.append("Could not detect IOC type")
            return result

        if ioc_type == "ip":
            await self._enrich_ip(result)
        elif ioc_type == "domain":
            await self._enrich_domain(result)
        elif ioc_type == "hash":
            await self._enrich_hash(result)

        self._calculate_composite_score(result)
        return result

    # ------------------------------------------------------------------
    # Per-type enrichment methods
    # ------------------------------------------------------------------

    async def _enrich_ip(self, result: EnrichedIOC):
        """Fan out VT + AbuseIPDB in parallel for IP lookups."""
        vt_task = asyncio.create_task(virustotal.lookup_ip(result.ioc))
        abuse_task = asyncio.create_task(abuseipdb.check_ip(result.ioc))

        vt_result, abuse_result = await asyncio.gather(
            vt_task, abuse_task, return_exceptions=True
        )

        if isinstance(vt_result, Exception):
            result.enrichment_errors.append(f"VT exception: {vt_result}")
        else:
            self._apply_vt(result, vt_result)

        if isinstance(abuse_result, Exception):
            result.enrichment_errors.append(f"AbuseIPDB exception: {abuse_result}")
        else:
            self._apply_abuse(result, abuse_result)

    async def _enrich_domain(self, result: EnrichedIOC):
        """Domains only go to VirusTotal (AbuseIPDB is IP-only)."""
        vt_result = await virustotal.lookup_domain(result.ioc)
        self._apply_vt(result, vt_result)

    async def _enrich_hash(self, result: EnrichedIOC):
        """Hashes only go to VirusTotal."""
        vt_result = await virustotal.lookup_hash(result.ioc)
        self._apply_vt(result, vt_result)

    # ------------------------------------------------------------------
    # Result merging helpers
    # ------------------------------------------------------------------

    def _apply_vt(self, result: EnrichedIOC, vt: VTVerdict):
        result.sources_queried.append("virustotal")
        result.vt_malicious = vt.malicious
        result.vt_suspicious = vt.suspicious
        result.vt_harmless = vt.harmless
        result.vt_total_engines = vt.total_engines
        result.vt_reputation = vt.reputation
        result.vt_tags = vt.tags
        result.vt_country = vt.country
        result.vt_as_owner = vt.as_owner
        result.vt_error = vt.error
        if vt.error:
            result.enrichment_errors.append(f"VT: {vt.error}")

    def _apply_abuse(self, result: EnrichedIOC, abuse: AbuseIPDBResult):
        result.sources_queried.append("abuseipdb")
        result.abuse_confidence_score = abuse.abuse_confidence_score
        result.abuse_total_reports = abuse.total_reports
        result.abuse_num_reporters = abuse.num_distinct_users
        result.abuse_isp = abuse.isp
        result.abuse_usage_type = abuse.usage_type
        result.abuse_last_reported = abuse.last_reported_at
        result.abuse_is_whitelisted = abuse.is_whitelisted
        result.abuse_error = abuse.error
        if abuse.error:
            result.enrichment_errors.append(f"AbuseIPDB: {abuse.error}")

    # ------------------------------------------------------------------
    # Composite scoring
    # ------------------------------------------------------------------

    def _calculate_composite_score(self, result: EnrichedIOC):
        """
        Combine signals from all sources into a single 0–100 risk score.

        Weights:
          - VT malicious engine votes: 10 pts each (dominant signal)
          - VT suspicious votes:        3 pts each
          - AbuseIPDB confidence:       up to 40 pts (scaled)
          - VT negative reputation:     up to 10 pts
        """
        score = 0

        # VirusTotal signals
        score += result.vt_malicious * 10
        score += result.vt_suspicious * 3
        if result.vt_reputation < 0:
            score += min(10, abs(result.vt_reputation) // 5)

        # AbuseIPDB signal (only for IPs)
        if result.ioc_type == "ip" and not result.abuse_error:
            # Scale 0–100 confidence → 0–40 score contribution
            score += int(result.abuse_confidence_score * 0.4)

        result.risk_score = min(100, score)

        # Derive verdict from final score
        if result.risk_score >= 70:
            result.verdict = "malicious"
        elif result.risk_score >= 30:
            result.verdict = "suspicious"
        elif len(result.sources_queried) == 0:
            result.verdict = "unknown"
        else:
            result.verdict = "clean"


# Module-level singleton
enrichment_service = EnrichmentService()

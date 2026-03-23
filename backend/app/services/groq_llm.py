"""
Groq LLM Service — Alert Explanation + MITRE ATT&CK Mapping

For every alert this service generates:
  1. Plain-English explanation of what the attack is doing
  2. MITRE ATT&CK tactic + technique mapping
  3. Recommended analyst action
  4. Severity justification

Results are cached in Redis by alert fingerprint — same alert type
with similar features always returns the same explanation instantly
without burning Groq quota.
"""

import json
import hashlib
import httpx
from dataclasses import dataclass, field
from typing import Optional

from app.core.config import get_settings
from app.core.redis import get_redis
from app.core.rate_limiter import groq_limiter

settings = get_settings()

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
CACHE_TTL = 86400  # 24 hours — explanations for the same alert type don't change


@dataclass
class MITREMapping:
    tactic_id: str        # e.g. "TA0040"
    tactic_name: str      # e.g. "Impact"
    technique_id: str     # e.g. "T1498"
    technique_name: str   # e.g. "Network Denial of Service"
    technique_url: str    # direct link to attack.mitre.org


@dataclass
class AlertExplanation:
    # Plain English
    summary: str                    # 1-sentence TL;DR
    what_is_happening: str          # 2-3 sentences: what the attack does
    why_flagged: str                # explains which features triggered it
    potential_impact: str           # what happens if this goes unchecked

    # MITRE mapping
    mitre: MITREMapping

    # Analyst guidance
    severity: str                   # critical / high / medium / low
    recommended_action: str         # what the analyst should do next
    false_positive_likelihood: str  # low / medium / high + reason

    # Meta
    cached: bool = False
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# MITRE ATT&CK static mapping
# Maps CICIDS2017 attack class names → MITRE tactic + technique
# ---------------------------------------------------------------------------

MITRE_MAPPINGS: dict[str, MITREMapping] = {
    "DDoS": MITREMapping(
        tactic_id="TA0040", tactic_name="Impact",
        technique_id="T1498", technique_name="Network Denial of Service",
        technique_url="https://attack.mitre.org/techniques/T1498/",
    ),
    "DoS Hulk": MITREMapping(
        tactic_id="TA0040", tactic_name="Impact",
        technique_id="T1499", technique_name="Endpoint Denial of Service",
        technique_url="https://attack.mitre.org/techniques/T1499/",
    ),
    "DoS GoldenEye": MITREMapping(
        tactic_id="TA0040", tactic_name="Impact",
        technique_id="T1499", technique_name="Endpoint Denial of Service",
        technique_url="https://attack.mitre.org/techniques/T1499/",
    ),
    "DoS slowloris": MITREMapping(
        tactic_id="TA0040", tactic_name="Impact",
        technique_id="T1499.001", technique_name="OS Exhaustion Flood",
        technique_url="https://attack.mitre.org/techniques/T1499/001/",
    ),
    "DoS Slowhttptest": MITREMapping(
        tactic_id="TA0040", tactic_name="Impact",
        technique_id="T1499.001", technique_name="OS Exhaustion Flood",
        technique_url="https://attack.mitre.org/techniques/T1499/001/",
    ),
    "PortScan": MITREMapping(
        tactic_id="TA0043", tactic_name="Reconnaissance",
        technique_id="T1046", technique_name="Network Service Discovery",
        technique_url="https://attack.mitre.org/techniques/T1046/",
    ),
    "FTP-Patator": MITREMapping(
        tactic_id="TA0006", tactic_name="Credential Access",
        technique_id="T1110.001", technique_name="Brute Force: Password Guessing",
        technique_url="https://attack.mitre.org/techniques/T1110/001/",
    ),
    "SSH-Patator": MITREMapping(
        tactic_id="TA0006", tactic_name="Credential Access",
        technique_id="T1110.001", technique_name="Brute Force: Password Guessing",
        technique_url="https://attack.mitre.org/techniques/T1110/001/",
    ),
    "Bot": MITREMapping(
        tactic_id="TA0011", tactic_name="Command and Control",
        technique_id="T1071", technique_name="Application Layer Protocol",
        technique_url="https://attack.mitre.org/techniques/T1071/",
    ),
    "Web Attack - Brute Force": MITREMapping(
        tactic_id="TA0006", tactic_name="Credential Access",
        technique_id="T1110.001", technique_name="Brute Force: Password Guessing",
        technique_url="https://attack.mitre.org/techniques/T1110/001/",
    ),
    "Web Attack - XSS": MITREMapping(
        tactic_id="TA0002", tactic_name="Execution",
        technique_id="T1059.007", technique_name="JavaScript",
        technique_url="https://attack.mitre.org/techniques/T1059/007/",
    ),
    "Web Attack - Sql Injection": MITREMapping(
        tactic_id="TA0006", tactic_name="Credential Access",
        technique_id="T1190", technique_name="Exploit Public-Facing Application",
        technique_url="https://attack.mitre.org/techniques/T1190/",
    ),
    "Infiltration": MITREMapping(
        tactic_id="TA0001", tactic_name="Initial Access",
        technique_id="T1566", technique_name="Phishing",
        technique_url="https://attack.mitre.org/techniques/T1566/",
    ),
    "Heartbleed": MITREMapping(
        tactic_id="TA0006", tactic_name="Credential Access",
        technique_id="T1190", technique_name="Exploit Public-Facing Application",
        technique_url="https://attack.mitre.org/techniques/T1190/",
    ),
    # Fallback for unknown attack types
    "UNKNOWN": MITREMapping(
        tactic_id="TA0043", tactic_name="Reconnaissance",
        technique_id="T1595", technique_name="Active Scanning",
        technique_url="https://attack.mitre.org/techniques/T1595/",
    ),
}


def get_mitre_mapping(attack_class: str) -> MITREMapping:
    """Fuzzy match attack class name to MITRE mapping."""
    # Exact match first
    if attack_class in MITRE_MAPPINGS:
        return MITRE_MAPPINGS[attack_class]

    # Normalised match (handle encoding issues in CICIDS2017 labels)
    normalised = attack_class.replace("\ufffd", "-").replace("â€", "-").strip()
    for key in MITRE_MAPPINGS:
        if key.lower() in normalised.lower() or normalised.lower() in key.lower():
            return MITRE_MAPPINGS[key]

    return MITRE_MAPPINGS["UNKNOWN"]


# ---------------------------------------------------------------------------
# Groq LLM Service
# ---------------------------------------------------------------------------

class GroqLLMService:

    def __init__(self):
        self.headers = {
            "Authorization": f"Bearer {settings.groq_api_key}",
            "Content-Type": "application/json",
        }

    async def explain_alert(
        self,
        attack_class: str,
        risk_score: int,
        anomaly_score: float,
        top_features: list[dict],
        ioc: Optional[str] = None,
        ioc_context: Optional[dict] = None,
    ) -> AlertExplanation:
        """
        Generate a full alert explanation.

        Checks Redis cache first — same attack type + risk bucket
        always returns the cached explanation to save Groq quota.
        """
        mitre = get_mitre_mapping(attack_class)

        # Cache key: attack type + risk bucket (low/med/high/critical)
        # We bucket risk score so similar alerts share a cache entry
        risk_bucket = (
            "critical" if risk_score >= 70
            else "high" if risk_score >= 50
            else "medium" if risk_score >= 30
            else "low"
        )
        cache_key = f"llm:explain:{attack_class}:{risk_bucket}"
        cache_key = hashlib.md5(cache_key.encode()).hexdigest()

        cached = await self._get_cache(cache_key)
        if cached:
            cached["cached"] = True
            cached["mitre"] = MITREMapping(**cached["mitre"])
            return AlertExplanation(**cached)

        # Build the LLM prompt
        feature_summary = self._format_features(top_features)
        ioc_line = f"Source IOC: {ioc}" if ioc else ""
        ioc_ctx = ""
        if ioc_context:
            vt_mal = ioc_context.get("vt_malicious", 0)
            abuse = ioc_context.get("abuse_confidence_score", 0)
            if vt_mal > 0 or abuse > 0:
                ioc_ctx = (
                    f"Threat intel context: VirusTotal flagged by {vt_mal} engines, "
                    f"AbuseIPDB confidence score {abuse}/100."
                )

        prompt = f"""You are a senior SOC analyst. Analyze this network security alert and respond ONLY with a JSON object.

Alert Details:
- Attack Classification: {attack_class}
- Risk Score: {risk_score}/100
- Anomaly Score: {anomaly_score:.2f}/1.0
- MITRE ATT&CK: {mitre.tactic_name} > {mitre.technique_name} ({mitre.technique_id})
{ioc_line}
{ioc_ctx}

Top contributing network features:
{feature_summary}

Respond with ONLY this JSON structure, no other text:
{{
  "summary": "One sentence TL;DR of what this alert means",
  "what_is_happening": "2-3 sentences explaining what the attacker is doing and how this attack works technically",
  "why_flagged": "1-2 sentences explaining which specific network features triggered this alert and why they are suspicious",
  "potential_impact": "1-2 sentences on what damage could occur if this is a real attack and goes unaddressed",
  "severity": "critical|high|medium|low",
  "recommended_action": "Specific actionable steps the analyst should take right now, in order",
  "false_positive_likelihood": "low|medium|high — followed by a brief reason why"
}}"""

        await groq_limiter.acquire()

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(
                    GROQ_API_URL,
                    headers=self.headers,
                    json={
                        "model": settings.groq_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.3,    # low temp = consistent, factual
                        "max_tokens": 600,
                        "response_format": {"type": "json_object"},
                    },
                )

                if resp.status_code == 429:
                    return self._fallback_explanation(
                        attack_class, risk_score, mitre, "rate_limited"
                    )

                resp.raise_for_status()
                data = resp.json()

        except httpx.TimeoutException:
            return self._fallback_explanation(
                attack_class, risk_score, mitre, "timeout"
            )
        except Exception as e:
            return self._fallback_explanation(
                attack_class, risk_score, mitre, str(e)[:80]
            )

        # Parse LLM response
        try:
            raw = data["choices"][0]["message"]["content"]
            parsed = json.loads(raw)
        except (KeyError, json.JSONDecodeError) as e:
            return self._fallback_explanation(
                attack_class, risk_score, mitre, f"parse_error: {e}"
            )

        explanation = AlertExplanation(
            summary=parsed.get("summary", ""),
            what_is_happening=parsed.get("what_is_happening", ""),
            why_flagged=parsed.get("why_flagged", ""),
            potential_impact=parsed.get("potential_impact", ""),
            mitre=mitre,
            severity=parsed.get("severity", risk_bucket),
            recommended_action=parsed.get("recommended_action", ""),
            false_positive_likelihood=parsed.get("false_positive_likelihood", ""),
        )

        # Cache it
        await self._set_cache(cache_key, explanation)
        return explanation

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _format_features(self, top_features: list[dict]) -> str:
        if not top_features:
            return "  (no feature data available)"
        lines = []
        for f in top_features[:5]:
            name = f.get("feature", "unknown").replace("_", " ")
            importance = f.get("importance", 0)
            value = f.get("value", 0)
            lines.append(f"  - {name}: value={value:.2f}, importance={importance:.4f}")
        return "\n".join(lines)

    def _fallback_explanation(
        self,
        attack_class: str,
        risk_score: int,
        mitre: MITREMapping,
        error: str,
    ) -> AlertExplanation:
        """
        Returns a static explanation when Groq is unavailable.
        Keeps the API working even without LLM access.
        """
        severity = (
            "critical" if risk_score >= 70
            else "high" if risk_score >= 50
            else "medium" if risk_score >= 30
            else "low"
        )
        return AlertExplanation(
            summary=f"Detected {attack_class} activity with risk score {risk_score}/100.",
            what_is_happening=(
                f"The system detected network traffic patterns consistent with {attack_class}. "
                f"This maps to MITRE ATT&CK {mitre.tactic_name} ({mitre.tactic_id})."
            ),
            why_flagged="Anomalous network flow features exceeded detection thresholds.",
            potential_impact="Potential service disruption or unauthorized access if unaddressed.",
            mitre=mitre,
            severity=severity,
            recommended_action=(
                "1. Verify the source IP against threat intel feeds. "
                "2. Check firewall logs for related activity. "
                "3. Isolate affected hosts if confirmed malicious."
            ),
            false_positive_likelihood=f"medium — LLM unavailable ({error}), using static template",
            error=error,
        )

    async def _get_cache(self, key: str) -> Optional[dict]:
        redis = await get_redis()
        raw = await redis.get(f"groq:{key}")
        if raw:
            return json.loads(raw)
        return None

    async def _set_cache(self, key: str, explanation: AlertExplanation):
        redis = await get_redis()
        data = explanation.__dict__.copy()
        data["mitre"] = explanation.mitre.__dict__
        await redis.setex(f"groq:{key}", CACHE_TTL, json.dumps(data))


# Module-level singleton
groq_service = GroqLLMService()

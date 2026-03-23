"""
Alerts API — the centrepiece endpoint of the platform.

POST /api/alerts/analyze   — score a flow + generate LLM explanation
GET  /api/alerts           — list recent alerts from DB
GET  /api/alerts/{id}      — get a single alert with full explanation
PATCH /api/alerts/{id}     — acknowledge / escalate / dismiss an alert
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Optional
from datetime import datetime, timezone

from app.core.database import get_db
from app.models.alert import Alert
from app.services.ml_service import ml_service
from app.services.groq_llm import groq_service
from app.services.enrichment import enrichment_service, detect_ioc_type

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    features: dict[str, float]
    source_ip: Optional[str] = None      # if provided, also runs IOC enrichment
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None


class MITREResponse(BaseModel):
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    technique_url: str


class AlertResponse(BaseModel):
    id: int
    source_ip: Optional[str]
    destination_ip: Optional[str]
    destination_port: Optional[int]

    # ML scores
    risk_score: int
    verdict: str
    attack_class: str
    attack_confidence: float
    anomaly_score: float
    is_anomaly: bool

    # LLM explanation
    summary: str
    what_is_happening: str
    why_flagged: str
    potential_impact: str
    recommended_action: str
    false_positive_likelihood: str
    severity: str
    explanation_cached: bool

    # MITRE
    mitre: MITREResponse

    # Top features
    top_features: list[dict]

    # Analyst workflow
    status: str          # open | acknowledged | escalated | dismissed
    created_at: datetime

    class Config:
        from_attributes = True


class AlertListItem(BaseModel):
    id: int
    source_ip: Optional[str]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    risk_score: int
    verdict: str
    attack_class: str
    severity: str
    summary: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class UpdateAlertRequest(BaseModel):
    status: str   # acknowledged | escalated | dismissed


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/analyze",
    response_model=AlertResponse,
    summary="Analyze a network flow — ML score + LLM explanation",
)
async def analyze_flow(
    request: AnalyzeRequest,
    db: AsyncSession = Depends(get_db),
):
    # ── 1. ML scoring
    prediction = ml_service.score(request.features)

    # ── 2. IOC enrichment (only if source IP provided and attack detected)
    ioc_context = None
    if request.source_ip and prediction.verdict != "clean":
        try:
            ioc_type = detect_ioc_type(request.source_ip)
            if ioc_type == "ip":
                enriched = await enrichment_service.enrich(request.source_ip)
                ioc_context = {
                    "vt_malicious": enriched.vt_malicious,
                    "abuse_confidence_score": enriched.abuse_confidence_score,
                }
        except Exception:
            pass  # IOC enrichment is best-effort

    # ── 3. LLM explanation (only for non-clean verdicts)
    if prediction.verdict != "clean":
        explanation = await groq_service.explain_alert(
            attack_class=prediction.attack_class,
            risk_score=prediction.combined_risk_score,
            anomaly_score=prediction.anomaly_score,
            top_features=prediction.shap_explanation,
            ioc=request.source_ip,
            ioc_context=ioc_context,
        )
    else:
        # Clean traffic — use minimal static explanation, don't burn Groq quota
        from app.services.groq_llm import get_mitre_mapping, MITREMapping
        mitre = get_mitre_mapping("UNKNOWN")
        from app.services.groq_llm import AlertExplanation
        explanation = AlertExplanation(
            summary="Traffic appears normal. No attack patterns detected.",
            what_is_happening="This flow matches the profile of benign network traffic.",
            why_flagged="No suspicious features exceeded detection thresholds.",
            potential_impact="None — traffic classified as benign.",
            mitre=mitre,
            severity="low",
            recommended_action="No action required. Monitor for changes.",
            false_positive_likelihood="low — clean verdict from both models",
        )

    # ── 4. Save alert to database
    alert = Alert(
        source_ip=request.source_ip,
        destination_ip=request.destination_ip,
        destination_port=request.destination_port,
        risk_score=prediction.combined_risk_score,
        verdict=prediction.verdict,
        attack_class=prediction.attack_class,
        attack_confidence=prediction.attack_confidence,
        anomaly_score=prediction.anomaly_score,
        is_anomaly=prediction.is_anomaly,
        summary=explanation.summary,
        what_is_happening=explanation.what_is_happening,
        why_flagged=explanation.why_flagged,
        potential_impact=explanation.potential_impact,
        recommended_action=explanation.recommended_action,
        false_positive_likelihood=explanation.false_positive_likelihood,
        severity=explanation.severity,
        explanation_cached=explanation.cached,
        mitre_tactic_id=explanation.mitre.tactic_id,
        mitre_tactic_name=explanation.mitre.tactic_name,
        mitre_technique_id=explanation.mitre.technique_id,
        mitre_technique_name=explanation.mitre.technique_name,
        mitre_technique_url=explanation.mitre.technique_url,
        top_features=prediction.shap_explanation,
        status="open",
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)

    return _to_response(alert)


@router.get(
    "",
    response_model=list[AlertListItem],
    summary="List recent alerts",
)
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    verdict: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Alert).order_by(desc(Alert.created_at)).limit(limit)
    if verdict:
        stmt = stmt.where(Alert.verdict == verdict)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if status:
        stmt = stmt.where(Alert.status == status)

    result = await db.execute(stmt)
    alerts = result.scalars().all()
    return [_to_list_item(a) for a in alerts]


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get a single alert with full explanation",
)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert not found")
    return _to_response(alert)


@router.patch(
    "/{alert_id}",
    response_model=AlertListItem,
    summary="Update alert status (acknowledge / escalate / dismiss)",
)
async def update_alert(
    alert_id: int,
    body: UpdateAlertRequest,
    db: AsyncSession = Depends(get_db),
):
    valid_statuses = {"acknowledged", "escalated", "dismissed", "open"}
    if body.status not in valid_statuses:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=422,
            detail=f"status must be one of: {valid_statuses}",
        )

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = body.status
    await db.commit()
    await db.refresh(alert)
    return _to_list_item(alert)


# ---------------------------------------------------------------------------
# Helper: model → response schema
# ---------------------------------------------------------------------------

def _to_response(alert: "Alert") -> AlertResponse:
    return AlertResponse(
        id=alert.id,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        destination_port=alert.destination_port,
        risk_score=alert.risk_score,
        verdict=alert.verdict,
        attack_class=alert.attack_class,
        attack_confidence=alert.attack_confidence,
        anomaly_score=alert.anomaly_score,
        is_anomaly=alert.is_anomaly,
        summary=alert.summary,
        what_is_happening=alert.what_is_happening,
        why_flagged=alert.why_flagged,
        potential_impact=alert.potential_impact,
        recommended_action=alert.recommended_action,
        false_positive_likelihood=alert.false_positive_likelihood,
        severity=alert.severity,
        explanation_cached=alert.explanation_cached,
        mitre=MITREResponse(
            tactic_id=alert.mitre_tactic_id,
            tactic_name=alert.mitre_tactic_name,
            technique_id=alert.mitre_technique_id,
            technique_name=alert.mitre_technique_name,
            technique_url=alert.mitre_technique_url,
        ),
        top_features=alert.top_features or [],
        status=alert.status,
        created_at=alert.created_at,
    )


def _to_list_item(alert: "Alert") -> AlertListItem:
    return AlertListItem(
        id=alert.id,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        destination_port=alert.destination_port,
        risk_score=alert.risk_score,
        verdict=alert.verdict,
        attack_class=alert.attack_class,
        severity=alert.severity,
        summary=alert.summary,
        status=alert.status,
        created_at=alert.created_at,
    )

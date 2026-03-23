"""
ML Scoring API endpoints.

POST /api/ml/score         — score a single network flow
POST /api/ml/score/batch   — score up to 50 flows at once
GET  /api/ml/status        — check if models are loaded and ready
GET  /api/ml/features      — return the list of expected feature names
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.services.ml_service import ml_service

router = APIRouter(prefix="/api/ml", tags=["ML"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class FlowFeatures(BaseModel):
    """
    Network flow feature vector.
    All fields are optional — missing values default to 0.
    Use GET /api/ml/features to see the full expected feature list.

    Common CICIDS2017 features (snake_case versions):
      flow_duration, total_fwd_packets, total_backward_packets,
      total_length_of_fwd_packets, total_length_of_bwd_packets,
      fwd_packet_length_max, fwd_packet_length_min, fwd_packet_length_mean,
      bwd_packet_length_max, flow_bytes_per_s, flow_packets_per_s,
      flow_iat_mean, flow_iat_std, fwd_iat_mean, bwd_iat_mean,
      fwd_psh_flags, bwd_psh_flags, fwd_urg_flags, bwd_urg_flags,
      fwd_header_length, bwd_header_length, fwd_packets_per_s,
      min_packet_length, max_packet_length, packet_length_mean,
      packet_length_std, packet_length_variance, fin_flag_count,
      syn_flag_count, rst_flag_count, psh_flag_count, ack_flag_count,
      urg_flag_count, cwe_flag_count, ece_flag_count, down_up_ratio,
      average_packet_size, avg_fwd_segment_size, avg_bwd_segment_size,
      subflow_fwd_packets, subflow_fwd_bytes, subflow_bwd_packets,
      subflow_bwd_bytes, init_win_bytes_forward, init_win_bytes_backward,
      act_data_pkt_fwd, min_seg_size_forward, active_mean, active_std,
      idle_mean, idle_std
    """
    # Accept any feature name dynamically
    model_config = {"extra": "allow"}

    def to_feature_dict(self) -> dict:
        return {k: float(v) for k, v in self.model_dump().items()
                if v is not None}


class ScoringRequest(BaseModel):
    features: dict[str, float]
    """Raw feature dict — keys are feature names, values are numeric."""


class BatchScoringRequest(BaseModel):
    flows: list[dict[str, float]]


class MLPredictionResponse(BaseModel):
    anomaly_score: float
    is_anomaly: bool
    attack_class: str
    attack_confidence: float
    top_classes: list[dict]
    combined_risk_score: int
    verdict: str
    shap_explanation: list[dict]
    error: Optional[str] = None


class MLStatusResponse(BaseModel):
    ready: bool
    message: str
    n_features: int
    n_classes: int
    feature_names: list[str]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/status",
    response_model=MLStatusResponse,
    summary="Check if ML models are trained and ready",
)
async def ml_status():
    ready = ml_service.is_ready()
    if not ready:
        return MLStatusResponse(
            ready=False,
            message="Models not trained. Run: python ml/train.py",
            n_features=0,
            n_classes=0,
            feature_names=[],
        )

    # Trigger load to get metadata
    try:
        ml_service._load()
        return MLStatusResponse(
            ready=True,
            message="Models loaded and ready",
            n_features=len(ml_service._feature_columns),
            n_classes=len(ml_service._label_map),
            feature_names=ml_service._feature_columns,
        )
    except Exception as e:
        return MLStatusResponse(
            ready=False,
            message=f"Load error: {str(e)}",
            n_features=0,
            n_classes=0,
            feature_names=[],
        )


@router.get(
    "/features",
    summary="Return the list of feature names the model expects",
)
async def get_features():
    if not ml_service.is_ready():
        return {"ready": False, "features": [], "message": "Models not trained yet"}
    ml_service._load()
    return {
        "ready": True,
        "n_features": len(ml_service._feature_columns),
        "features": ml_service._feature_columns,
    }


@router.post(
    "/score",
    response_model=MLPredictionResponse,
    summary="Score a single network flow",
    description=(
        "Submit a network flow feature vector. "
        "Returns anomaly score, predicted attack class, "
        "combined risk score (0–100), and SHAP explanation. "
        "Missing features default to 0."
    ),
)
async def score_flow(request: ScoringRequest):
    prediction = ml_service.score(request.features)
    return MLPredictionResponse(**prediction.__dict__)


@router.post(
    "/score/batch",
    response_model=list[MLPredictionResponse],
    summary="Score up to 50 network flows",
)
async def score_batch(request: BatchScoringRequest):
    if len(request.flows) > 50:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=422,
            detail="Maximum 50 flows per batch request",
        )
    return [
        MLPredictionResponse(**ml_service.score(flow).__dict__)
        for flow in request.flows
    ]

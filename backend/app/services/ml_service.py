"""
ML Model Loader + Inference Service

Loads the trained models once at startup (lazy, thread-safe singleton).
Used by the /api/ml/score endpoint.

The two models work together:
  - Isolation Forest gives an anomaly score independent of labels
  - XGBoost gives attack classification with per-class probabilities
  - Combined score = weighted blend of both signals
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MLPrediction:
    """Result from the ML scoring pipeline."""
    anomaly_score: float          # 0.0–1.0 from Isolation Forest
    is_anomaly: bool              # Isolation Forest binary verdict
    attack_class: str             # XGBoost predicted class name
    attack_confidence: float      # 0.0–1.0 confidence for predicted class
    top_classes: list[dict]       # top-3 classes with probabilities
    combined_risk_score: int      # 0–100 final blended score
    verdict: str                  # clean | suspicious | malicious
    shap_explanation: list[dict]  # top features that drove this prediction
    error: Optional[str] = None


class MLService:
    """
    Lazy-loading singleton for ML models.
    Models are loaded on first call to score(), not at import time,
    so the FastAPI server starts instantly even if models aren't trained yet.
    """

    def __init__(self):
        self._loaded = False
        self._scaler = None
        self._iso_forest = None
        self._xgb_clf = None
        self._feature_columns: list[str] = []
        self._label_map: dict = {}          # name → index
        self._reverse_label_map: dict = {}  # index → name
        
    @property
    def _models_dir(self) -> str:
        from app.core.config import get_settings
        return get_settings().models_dir

    def _load(self):
        """Load all model artifacts. Called once on first inference request."""
        if self._loaded:
            return

        missing = []
        required = [
            "scaler.pkl",
            "isolation_forest.pkl",
            "xgboost_classifier.pkl",
            "feature_columns.json",
            "label_map.json",
        ]
        for fname in required:
            path = os.path.join(self._models_dir, fname)
            if not os.path.exists(path):
                missing.append(fname)

        if missing:
            raise FileNotFoundError(
                f"Models not trained yet. Missing: {missing}. "
                f"Run  python ml/train.py  first."
            )

        self._scaler = joblib.load(
            os.path.join(self._models_dir, "scaler.pkl")
        )
        self._iso_forest = joblib.load(
            os.path.join(self._models_dir, "isolation_forest.pkl")
        )
        self._xgb_clf = joblib.load(
            os.path.join(self._models_dir, "xgboost_classifier.pkl")
        )
        with open(os.path.join(self._models_dir, "feature_columns.json")) as f:
            self._feature_columns = json.load(f)
        with open(os.path.join(self._models_dir, "label_map.json")) as f:
            self._label_map = json.load(f)

        self._reverse_label_map = {
            v: k for k, v in self._label_map.items()
        }
        self._loaded = True
        print(f"✅  ML models loaded ({len(self._feature_columns)} features, "
              f"{len(self._label_map)} classes)")

    def is_ready(self) -> bool:
        """Check if models are trained and loadable."""
        required = [
            "scaler.pkl", "isolation_forest.pkl",
            "xgboost_classifier.pkl", "feature_columns.json", "label_map.json"
        ]
        return all(
            os.path.exists(os.path.join(self._models_dir, f))
            for f in required
        )

    def score(self, features: dict) -> MLPrediction:
        try:
            self._load()
        except FileNotFoundError as e:
            return MLPrediction(
                anomaly_score=0.0, is_anomaly=False,
                attack_class="unknown", attack_confidence=0.0,
                top_classes=[], combined_risk_score=0,
                verdict="unknown", shap_explanation=[],
                error=str(e),
            )

        # ── Step 1: build FULL feature vector (all columns scaler was trained on)
        # The scaler expects every column it saw during fit — missing ones → 0
        all_feature_cols = self._scaler.feature_names_in_.tolist()
        full_row = {col: features.get(col, 0.0) for col in all_feature_cols}
        X_full = pd.DataFrame([full_row])[all_feature_cols].astype(np.float32)

        # Clean any Inf/NaN from input
        X_full.replace([np.inf, -np.inf], np.nan, inplace=True)
        X_full.fillna(0, inplace=True)

        # ── Step 2: scale all features
        X_scaled_full = self._scaler.transform(X_full)
        X_scaled_full_df = pd.DataFrame(X_scaled_full, columns=all_feature_cols)

        # ── Step 3: slice to the top-25 SHAP-selected features for the models
        X_scaled = X_scaled_full_df[self._feature_columns].values

        # ── Isolation Forest
        iso_raw = self._iso_forest.decision_function(X_scaled)[0]
        anomaly_score = float(np.clip((-iso_raw + 0.5) / 1.0, 0.0, 1.0))
        is_anomaly = self._iso_forest.predict(X_scaled)[0] == -1

        # ── XGBoost classifier
        proba = self._xgb_clf.predict_proba(X_scaled)[0]
        predicted_idx = int(np.argmax(proba))
        attack_class = self._reverse_label_map.get(predicted_idx, "Unknown")
        attack_confidence = float(proba[predicted_idx])

        top_3_idx = np.argsort(proba)[::-1][:3]
        top_classes = [
            {
                "class": self._reverse_label_map.get(int(i), "Unknown"),
                "probability": round(float(proba[i]), 4),
            }
            for i in top_3_idx
        ]

        # ── Combined risk score
        is_benign = attack_class.upper() == "BENIGN"
        xgb_contribution = 0 if is_benign else attack_confidence * 60
        iso_contribution = anomaly_score * 40
        combined_risk_score = int(min(100, xgb_contribution + iso_contribution))

        if combined_risk_score >= 70:
            verdict = "malicious"
        elif combined_risk_score >= 30:
            verdict = "suspicious"
        else:
            verdict = "clean"

        # ── SHAP explanation
        shap_explanation = self._explain(X_scaled)

        return MLPrediction(
            anomaly_score=round(anomaly_score, 4),
            is_anomaly=bool(is_anomaly),
            attack_class=attack_class,
            attack_confidence=round(attack_confidence, 4),
            top_classes=top_classes,
            combined_risk_score=combined_risk_score,
            verdict=verdict,
            shap_explanation=shap_explanation,
        )
    def _explain(self, X_scaled: np.ndarray) -> list[dict]:
        """Return top-5 SHAP feature contributions for the prediction."""
        try:
            import shap
            explainer = shap.TreeExplainer(self._xgb_clf)
            shap_vals = explainer.shap_values(X_scaled)

            # For multi-class, shap_vals shape is (n_samples, n_features, n_classes)
            # Use the predicted class dimension
            if shap_vals.ndim == 3:
                sv = shap_vals[0, :, :]
                mean_sv = np.abs(sv).mean(axis=1)
            else:
                mean_sv = np.abs(shap_vals[0])

            top_idx = np.argsort(mean_sv)[::-1][:5]
            return [
                {
                    "feature": self._feature_columns[i],
                    "importance": round(float(mean_sv[i]), 4),
                    "value": round(float(X_scaled[0, i]), 4),
                }
                for i in top_idx
            ]
        except Exception:
            # SHAP is best-effort — never block a prediction
            return []


# Module-level singleton
ml_service = MLService()

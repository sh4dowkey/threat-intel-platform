"""
CICIDS2017 — Model Training Pipeline
Trains two complementary models:
  1. Isolation Forest  — unsupervised anomaly detection (no labels needed)
  2. XGBoost Classifier — supervised multi-class attack classification

Both models use the top-25 features selected by SHAP importance.
Outputs saved to ml/models/:
  - feature_columns.json    — ordered list of the 25 selected features
  - scaler.pkl              — StandardScaler fitted on training data
  - isolation_forest.pkl    — anomaly detector
  - xgboost_classifier.pkl  — attack classifier
  - label_map.json          — class index → attack name

Usage:
    cd ml/
    python train.py
"""

import os
import json
import time
import warnings
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    confusion_matrix,
)
from sklearn.utils.class_weight import compute_sample_weight
import xgboost as xgb
import shap

warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────────────────────────

BASE_DIR   = os.path.dirname(__file__)
DATA_DIR   = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

CLEANED_CSV     = os.path.join(DATA_DIR, "cleaned.csv")
LABEL_MAP_PATH  = os.path.join(DATA_DIR, "label_map.json")
FEATURE_COL_OUT = os.path.join(MODELS_DIR, "feature_columns.json")
SCALER_OUT      = os.path.join(MODELS_DIR, "scaler.pkl")
ISO_OUT         = os.path.join(MODELS_DIR, "isolation_forest.pkl")
XGB_OUT         = os.path.join(MODELS_DIR, "xgboost_classifier.pkl")
LABEL_MAP_OUT   = os.path.join(MODELS_DIR, "label_map.json")

N_FEATURES_TO_SELECT = 25   # SHAP will pick the best 25 out of all available
SAMPLE_SIZE = 200_000       # rows to use for training (full set can be slow)
RANDOM_STATE = 42


# ── 1. Load cleaned data ──────────────────────────────────────────────────────

print("=" * 60)
print("CICIDS2017 Training Pipeline")
print("=" * 60)

if not os.path.exists(CLEANED_CSV):
    print("❌  cleaned.csv not found. Run  python eda.py  first.")
    exit(1)

print("\n⏳  Loading cleaned dataset...")
df = pd.read_csv(CLEANED_CSV, low_memory=False)
print(f"✅  Loaded {len(df):,} rows × {len(df.columns)} columns")

with open(LABEL_MAP_PATH) as f:
    label_map = json.load(f)
reverse_label_map = {v: k for k, v in label_map.items()}


# ── 2. Prepare features and labels ───────────────────────────────────────────

EXCLUDE = {"label", "label_binary", "label_encoded"}
feature_cols = [c for c in df.columns if c not in EXCLUDE]

X = df[feature_cols].astype(np.float32)
y_binary = df["label_binary"].values
y_multi  = df["label_encoded"].values

# Subsample for manageable training time
if len(df) > SAMPLE_SIZE:
    print(f"\n⚡  Subsampling to {SAMPLE_SIZE:,} rows for training speed...")
    idx = np.random.RandomState(RANDOM_STATE).choice(
        len(df), SAMPLE_SIZE, replace=False
    )
    X        = X.iloc[idx].reset_index(drop=True)
    y_binary = y_binary[idx]
    y_multi  = y_multi[idx]

print(f"    Training set: {len(X):,} rows × {len(feature_cols)} features")
print(f"    Attack rows : {y_binary.sum():,}  "
      f"({y_binary.mean()*100:.1f}%)")

# Train/test split
X_train, X_test, yb_train, yb_test, ym_train, ym_test = train_test_split(
    X, y_binary, y_multi,
    test_size=0.2,
    random_state=RANDOM_STATE,
    stratify=y_binary,
)
print(f"    Train: {len(X_train):,}   Test: {len(X_test):,}")


# ── 3. Scale features ─────────────────────────────────────────────────────────

print("\n⚙️   Fitting StandardScaler...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)
joblib.dump(scaler, SCALER_OUT)
print(f"✅  Scaler saved → {SCALER_OUT}")


# ── 4. SHAP feature selection ─────────────────────────────────────────────────
# Train a fast preliminary XGBoost on all features, use SHAP to rank them,
# then keep only the top N for the final models.

print(f"\n🔍  Selecting top {N_FEATURES_TO_SELECT} features via SHAP...")
print("    Training preliminary XGBoost for feature importance...")

t0 = time.time()
prelim_xgb = xgb.XGBClassifier(
    n_estimators=100,
    max_depth=4,
    learning_rate=0.1,
    subsample=0.8,
    use_label_encoder=False,
    eval_metric="logloss",
    random_state=RANDOM_STATE,
    n_jobs=-1,
)
# Binary classification for feature selection pass
prelim_xgb.fit(X_train_scaled, yb_train)
print(f"    Preliminary model trained in {time.time()-t0:.1f}s")

# Compute SHAP values on a 5k sample (fast)
shap_sample = X_test_scaled[:5000]
explainer = shap.TreeExplainer(prelim_xgb)
shap_values = explainer.shap_values(shap_sample)

# Mean absolute SHAP value per feature = importance
mean_shap = np.abs(shap_values).mean(axis=0)
shap_importance = pd.Series(mean_shap, index=feature_cols).sort_values(
    ascending=False
)

top_features = shap_importance.head(N_FEATURES_TO_SELECT).index.tolist()

print(f"\n    Top {N_FEATURES_TO_SELECT} features by SHAP importance:")
for i, (feat, score) in enumerate(
    shap_importance.head(N_FEATURES_TO_SELECT).items(), 1
):
    print(f"    {i:2d}. {feat:45s}  {score:.4f}")

# Save feature list — inference must use EXACTLY these columns in this order
with open(FEATURE_COL_OUT, "w") as f:
    json.dump(top_features, f, indent=2)
print(f"\n✅  Feature list saved → {FEATURE_COL_OUT}")

# Subset to selected features
X_train_sel = pd.DataFrame(X_train_scaled, columns=feature_cols)[top_features].values
X_test_sel  = pd.DataFrame(X_test_scaled,  columns=feature_cols)[top_features].values


# ── 5. Isolation Forest (unsupervised anomaly detector) ───────────────────────

print("\n🌲  Training Isolation Forest...")
print("    (trains on BENIGN traffic only — learns what normal looks like)")
t0 = time.time()

# Train only on benign samples — true anomaly detection
X_benign = X_train_sel[yb_train == 0]
print(f"    Benign training samples: {len(X_benign):,}")

iso_forest = IsolationForest(
    n_estimators=200,
    max_samples="auto",
    contamination=0.05,   # expect ~5% anomalies in production traffic
    random_state=RANDOM_STATE,
    n_jobs=-1,
)
iso_forest.fit(X_benign)
print(f"✅  Isolation Forest trained in {time.time()-t0:.1f}s")

# Evaluate: -1 = anomaly (attack), 1 = normal (benign)
iso_preds = iso_forest.predict(X_test_sel)
iso_binary = (iso_preds == -1).astype(int)   # convert to 0/1

from sklearn.metrics import f1_score, precision_score, recall_score
iso_f1  = f1_score(yb_test, iso_binary)
iso_pre = precision_score(yb_test, iso_binary)
iso_rec = recall_score(yb_test, iso_binary)
print(f"\n    Isolation Forest on test set:")
print(f"    Precision : {iso_pre:.3f}")
print(f"    Recall    : {iso_rec:.3f}")
print(f"    F1 Score  : {iso_f1:.3f}")

joblib.dump(iso_forest, ISO_OUT)
print(f"✅  Isolation Forest saved → {ISO_OUT}")


# ── 6. XGBoost Classifier (supervised multi-class) ────────────────────────────

print("\n🚀  Training XGBoost Classifier (multi-class)...")
t0 = time.time()

# Handle class imbalance with sample weights
sample_weights = compute_sample_weight("balanced", ym_train)

n_classes = len(label_map)
xgb_clf = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    min_child_weight=5,
    use_label_encoder=False,
    eval_metric="mlogloss",
    objective="multi:softprob",
    num_class=n_classes,
    random_state=RANDOM_STATE,
    n_jobs=-1,
    early_stopping_rounds=20,
)
xgb_clf.fit(
    X_train_sel, ym_train,
    sample_weight=sample_weights,
    eval_set=[(X_test_sel, ym_test)],
    verbose=50,
)
print(f"\n✅  XGBoost trained in {time.time()-t0:.1f}s")

# Evaluate
ym_pred = xgb_clf.predict(X_test_sel)
print("\n    Classification Report:")
actual_classes = sorted(set(ym_test) | set(ym_pred))
target_names = [reverse_label_map[i] for i in actual_classes]
report = classification_report(
    ym_test, ym_pred,
    labels=actual_classes,
    target_names=target_names,
    zero_division=0,
)
print(report)

# Per-class AUC
ym_proba = xgb_clf.predict_proba(X_test_sel)
try:
    auc = roc_auc_score(ym_test, ym_proba, multi_class="ovr", average="macro")
    print(f"    Macro AUC (OvR): {auc:.4f}")
except Exception:
    pass

joblib.dump(xgb_clf, XGB_OUT)
print(f"✅  XGBoost Classifier saved → {XGB_OUT}")

# Copy label map to models dir
import shutil
shutil.copy(LABEL_MAP_PATH, LABEL_MAP_OUT)
print(f"✅  Label map saved → {LABEL_MAP_OUT}")


# ── 7. Summary ────────────────────────────────────────────────────────────────

print(f"\n{'='*60}")
print("Training complete. Models saved:")
for path in [SCALER_OUT, FEATURE_COL_OUT, ISO_OUT, XGB_OUT, LABEL_MAP_OUT]:
    size_kb = os.path.getsize(path) / 1024
    print(f"  {os.path.basename(path):35s}  {size_kb:>8.1f} KB")
print(f"\nNext step: run the FastAPI server and test POST /api/ml/score")
print(f"{'='*60}")

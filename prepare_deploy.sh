#!/usr/bin/env bash
# prepare_deploy.sh
#
# Copies trained ML models into backend/models/ so Docker can bundle them.
# Run this from the project root before building the Docker image or
# deploying to Railway.
#
# Usage:
#   chmod +x prepare_deploy.sh
#   ./prepare_deploy.sh

set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ML_MODELS="$ROOT/ml/models"
BACKEND_MODELS="$ROOT/backend/models"

echo "🔍  Checking for trained models..."

REQUIRED_FILES=(
  "scaler.pkl"
  "isolation_forest.pkl"
  "xgboost_classifier.pkl"
  "feature_columns.json"
  "label_map.json"
)

missing=0
for f in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "$ML_MODELS/$f" ]; then
    echo "  ❌  Missing: ml/models/$f"
    missing=1
  else
    size=$(du -h "$ML_MODELS/$f" | cut -f1)
    echo "  ✅  Found:   ml/models/$f  ($size)"
  fi
done

if [ $missing -eq 1 ]; then
  echo ""
  echo "❌  Some model files are missing."
  echo "    Run:  cd ml && python train.py"
  exit 1
fi

echo ""
echo "📦  Copying models to backend/models/ for Docker build..."
mkdir -p "$BACKEND_MODELS"

for f in "${REQUIRED_FILES[@]}"; do
  cp "$ML_MODELS/$f" "$BACKEND_MODELS/$f"
  echo "  Copied: $f"
done

echo ""
echo "✅  Models ready at backend/models/"
echo "    You can now build the Docker image or push to Railway."
echo ""
echo "    Local build:   docker build -f docker/Dockerfile -t tip-backend ."
echo "    Railway push:  git push origin main"

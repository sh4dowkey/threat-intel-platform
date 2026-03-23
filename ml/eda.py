"""
CICIDS2017 — Exploratory Data Analysis + Cleaning
Run this BEFORE training. It tells you:
  - Class distribution (expect ~79% Benign)
  - Which columns have Infinity / NaN values
  - Which features matter most (correlation-based pre-filter)
  - Saves a cleaned CSV ready for training

Usage:
    cd ml/
    python eda.py

Output:
    data/cleaned.csv          — cleaned, label-encoded dataset
    data/class_counts.txt     — class distribution summary
"""

import os
import glob
import pandas as pd
import numpy as np

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
OUTPUT_CSV = os.path.join(DATA_DIR, "cleaned.csv")
OUTPUT_COUNTS = os.path.join(DATA_DIR, "class_counts.txt")

# ── 1. Load all CSVs from the MachineLearningCSV folder ──────────────────────

csv_files = glob.glob(os.path.join(DATA_DIR, "**", "*.csv"), recursive=True)
if not csv_files:
    # Also check direct data/ folder
    csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))

if not csv_files:
    print("❌  No CSV files found in ml/data/")
    print("    Download MachineLearningCSV.zip from:")
    print("    https://www.unb.ca/cic/datasets/ids-2017.html")
    print("    Extract into ml/data/")
    exit(1)

print(f"📂  Found {len(csv_files)} CSV files:")
for f in csv_files:
    size_mb = os.path.getsize(f) / 1024 / 1024
    print(f"    {os.path.basename(f):50s} {size_mb:.1f} MB")

print("\n⏳  Loading... (may take 1–2 minutes for large files)")
dfs = []
for f in csv_files:
    try:
        df = pd.read_csv(f, encoding="utf-8", low_memory=False)
        dfs.append(df)
        print(f"    ✅  {os.path.basename(f):50s} {len(df):>8,} rows")
    except Exception as e:
        print(f"    ❌  {os.path.basename(f)}: {e}")

df = pd.concat(dfs, ignore_index=True)
print(f"\n📊  Total rows loaded: {len(df):,}")
print(f"📊  Total columns:     {len(df.columns)}")

# ── 2. Normalise column names ─────────────────────────────────────────────────

df.columns = (
    df.columns
    .str.strip()
    .str.lower()
    .str.replace(" ", "_")
    .str.replace("/", "_per_")
    .str.replace(r"[^a-z0-9_]", "", regex=True)
)
print(f"\n🔤  Columns normalised. Label column detected as: ", end="")

# Find the label column (CICIDS2017 calls it ' Label' with a space)
label_col = None
for candidate in ["label", " label", "labels"]:
    if candidate in df.columns:
        label_col = candidate
        break
if label_col is None:
    # Last resort: find any column with 'label' in its name
    matches = [c for c in df.columns if "label" in c]
    label_col = matches[0] if matches else None

if label_col is None:
    print("❌  Could not find label column. Columns are:")
    print(df.columns.tolist())
    exit(1)

print(f"'{label_col}'")
df = df.rename(columns={label_col: "label"})

# ── 3. Class distribution ─────────────────────────────────────────────────────

print("\n📈  Class distribution (before cleaning):")
counts = df["label"].value_counts()
total = len(df)
lines = []
for label, count in counts.items():
    pct = count / total * 100
    line = f"    {label:40s}  {count:>8,}  ({pct:5.1f}%)"
    print(line)
    lines.append(line)

with open(OUTPUT_COUNTS, "w") as f:
    f.write("\n".join(lines))
print(f"\n💾  Saved class counts → {OUTPUT_COUNTS}")

# ── 4. Drop problematic rows and columns ──────────────────────────────────────

print("\n🧹  Cleaning...")

# Replace Infinity values with NaN, then drop
before = len(df)
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
print(f"    Dropped {before - len(df):,} rows with Inf/NaN  "
      f"({len(df):,} remaining)")

# Drop exact duplicate rows
before = len(df)
df.drop_duplicates(inplace=True)
print(f"    Dropped {before - len(df):,} duplicate rows  "
      f"({len(df):,} remaining)")

# Drop columns with zero variance (carry no information)
feature_cols = [c for c in df.columns if c != "label"]
nunique = df[feature_cols].nunique()
zero_var = nunique[nunique <= 1].index.tolist()
if zero_var:
    df.drop(columns=zero_var, inplace=True)
    print(f"    Dropped {len(zero_var)} zero-variance columns: {zero_var}")

# ── 5. Binary label encoding ──────────────────────────────────────────────────
# For the anomaly detection model we use binary: 0=Benign, 1=Attack
# The multi-class label is preserved for the classifier model

df["label_binary"] = (df["label"].str.upper() != "BENIGN").astype(int)

print(f"\n🏷️   Binary label distribution:")
b_counts = df["label_binary"].value_counts()
print(f"    Benign (0): {b_counts.get(0, 0):>8,}")
print(f"    Attack (1): {b_counts.get(1, 0):>8,}")

# Multi-class encoding
label_map = {v: i for i, v in enumerate(df["label"].unique())}
df["label_encoded"] = df["label"].map(label_map)
print(f"\n🏷️   Multi-class labels ({len(label_map)} classes):")
for name, code in sorted(label_map.items(), key=lambda x: x[1]):
    print(f"    {code:2d} → {name}")

# Save label map for inference
import json
label_map_path = os.path.join(DATA_DIR, "label_map.json")
with open(label_map_path, "w") as f:
    json.dump(label_map, f, indent=2)
print(f"\n💾  Saved label map → {label_map_path}")

# ── 6. Feature correlation pre-filter ─────────────────────────────────────────
# Remove features that are nearly perfectly correlated with another
# (keeps training fast and reduces overfitting)

print("\n🔍  Checking feature correlations...")
feature_cols = [c for c in df.columns
                if c not in ("label", "label_binary", "label_encoded")]

# Sample for correlation check (full dataset is slow)
sample = df[feature_cols].sample(min(50_000, len(df)), random_state=42)
corr_matrix = sample.corr().abs()
upper = corr_matrix.where(
    np.triu(np.ones(corr_matrix.shape), k=1).astype(bool)
)
to_drop = [col for col in upper.columns if any(upper[col] > 0.98)]
if to_drop:
    df.drop(columns=to_drop, inplace=True)
    print(f"    Dropped {len(to_drop)} highly-correlated features")
else:
    print(f"    No highly-correlated features found")

feature_cols = [c for c in df.columns
                if c not in ("label", "label_binary", "label_encoded")]
print(f"    Features remaining: {len(feature_cols)}")

# ── 7. Save cleaned dataset ───────────────────────────────────────────────────

print(f"\n⏳  Saving cleaned dataset...")
df.to_csv(OUTPUT_CSV, index=False)
size_mb = os.path.getsize(OUTPUT_CSV) / 1024 / 1024
print(f"✅  Saved → {OUTPUT_CSV}  ({size_mb:.1f} MB)")

print(f"\n{'='*60}")
print(f"EDA complete. Summary:")
print(f"  Total clean rows : {len(df):,}")
print(f"  Feature columns  : {len(feature_cols)}")
print(f"  Attack classes   : {len(label_map)}")
print(f"  Benign ratio     : {b_counts.get(0,0)/len(df)*100:.1f}%")
print(f"\nNext step: run  python train.py")
print(f"{'='*60}")

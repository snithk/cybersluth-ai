#!/usr/bin/env python3
"""
============================================================
  AI-Driven Cyber Forensics Analyzer — Training Pipeline
============================================================
Trains and saves two ML models from sample_network_traffic.csv:
  1. RandomForestClassifier  → classifies attack type
  2. IsolationForest         → detects unknown anomalies
Models are saved to /src/models/saved/ and auto-loaded by the analyzer.
"""

import os
import sys
import pickle
import warnings
import numpy as np
import pandas as pd
from pathlib import Path

warnings.filterwarnings("ignore")

# ── scikit-learn ──────────────────────────────────────────────────────────────
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
DATA_FILE  = BASE_DIR / "sample_network_traffic.csv"
SAVE_DIR   = BASE_DIR / "src" / "models" / "saved"
SAVE_DIR.mkdir(parents=True, exist_ok=True)

# ── Pretty printer ────────────────────────────────────────────────────────────
def banner(text: str):
    width = 60
    print("\n" + "═" * width)
    print(f"  {text}")
    print("═" * width)

def check(text: str):
    print(f"  ✔  {text}")

def info(text: str):
    print(f"  ➜  {text}")

# ─────────────────────────────────────────────────────────────────────────────
# 1.  LOAD & INSPECT DATA
# ─────────────────────────────────────────────────────────────────────────────
banner("STEP 1 — Loading Dataset")

if not DATA_FILE.exists():
    print(f"  ✘  Dataset not found: {DATA_FILE}")
    sys.exit(1)

df = pd.read_csv(DATA_FILE)
info(f"Loaded {len(df):,} rows × {len(df.columns)} columns")
info(f"Columns: {list(df.columns)}")

# Label distribution
print("\n  Attack Label Distribution:")
label_counts = df["label"].value_counts()
for label, count in label_counts.items():
    pct = 100 * count / len(df)
    bar = "█" * int(pct / 2)
    print(f"    {label:<15} {count:>4}  ({pct:5.1f}%)  {bar}")

# ─────────────────────────────────────────────────────────────────────────────
# 2.  FEATURE ENGINEERING
# ─────────────────────────────────────────────────────────────────────────────
banner("STEP 2 — Feature Engineering")

# Encode categorical columns
protocol_enc  = LabelEncoder()
flags_enc     = LabelEncoder()
label_enc     = LabelEncoder()

df["protocol_enc"] = protocol_enc.fit_transform(df["protocol"].astype(str))
df["flags_enc"]    = flags_enc.fit_transform(df["flags"].astype(str))

# Extract IP octets as numeric features
def ip_to_int(ip_series):
    """Convert last octet of IP to int (simple but effective)."""
    return ip_series.str.split(".").str[-1].astype(int)

df["src_ip_oct"]   = ip_to_int(df["src_ip"])
df["dst_ip_oct"]   = ip_to_int(df["dst_ip"])

# Encode labels
df["label_enc"] = label_enc.fit_transform(df["label"])
class_names     = list(label_enc.classes_)
info(f"Classes: {class_names}")

# Feature matrix
FEATURE_COLS = [
    "src_port",
    "dst_port",
    "packet_length",
    "duration",
    "protocol_enc",
    "flags_enc",
    "src_ip_oct",
    "dst_ip_oct",
]

X = df[FEATURE_COLS].values
y = df["label_enc"].values
check(f"Feature matrix shape: {X.shape}")

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ─────────────────────────────────────────────────────────────────────────────
# 3.  TRAIN / TEST SPLIT
# ─────────────────────────────────────────────────────────────────────────────
banner("STEP 3 — Train / Test Split (80 / 20)")

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)
info(f"Training samples : {len(X_train):,}")
info(f"Testing  samples : {len(X_test):,}")

# ─────────────────────────────────────────────────────────────────────────────
# 4.  TRAIN RANDOM FOREST CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────
banner("STEP 4 — Training Random Forest Classifier")

clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    min_samples_split=2,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",
)
info("Training RandomForestClassifier (n_estimators=200)…")
clf.fit(X_train, y_train)
check("Training complete!")

# Evaluate
y_pred = clf.predict(X_test)
acc    = accuracy_score(y_test, y_pred)

print(f"\n  🎯  Accuracy: {acc * 100:.2f}%\n")
print("  Classification Report:")
report = classification_report(
    y_test, y_pred, target_names=class_names, zero_division=0
)
for line in report.splitlines():
    print("    " + line)

# Feature importance
print("\n  Top Feature Importances:")
importances = clf.feature_importances_
for feat, imp in sorted(zip(FEATURE_COLS, importances), key=lambda x: -x[1]):
    bar = "▓" * int(imp * 50)
    print(f"    {feat:<18} {imp:.4f}  {bar}")

# ─────────────────────────────────────────────────────────────────────────────
# 5.  TRAIN ISOLATION FOREST (Anomaly Detection)
# ─────────────────────────────────────────────────────────────────────────────
banner("STEP 5 — Training Isolation Forest (Anomaly Detector)")

# Train only on benign traffic so it learns "normal"
benign_mask     = df["label"] == "Benign"
X_benign_scaled = X_scaled[benign_mask.values]
info(f"Training on {len(X_benign_scaled):,} benign samples only (learns normal behaviour)")

iso_forest = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42,
    n_jobs=-1,
)
iso_forest.fit(X_benign_scaled)
check("IsolationForest training complete!")

# Quick sanity check
attack_mask     = df["label"] != "Benign"
X_attack_scaled = X_scaled[attack_mask.values]

benign_preds = iso_forest.predict(X_benign_scaled)
attack_preds = iso_forest.predict(X_attack_scaled)

benign_anomaly_rate = (benign_preds == -1).mean() * 100
attack_anomaly_rate = (attack_preds == -1).mean() * 100

print(f"\n  Anomaly detection rates:")
print(f"    Benign traffic flagged as anomaly : {benign_anomaly_rate:.1f}%  (false positive rate)")
print(f"    Attack traffic flagged as anomaly : {attack_anomaly_rate:.1f}%  (true positive rate)")

# ─────────────────────────────────────────────────────────────────────────────
# 6.  SAVE ALL MODELS + ENCODERS
# ─────────────────────────────────────────────────────────────────────────────
banner("STEP 6 — Saving Models to Disk")

models_to_save = {
    "rf_classifier.pkl"    : clf,
    "isolation_forest.pkl" : iso_forest,
    "scaler.pkl"           : scaler,
    "label_encoder.pkl"    : label_enc,
    "protocol_encoder.pkl" : protocol_enc,
    "flags_encoder.pkl"    : flags_enc,
}

for filename, obj in models_to_save.items():
    path = SAVE_DIR / filename
    with open(path, "wb") as f:
        pickle.dump(obj, f)
    size_kb = path.stat().st_size / 1024
    check(f"Saved {filename} ({size_kb:.1f} KB)  →  {path}")

# Save class names list for reference
class_names_path = SAVE_DIR / "class_names.txt"
class_names_path.write_text("\n".join(class_names))
check(f"Saved class_names.txt  →  {class_names_path}")

# ─────────────────────────────────────────────────────────────────────────────
# 7.  SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
banner("TRAINING COMPLETE ✅")
print(f"""
  Models trained and saved to:
    {SAVE_DIR}

  Summary:
    • RandomForestClassifier  accuracy : {acc * 100:.2f}%
    • IsolationForest         anomaly detection on attacks : {attack_anomaly_rate:.1f}%
    • Attack classes learned  : {', '.join(class_names)}
    • Features used           : {len(FEATURE_COLS)}
    • Total training samples  : {len(X_train):,}

  Next step:
    Run  python app.py  — the analyzer will now load the trained models
    automatically and use them for real-time threat classification!
""")

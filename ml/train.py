"""
train.py — LinkLens Model Trainer

Trains a Random Forest on the feature set defined in ../backend/features.py
and saves the model to ../backend/models/phishing_model.joblib.

Usage:
    cd ml
    python train.py

Output:
    ../backend/models/phishing_model.joblib   ← drop-in replacement

The saved payload is a dict:
    {
        "model":         RandomForestClassifier (fitted),
        "feature_names": list[str],            ← column order the model expects
        "training_accuracy": float,
        "test_accuracy":     float,
    }
"""

import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix
)

# ── Path setup ─────────────────────────────────────────────────────────────────
ROOT     = Path(__file__).resolve().parent.parent
ML_DIR   = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))   # so we can import features.py

from features import extract       # noqa: E402  (import after sys.path tweak)
from data_loader import load       # noqa: E402

MODEL_OUT = ROOT / "backend" / "models" / "phishing_model.joblib"


# ── Feature extraction ─────────────────────────────────────────────────────────
def build_features(urls: list[str]) -> pd.DataFrame:
    rows = []
    errors = 0
    for i, url in enumerate(urls):
        try:
            rows.append(extract(url))
        except Exception:
            errors += 1
            rows.append({})          # blank row — filled with 0 later
        if (i + 1) % 5000 == 0:
            print(f"  Extracted {i+1:,} / {len(urls):,} URLs…")

    df = pd.DataFrame(rows).fillna(0)
    if errors:
        print(f"  [warn] {errors} URLs failed extraction — filled with zeros.")
    return df


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("LinkLens Model Trainer")
    print("=" * 60)

    # 1. Load data
    print("\n[1/4] Loading training data…")
    urls, labels = load()

    # 2. Extract features
    print("\n[2/4] Extracting features…")
    t0 = time.time()
    X = build_features(urls)
    y = np.array(labels)
    feature_names = list(X.columns)
    print(f"  Done in {time.time() - t0:.1f}s  |  "
          f"Shape: {X.shape}  |  Features: {len(feature_names)}")
    print(f"  Columns: {feature_names}")

    # 3. Train / test split (80/20, stratified)
    print("\n[3/4] Training Random Forest…")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=300,       # more trees = more stable predictions
        max_depth=None,         # let trees grow fully
        min_samples_leaf=2,     # slight regularisation to avoid overfitting
        class_weight="balanced",# compensates for any remaining class skew
        n_jobs=-1,              # use all CPU cores
        random_state=42,
    )
    model.fit(X_train, y_train)

    # 4. Evaluate
    print("\n[4/4] Evaluating…")
    train_acc = accuracy_score(y_train, model.predict(X_train))
    test_acc  = accuracy_score(y_test,  model.predict(X_test))

    print(f"\n  Train accuracy : {train_acc:.4f}  ({train_acc*100:.2f}%)")
    print(f"  Test accuracy  : {test_acc:.4f}  ({test_acc*100:.2f}%)")
    print(f"\n  Classification report (test set):")
    print(classification_report(y_test, model.predict(X_test),
                                target_names=["safe", "phishing"]))

    cm = confusion_matrix(y_test, model.predict(X_test))
    print("  Confusion matrix:")
    print(f"    True Safe    caught as Safe    : {cm[0][0]:>6}")
    print(f"    Safe         missed as Phishing: {cm[0][1]:>6}  ← false positives")
    print(f"    Phishing     caught as Phishing: {cm[1][1]:>6}")
    print(f"    Phishing     missed as Safe    : {cm[1][0]:>6}  ← false negatives")

    # Top 10 most important features
    importances = sorted(
        zip(feature_names, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print("\n  Top 10 features by importance:")
    for name, imp in importances[:10]:
        bar = "█" * int(imp * 200)
        print(f"    {name:<22} {imp:.4f}  {bar}")

    # 5. Save
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model":             model,
        "feature_names":     feature_names,
        "training_accuracy": round(train_acc, 4),
        "test_accuracy":     round(test_acc, 4),
    }
    joblib.dump(payload, MODEL_OUT)
    print(f"\n  Model saved → {MODEL_OUT}")
    print(f"  File size  : {MODEL_OUT.stat().st_size / 1024:.1f} KB")
    print("\n  Restart the backend (python main.py) to load the new model.")
    print("=" * 60)


if __name__ == "__main__":
    main()

"""
train.py — LinkLens Model Trainer

Trains an XGBoost classifier (falls back to Random Forest if XGBoost
is not installed) on the feature set in ../backend/features.py and
saves the model to ../backend/models/phishing_model.joblib.

Usage:
    cd ml
    python train.py           # local data only
    python train.py --live    # fetch OpenPhish + Tranco live feeds too

Install XGBoost first:
    pip install xgboost
"""
import os
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
)

ROOT    = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import backend.features
from backend.features import extract     # noqa: E402
from ml.data_loader import load          # noqa: E402

MODEL_OUT = ROOT / "backend" / "models" / "phishing_model.joblib"


# ── Model selection ───────────────────────────────────────────────────────────

def build_model():
    """Return XGBoost if available, else Random Forest."""
    try:
        from xgboost import XGBClassifier
        print("  Using XGBoost classifier")
        return XGBClassifier(
            n_estimators      = 400,
            max_depth         = 7,
            learning_rate     = 0.1,
            subsample         = 0.8,
            colsample_bytree  = 0.8,
            use_label_encoder = False,
            eval_metric       = "logloss",
            n_jobs            = -1,
            random_state      = 42,
        )
    except ImportError:
        from sklearn.ensemble import RandomForestClassifier
        print("  XGBoost not installed — using Random Forest")
        print("  Install with: pip install xgboost")
        return RandomForestClassifier(
            n_estimators    = 300,
            max_depth       = None,
            min_samples_leaf= 2,
            class_weight    = "balanced",
            n_jobs          = -1,
            random_state    = 42,
        )


# ── Feature extraction ────────────────────────────────────────────────────────

def build_features(urls: list[str]) -> pd.DataFrame:
    rows   = []
    errors = 0
    total  = len(urls)
    os.environ["LINKLENS_NO_WHOIS"] = "1"   # WHOIS lookups can be very slow, so we disable them during training.
    for i, url in enumerate(urls):
        try:
            rows.append(extract(url))
        except Exception:
            errors += 1
            rows.append({})
        if (i + 1) % 5000 == 0:
            print(f"  Extracted {i+1:,} / {total:,} URLs …")

    df = pd.DataFrame(rows).fillna(0)
    if errors:
        print(f"  [warn] {errors} URLs failed extraction — filled with zeros.")
    return df


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 62)
    print("LinkLens Model Trainer")
    print("=" * 62)

    # 1. Load data
    print("\n[1/4] Loading training data …")
    urls, labels = load()

    # 2. Extract features
    print("\n[2/4] Extracting features …")
    t0 = time.time()
    X  = build_features(urls)
    y  = np.array(labels)
    feature_names = list(X.columns)
    print(f"  Done in {time.time()-t0:.1f}s  |  "
          f"Shape: {X.shape}  |  Features: {len(feature_names)}")
    print(f"  Columns: {feature_names}")

    # 3. Train
    print("\n[3/4] Training …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )

    model = build_model()
    model.fit(X_train, y_train)

    # 4. Evaluate
    print("\n[4/4] Evaluating …")
    train_acc = accuracy_score(y_train, model.predict(X_train))
    test_acc  = accuracy_score(y_test,  model.predict(X_test))

    print(f"\n  Train accuracy : {train_acc:.4f}  ({train_acc*100:.2f}%)")
    print(f"  Test  accuracy : {test_acc:.4f}  ({test_acc*100:.2f}%)")
    print(f"\n  Classification report (test set):")
    print(classification_report(
        y_test, model.predict(X_test), target_names=["safe", "phishing"]
    ))

    cm = confusion_matrix(y_test, model.predict(X_test))
    print("  Confusion matrix:")
    print(f"    Safe    → Safe    (correct)  : {cm[0][0]:>6}")
    print(f"    Safe    → Phishing (FP)      : {cm[0][1]:>6}  ← false positives")
    print(f"    Phishing→ Phishing (correct) : {cm[1][1]:>6}")
    print(f"    Phishing→ Safe    (FN)       : {cm[1][0]:>6}  ← false negatives")

    # Feature importances
    try:
        importances = sorted(
            zip(feature_names, model.feature_importances_),
            key=lambda x: x[1], reverse=True,
        )
        print("\n  Top 10 features by importance:")
        for name, imp in importances[:10]:
            bar = "█" * int(imp * 200)
            print(f"    {name:<25} {imp:.4f}  {bar}")
    except AttributeError:
        pass   # some models don't expose feature_importances_

    # Save
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model":             model,
        "feature_names":     feature_names,
        "training_accuracy": round(train_acc, 4),
        "test_accuracy":     round(test_acc, 4),
        "model_type":        type(model).__name__,
    }
    joblib.dump(payload, MODEL_OUT)
    print(f"\n  Model saved → {MODEL_OUT}")
    print(f"  File size   : {MODEL_OUT.stat().st_size / 1024:.1f} KB")
    print(f"  Model type  : {type(model).__name__}")
    print("\n  Restart the backend to load the new model.")
    print("=" * 62)


if __name__ == "__main__":
    main()
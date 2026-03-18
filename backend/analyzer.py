"""
analyzer.py — LinkLens Core Analyzer
Loads the ML model once, scores any URL using features.py,
and returns a clean UI-ready result dict.
"""

from pathlib import Path
import joblib
import pandas as pd

from features import extract

_model        = None
_feature_cols = []
MODEL_PATH    = Path(__file__).parent / "models" / "phishing_model.joblib"


def load_model() -> bool:
    global _model, _feature_cols
    try:
        payload       = joblib.load(MODEL_PATH)
        _model        = payload["model"]
        _feature_cols = payload.get("feature_names", [])
        print(f"[LinkLens] Model loaded — {len(_feature_cols)} features, "
              f"type={type(_model).__name__}")
        return True
    except Exception as e:
        print(f"[LinkLens] Model load failed: {e}")
        return False


def _verdict(score: int) -> str:
    if score < 30:  return "SAFE"
    if score < 70:  return "SUSPICIOUS"
    return "MALICIOUS"


def _highlights(feat: dict, verdict: str) -> list[str]:
    notes = []
    if feat.get("homoglyph_spoof"):
        notes.append("Domain uses character substitution to impersonate a known brand.")
    if feat.get("brand_spoof"):
        notes.append("A brand name appears in the URL but not in the actual domain.")
    if feat.get("uses_ip"):
        notes.append("URL uses a raw IP address instead of a domain name.")
    if feat.get("is_shortened"):
        notes.append("URL passes through a link shortener — destination hidden.")
    if feat.get("risky_tld"):
        notes.append("Domain uses a TLD commonly associated with free/spam sites.")
    if feat.get("phish_keywords", 0) >= 2:
        notes.append(f"{feat['phish_keywords']} phishing-related keywords detected in URL.")
    if feat.get("http_count", 0) > 1:
        notes.append("URL contains an embedded URL — classic redirect trick.")
    if feat.get("url_entropy", 0) > 4.5:
        notes.append("High URL entropy — suggests randomised or obfuscated characters.")
    if feat.get("n_hyphens", 0) > 3:
        notes.append("Excessive hyphens in domain — common in spoofed sites.")
    if not notes:
        notes.append("No specific risk indicators found in URL structure.")
    return notes


def _param_bars(feat: dict, confidence: float) -> list[dict]:
    def clamp(v): return max(0, min(100, int(v)))
    return [
        {"label": "URL Length",         "value": clamp(feat.get("url_len", 0) / 2)},
        {"label": "Special Characters", "value": clamp(feat.get("n_hyphens", 0) * 20
                                                       + feat.get("n_at", 0) * 40)},
        {"label": "Phish Keywords",     "value": clamp(feat.get("phish_keywords", 0) * 25)},
        {"label": "URL Entropy",        "value": clamp(feat.get("url_entropy", 0) / 6 * 100)},
        {"label": "Brand Spoofing",     "value": 100 if feat.get("brand_spoof")
                                                     or feat.get("homoglyph_spoof") else 0},
        {"label": "ML Confidence",      "value": clamp(confidence * 100)},
    ]


def analyze(url: str) -> dict:
    if _model is None:
        if not load_model():
            return {"error": "Model unavailable", "score": -1}

    try:
        feat = extract(url)

        # Trusted domains are always SAFE — skip model scoring
        if feat.get("is_trusted"):
            return {
                "url":        url,
                "score":      0,
                "verdict":    "SAFE",
                "confidence": 0.0,
                "highlights": ["No specific risk indicators found in URL structure."],
                "bars":       _param_bars(feat, 0.0),
            }

        row = pd.DataFrame([feat])
        for col in _feature_cols:
            if col not in row.columns:
                row[col] = 0
        row = row[_feature_cols].fillna(0).replace([float("inf"), float("-inf")], 0)

        prob  = float(_model.predict_proba(row)[0][1])
        score = int(prob * 100)

        # Hard overrides for deterministic signals the model may underweight
        if feat.get("homoglyph_spoof"):
            score = max(score, 80)
        if feat.get("brand_spoof"):
            score = max(score, 70)

        verdict = _verdict(score)

        return {
            "url":        url,
            "score":      score,
            "verdict":    verdict,
            "confidence": round(prob, 3),
            "highlights": _highlights(feat, verdict),
            "bars":       _param_bars(feat, prob),
        }

    except Exception as e:
        print(f"[LinkLens] Analysis error for {url}: {e}")
        return {"error": str(e), "score": -1}

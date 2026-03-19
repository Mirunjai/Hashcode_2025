"""
analyzer.py — LinkLens Core Analyzer v1.3

Changes from v1.2:
  - combined_score() function merges URL + OCR scores intelligently
  - /analyze endpoint now accepts optional ocr_score parameter
  - OCR can boost a score upward or soften it slightly
  - OCR can NEVER downgrade MALICIOUS → SAFE (attack-resistant)
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
              f"type={payload.get('model_type', type(_model).__name__)}, "
              f"test_acc={payload.get('test_accuracy','?')}")
        return True
    except Exception as e:
        print(f"[LinkLens] Model load failed: {e}")
        return False


# ── Verdict helpers ───────────────────────────────────────────────────────────

def _verdict(score: int) -> str:
    if score < 30:  return "SAFE"
    if score < 70:  return "SUSPICIOUS"
    return "MALICIOUS"


# ── Combined scoring ──────────────────────────────────────────────────────────

def combined_score(url_score: int, ocr_score: int) -> tuple[int, str]:
    """
    Merge URL analysis score and OCR page-content score.

    Rules (in priority order):
      1. OCR finds phishing content (≥70) → take the higher of the two scores
      2. OCR is suspicious (30-69)        → nudge URL score up by 10, cap at 100
      3. URL is MALICIOUS, OCR is clean   → soften by up to 10 pts, floor at 70
                                            (stays MALICIOUS — OCR cannot save it)
      4. URL is SUSPICIOUS, OCR is clean  → soften by up to 5 pts
      5. Both clean                       → URL score unchanged

    Design intent:
      - OCR is an amplifier, not an arbiter
      - A well-crafted phishing page can fool OCR (images, CSS tricks, redirects)
      - We never let a clean OCR override a MALICIOUS URL verdict to SAFE
    """
    if ocr_score >= 70:
        # OCR confirmed phishing content — escalate
        final = max(url_score, ocr_score)

    elif 30 <= ocr_score < 70:
        # OCR is suspicious — nudge the URL score up slightly
        final = min(url_score + 10, 100)

    elif ocr_score == 0 and url_score >= 70:
        # URL malicious, OCR clean — soften a little but stay MALICIOUS
        # Floor at 70 so it can never cross into SUSPICIOUS
        final = max(url_score - 10, 70)

    elif ocr_score == 0 and 30 <= url_score < 70:
        # URL suspicious, OCR clean — soften a little
        final = max(url_score - 5, 30)

    else:
        # Both clean
        final = url_score

    return final, _verdict(final)


# ── Findings builders ─────────────────────────────────────────────────────────

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
    age = feat.get("domain_age_days", -1)
    if age == -1:
        notes.append("Domain age unknown — WHOIS lookup failed or timed out.")
    elif age < 30:
        notes.append(f"Domain is brand new ({age} days old) — very high risk signal.")
    elif age < 180:
        notes.append(f"Domain is only {age} days old — recently registered.")
    if not notes:
        notes.append("No specific risk indicators found in URL structure.")
    return notes


def _param_bars(feat: dict, confidence: float) -> list[dict]:
    def clamp(v): return max(0, min(100, int(v)))

    age = feat.get("domain_age_days", -1)
    if age == -1:   age_score = 50
    elif age < 30:  age_score = 100
    elif age < 180: age_score = 70
    elif age < 365: age_score = 40
    else:           age_score = 5

    return [
        {"label": "URL Length",         "value": clamp(feat.get("url_len", 0) / 2)},
        {"label": "Special Characters", "value": clamp(feat.get("n_hyphens", 0) * 20
                                                       + feat.get("n_at", 0) * 40)},
        {"label": "Phish Keywords",     "value": clamp(feat.get("phish_keywords", 0) * 25)},
        {"label": "URL Entropy",        "value": clamp(feat.get("url_entropy", 0) / 6 * 100)},
        {"label": "Brand Spoofing",     "value": 100 if feat.get("brand_spoof")
                                                     or feat.get("homoglyph_spoof") else 0},
        {"label": "Domain Age Risk",    "value": age_score},
        {"label": "ML Confidence",      "value": clamp(confidence * 100)},
    ]


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(url: str, ocr_score: int = -1) -> dict:
    """
    Analyze a URL and optionally combine with an OCR score.

    Args:
        url       — the URL to analyze
        ocr_score — page content OCR score (0-100), or -1 if not available

    Returns a dict ready to serialize as JSON.
    """
    if _model is None:
        if not load_model():
            return {"error": "Model unavailable", "score": -1}

    try:
        feat = extract(url)

        # Trusted domains short-circuit — OCR doesn't change this
        if feat.get("is_trusted"):
            return {
                "url":        url,
                "score":      0,
                "verdict":    "SAFE",
                "confidence": 0.0,
                "highlights": ["No specific risk indicators found in URL structure."],
                "bars":       _param_bars(feat, 0.0),
                "ocr_applied": False,
            }

        # Run ML model
        row = pd.DataFrame([feat])
        for col in _feature_cols:
            if col not in row.columns:
                row[col] = 0
        row = row[_feature_cols].fillna(0).replace([float("inf"), float("-inf")], 0)

        prob      = float(_model.predict_proba(row)[0][1])
        url_score = int(prob * 100)

        # Hard overrides for deterministic signals
        if feat.get("homoglyph_spoof"):
            url_score = max(url_score, 80)
        if feat.get("brand_spoof"):
            url_score = max(url_score, 70)
        age = feat.get("domain_age_days", -1)
        if 0 <= age < 30:
            url_score = max(url_score, 75)

        # Apply OCR combination if score provided
        ocr_applied = False
        if ocr_score >= 0:
            final_score, verdict = combined_score(url_score, ocr_score)
            ocr_applied = True
        else:
            final_score = url_score
            verdict     = _verdict(url_score)

        return {
            "url":          url,
            "score":        final_score,
            "url_score":    url_score,           # raw URL-only score for transparency
            "ocr_score":    ocr_score if ocr_score >= 0 else None,
            "verdict":      verdict,
            "confidence":   round(prob, 3),
            "highlights":   _highlights(feat, verdict),
            "bars":         _param_bars(feat, prob),
            "ocr_applied":  ocr_applied,
        }

    except Exception as e:
        print(f"[LinkLens] Analysis error for {url}: {e}")
        return {"error": str(e), "score": -1}
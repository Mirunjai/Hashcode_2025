"""
analyzer.py — LinkLens Core Analyzer v1.4

Changes:
  - combined_score() now merges URL + OCR + DOM (3 layers)
  - Each layer shown separately in response with own score/verdict
  - WHOIS status reported explicitly (working / failed / unknown)
  - analyze() accepts ocr_score and dom_score as optional params
  - Final score computed from weighted combination of all available layers
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


# ── Verdict ───────────────────────────────────────────────────────────────────

def _verdict(score: int) -> str:
    if score < 30:  return "SAFE"
    if score < 70:  return "SUSPICIOUS"
    return "MALICIOUS"


# ── 4-layer combined scoring ──────────────────────────────────────────────────

def combined_score(
    url_score: int,
    ocr_score: int  = -1,
    dom_score: int  = -1,
) -> tuple[int, str]:
    """
    Merge URL ML score with OCR and DOM scores.

    Layer weights:
      URL  — primary signal, 60% weight when all layers available
      OCR  — page text,      25% weight
      DOM  — page structure, 15% weight

    Hard rules (override weighted average):
      1. Any layer ≥ 70 (MALICIOUS) → final cannot be SAFE
      2. MALICIOUS URL → floor at 70 regardless of other layers
      3. OCR/DOM cannot downgrade MALICIOUS URL to SAFE
      4. OCR/DOM CAN escalate a SAFE URL to SUSPICIOUS or MALICIOUS
    """
    available = [(url_score, 0.60)]
    if ocr_score >= 0:
        available.append((ocr_score, 0.25))
    if dom_score >= 0:
        available.append((dom_score, 0.15))

    # Renormalise weights if some layers missing
    total_weight = sum(w for _, w in available)
    weighted_avg = sum(s * (w / total_weight) for s, w in available)
    final = int(weighted_avg)

    # Hard rule 1: if any layer is MALICIOUS, floor at 65 (at least SUSPICIOUS)
    any_malicious = (
        url_score >= 70 or
        (ocr_score >= 0 and ocr_score >= 70) or
        (dom_score >= 0 and dom_score >= 70)
    )
    if any_malicious:
        final = max(final, 65)

    # Hard rule 2: MALICIOUS URL cannot go below 70
    if url_score >= 70:
        final = max(final, 70)

    # Hard rule 3: if ALL available secondary layers are clean (0),
    # allow softening by up to 10 points — but never below 70 if URL is MALICIOUS
    secondary_scores = [s for s, _ in available[1:]]
    if secondary_scores and all(s == 0 for s in secondary_scores):
        softened = url_score - 10
        if url_score >= 70:
            final = max(softened, 70)   # stays MALICIOUS
        else:
            final = max(softened, 30)   # stays at least SUSPICIOUS

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


def _whois_status(feat: dict) -> dict:
    """Return explicit WHOIS info for display in the scoreboard."""
    age = feat.get("domain_age_days", -1)
    if feat.get("is_trusted"):
        return {"status": "trusted", "age_days": None,
                "label": "Trusted domain — WHOIS skipped"}
    if age == -1:
        return {"status": "failed", "age_days": None,
                "label": "WHOIS lookup failed or timed out"}
    if age == 0:
        return {"status": "new", "age_days": 0,
                "label": "Registered today — extremely suspicious"}
    if age < 30:
        return {"status": "new", "age_days": age,
                "label": f"Brand new domain — {age} days old"}
    if age < 365:
        return {"status": "recent", "age_days": age,
                "label": f"Recently registered — {age} days old"}
    years = age // 365
    return {"status": "old", "age_days": age,
            "label": f"Established domain — ~{years} year{'s' if years > 1 else ''} old"}


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(url: str, ocr_score: int = -1, dom_score: int = -1) -> dict:
    """
    Full analysis pipeline. Accepts optional secondary layer scores.

    Args:
        url       — URL to analyze
        ocr_score — OCR page content score (0-100), or -1 if not run
        dom_score — DOM structure check score (0-100), or -1 if not run

    Returns full result dict with per-layer breakdown and combined score.
    """
    if _model is None:
        if not load_model():
            return {"error": "Model unavailable", "score": -1}

    try:
        feat = extract(url)

        # Trusted domains — short circuit everything
        if feat.get("is_trusted"):
            return {
                "url":          url,
                "score":        0,
                "url_score":    0,
                "verdict":      "SAFE",
                "confidence":   0.0,
                "highlights":   ["Trusted domain — no analysis needed."],
                "bars":         _param_bars(feat, 0.0),
                "whois":        _whois_status(feat),
                "layers": {
                    "url":  {"score": 0,         "verdict": "SAFE",    "weight": "60%"},
                    "ocr":  {"score": ocr_score,  "verdict": "UNKNOWN", "weight": "25%"},
                    "dom":  {"score": dom_score,  "verdict": "UNKNOWN", "weight": "15%"},
                    "whois":{"status": "trusted", "label": "Trusted domain"},
                },
                "ocr_applied": False,
                "dom_applied": False,
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

        # Combined scoring with all available layers
        ocr_applied = ocr_score >= 0
        dom_applied = dom_score >= 0

        if ocr_applied or dom_applied:
            final_score, verdict = combined_score(url_score, ocr_score, dom_score)
        else:
            final_score = url_score
            verdict     = _verdict(url_score)

        whois_info = _whois_status(feat)

        return {
            "url":          url,
            "score":        final_score,
            "url_score":    url_score,
            "verdict":      verdict,
            "confidence":   round(prob, 3),
            "highlights":   _highlights(feat, verdict),
            "bars":         _param_bars(feat, prob),
            "whois":        whois_info,
            "layers": {
                "url":  {
                    "score":   url_score,
                    "verdict": _verdict(url_score),
                    "weight":  "60%",
                },
                "ocr":  {
                    "score":   ocr_score if ocr_applied else None,
                    "verdict": _verdict(ocr_score) if ocr_applied else "PENDING",
                    "weight":  "25%",
                },
                "dom":  {
                    "score":   dom_score if dom_applied else None,
                    "verdict": _verdict(dom_score) if dom_applied else "PENDING",
                    "weight":  "15%",
                },
                "whois": whois_info,
            },
            "ocr_applied":  ocr_applied,
            "dom_applied":  dom_applied,
        }

    except Exception as e:
        print(f"[LinkLens] Analysis error for {url}: {e}")
        return {"error": str(e), "score": -1}
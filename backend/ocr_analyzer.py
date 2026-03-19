"""
ocr_analyzer.py — LinkLens OCR Text Analyzer

Accepts a base64-encoded screenshot of a webpage, extracts visible
text using pytesseract, then scores it for phishing indicators.

Phishing phrases are grouped by risk level:
  CRITICAL — payment, credential theft, account suspension threats
  HIGH     — urgency triggers, verification demands
  MEDIUM   — generic security / update language

Returns a structured result with found phrases, risk level, and
a 0-100 OCR threat score that can be combined with the URL score.
"""

import re
import base64
import io
from PIL import Image
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
# ── Phishing phrase database ──────────────────────────────────────────────────

CRITICAL_PHRASES = [
    "enter your password",
    "confirm your password",
    "enter your credit card",
    "enter your card number",
    "enter your ssn",
    "enter your social security",
    "your account has been suspended",
    "your account will be closed",
    "your account has been locked",
    "verify your identity",
    "confirm your identity",
    "unusual activity detected",
    "unauthorized access",
    "your payment failed",
    "update your billing",
    "enter your bank",
]

HIGH_PHRASES = [
    "verify your account",
    "confirm your account",
    "urgent action required",
    "immediate action required",
    "action required",
    "your account expires",
    "account verification",
    "security alert",
    "security warning",
    "limited time",
    "act now",
    "click here to verify",
    "click here to confirm",
    "validate your account",
    "reactivate your account",
    "login attempt",
    "suspicious login",
]

MEDIUM_PHRASES = [
    "update your information",
    "update your details",
    "update your account",
    "we have noticed",
    "we detected",
    "please verify",
    "please confirm",
    "kindly verify",
    "kindly confirm",
    "dear customer",
    "dear user",
    "dear account holder",
    "your password will expire",
    "reset your password",
]

# Brand impersonation — if these appear alongside phishing phrases it's very suspicious
BRAND_NAMES = [
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "netflix", "bank of america", "chase", "wells fargo", "citibank",
    "instagram", "twitter", "linkedin", "dropbox", "adobe",
]


# ── OCR extraction ────────────────────────────────────────────────────────────

def extract_text(image_base64: str) -> str:
    """Run pytesseract OCR on a base64-encoded image. Returns raw text."""
    try:
        import pytesseract
        img_bytes = base64.b64decode(image_base64)
        img       = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        text      = pytesseract.image_to_string(img, config="--psm 3")
        return text
    except ImportError:
        raise RuntimeError("pytesseract not installed. Run: pip install pytesseract")
    except Exception as e:
        raise RuntimeError(f"OCR failed: {e}")


# ── Phrase matching ───────────────────────────────────────────────────────────

def find_phrases(text: str) -> dict:
    """
    Scan OCR text for phishing phrases.
    Returns dict with found phrases grouped by severity.
    """
    lower = text.lower()
    # Normalise whitespace for matching
    lower = re.sub(r"\s+", " ", lower)

    found = {
        "critical": [p for p in CRITICAL_PHRASES if p in lower],
        "high":     [p for p in HIGH_PHRASES     if p in lower],
        "medium":   [p for p in MEDIUM_PHRASES   if p in lower],
        "brands":   [b for b in BRAND_NAMES      if b in lower],
    }
    return found


def ocr_score(found: dict) -> int:
    """Convert found phrases into a 0-100 threat score."""
    score = 0
    score += len(found["critical"]) * 35
    score += len(found["high"])     * 20
    score += len(found["medium"])   * 10
    # Brand name present alongside phishing phrases amplifies the score
    if found["brands"] and (found["critical"] or found["high"]):
        score += 15
    return min(score, 100)


def ocr_verdict(score: int) -> str:
    if score >= 70: return "MALICIOUS"
    if score >= 30: return "SUSPICIOUS"
    return "SAFE"


def ocr_highlights(found: dict, score: int) -> list[str]:
    """Plain-English bullets for the popup findings panel."""
    notes = []

    if found["critical"]:
        for p in found["critical"][:2]:   # show up to 2
            notes.append(f"CRITICAL text detected: \"{p}\"")

    if found["high"]:
        for p in found["high"][:2]:
            notes.append(f"High-risk phrase found: \"{p}\"")

    if found["brands"] and (found["critical"] or found["high"]):
        brands = ", ".join(found["brands"][:3])
        notes.append(f"Brand impersonation: page mentions {brands}")

    if found["medium"] and not notes:
        notes.append(f"Suspicious language detected on page ({len(found['medium'])} phrases)")

    if not notes:
        notes.append("No phishing phrases found in page text.")

    return notes


# ── Public function ───────────────────────────────────────────────────────────

def analyze_screenshot(image_base64: str) -> dict:
    """
    Full pipeline: base64 image → OCR → phrase matching → scored result.
    Returns a dict ready to merge with the URL analysis result.
    """
    try:
        text  = extract_text(image_base64)
        found = find_phrases(text)
        score = ocr_score(found)

        return {
            "success":        True,
            "ocr_score":      score,
            "ocr_verdict":    ocr_verdict(score),
            "ocr_highlights": ocr_highlights(found, score),
            "ocr_phrases":    found,
            "ocr_text_len":   len(text),
        }

    except RuntimeError as e:
        return {
            "success":        False,
            "error":          str(e),
            "ocr_score":      0,
            "ocr_verdict":    "UNKNOWN",
            "ocr_highlights": [],
            "ocr_phrases":    {},
        }

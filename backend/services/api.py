from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional
import requests
import base64

app = FastAPI()

# Allow frontend/extension to call backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# Pydantic model
# ----------------------------
class ScanRequest(BaseModel):
    url: HttpUrl
    screenshot_base64: Optional[str] = None
    user_id: Optional[str] = None
    timestamp: Optional[str] = None

# ----------------------------
# Feature extraction functions
# ----------------------------
def extract_url_features(url: str) -> dict:
    return {
        "has_dash": int("-" in url),
        "length": len(url),
        "num_digits": sum(c.isdigit() for c in url)
    }

def extract_html_features(html: str) -> dict:
    return {
        "has_form": int("<form" in html),
        "has_password": int("password" in html),
        "num_links": html.count("<a ")
    }

def extract_ocr_features(img_bytes: bytes) -> dict:
    # Placeholder OCR logic; replace with actual OCR extraction
    text = "example"
    return {
        "login_word": int("login" in text.lower()),
        "verify_word": int("verify" in text.lower())
    }

# ----------------------------
# ML scoring functions
# ----------------------------
def ml_score_url(features: dict) -> float:
    return min(0.3 * features.get("has_dash",0) + 0.2 * (features.get("length",0)/100), 1.0)

def ml_score_html(features: dict) -> float:
    return min(0.25 * features.get("has_form",0) + 0.25 * features.get("has_password",0), 1.0)

def ml_score_ocr(features: dict) -> float:
    return min(0.25 * features.get("login_word",0) + 0.25 * features.get("verify_word",0), 1.0)

def ml_final_score(url_score, html_score, ocr_score, weights=None) -> float:
    if not weights:
        weights = {"url":0.4, "html":0.3, "ocr":0.3}
    total = url_score*weights["url"] + html_score*weights["html"] + ocr_score*weights["ocr"]
    return min(total, 1.0)

# ----------------------------
# API endpoint
# ----------------------------
@app.post("/api/scan-url")
def scan_url(req: ScanRequest):
    url = req.url
    screenshot = req.screenshot_base64

    # 1️⃣ Extract URL features
    url_feats = extract_url_features(url)

    # 2️⃣ Extract HTML features
    try:
        html_content = requests.get(url, timeout=2).text
        html_feats = extract_html_features(html_content)
    except:
        html_feats = {"has_form":0, "has_password":0, "num_links":0}

    # 3️⃣ Extract OCR features (optional)
    if screenshot:
        img_bytes = base64.b64decode(screenshot)
        ocr_feats = extract_ocr_features(img_bytes)
    else:
        ocr_feats = {}

    # 4️⃣ ML-based scores per parameter
    score_url = ml_score_url(url_feats)
    score_html = ml_score_html(html_feats)
    score_ocr = ml_score_ocr(ocr_feats)

    # 5️⃣ Combine scores for final threat score
    threat_score = ml_final_score(score_url, score_html, score_ocr)

    # 6️⃣ Decide allow/block
    allow = threat_score < 0.5

    # 7️⃣ Return JSON with all details
    return {
        "url": url,
        "threat_score": threat_score,
        "allow": allow,
        "scores": {
            "url_score": score_url,
            "html_score": score_html,
            "ocr_score": score_ocr
        },
        "features": {
            "url": url_feats,
            "html": html_feats,
            "ocr": ocr_feats
        }
    }

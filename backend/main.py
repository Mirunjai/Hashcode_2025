"""
main.py — LinkLens API v1.3
Endpoints:
  GET  /              — health check
  POST /analyze       — URL analysis (optional ocr_score for combined scoring)
  POST /decode-qr     — QR image decode + analyze
  POST /analyze-page  — OCR screenshot analysis
"""

import base64
import io
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from analyzer import analyze
from ocr_analyzer import analyze_screenshot


@asynccontextmanager
async def lifespan(app: FastAPI):
    from analyzer import load_model
    load_model()
    yield


app = FastAPI(title="LinkLens API", version="1.3.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["chrome-extension://*", "http://localhost:5173"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


# ── Schemas ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url:       HttpUrl
    ocr_score: Optional[int] = -1   # pass OCR score to get combined result

class QRRequest(BaseModel):
    image_base64: str

class PageRequest(BaseModel):
    url:          str
    image_base64: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/")
def health():
    return {"status": "ok", "service": "LinkLens", "version": "1.3.0"}


@app.post("/analyze")
def analyze_url(req: ScanRequest):
    return analyze(str(req.url), ocr_score=req.ocr_score or -1)


@app.post("/decode-qr")
def decode_qr(req: QRRequest):
    try:
        from pyzbar.pyzbar import decode as qr_decode
        from PIL import Image
    except ImportError:
        return {"success": False,
                "error": "pyzbar/pillow not installed. Run: pip install pyzbar pillow"}
    try:
        img_bytes = base64.b64decode(req.image_base64)
        img       = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        codes     = qr_decode(img)
        if not codes:
            return {"success": False, "error": "No QR code found in image."}
        raw = codes[0].data.decode("utf-8", errors="ignore").strip()
        if not raw.startswith("http"):
            return {"success": False, "error": f"QR content is not a URL: {raw}"}
        result            = analyze(raw)
        result["qr_url"]  = raw
        result["success"] = True
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/analyze-page")
def analyze_page(req: PageRequest):
    """
    Run OCR on a webpage screenshot.
    The extension calls this after the URL scan, then can re-call
    /analyze passing the returned ocr_score to get a combined verdict.
    """
    result        = analyze_screenshot(req.image_base64)
    result["url"] = req.url
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
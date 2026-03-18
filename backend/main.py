"""
main.py — LinkLens API
Entry point. Starts FastAPI, loads the ML model on startup,
exposes the single /analyze endpoint.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from analyzer import analyze


# ── Startup / shutdown ────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    from analyzer import load_model
    load_model()
    yield


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="LinkLens API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["chrome-extension://*", "http://localhost:5173"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


# ── Schema ────────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    url: HttpUrl


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/")
def health():
    return {"status": "ok", "service": "LinkLens"}


@app.post("/analyze")
def analyze_url(req: ScanRequest):
    return analyze(str(req.url))


# ── Run directly ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

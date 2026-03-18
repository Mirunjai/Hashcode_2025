# main_api.py (FINAL VERSION with modern lifespan event)
import uvicorn
from fastapi import FastAPI, Request
from pydantic import BaseModel, HttpUrl
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager # <-- NEW IMPORT

from orchestrator import orchestrate_url_analysis 
from ml_handler import init_ml_handler 

# --- 1. DEFINE THE NEW LIFESPAN FUNCTION ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Code to run on startup
    print("--- [API SERVER] Lifespan event: Triggering ML Model Load ---")
    success = init_ml_handler(model_path="models/phishing_model.joblib")
    if not success:
        print("--- [API SERVER] FATAL ERROR: Machine Learning Model could not be loaded. ---")
    
    yield # The API is running at this point
    
    # Code to run on shutdown
    print("--- [API SERVER] Lifespan event: Shutting down. ---")

# --- 2. CREATE THE APP AND CONNECT THE LIFESPAN FUNCTION ---
app = FastAPI(
    title="PhishEye Zero-Day Threat Analysis API",
    description="An API focused on detecting new and unknown phishing threats.",
    version="1.5.0",
    lifespan=lifespan # <-- Connects the function to the app
)

# --- (Your CORS settings are perfect, no changes needed) ---
origins = ["chrome-extension://*", "http://localhost:5173"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- (Your endpoint code remains exactly the same) ---
class URLRequest(BaseModel):
    url: HttpUrl
    screenshot_base64: Optional[str] = None

@app.get("/", tags=["Health Check"])
def health_check():
    return {"status": "PhishEye Zero-Day Hunter API is active!"}

@app.post("/api/v1/analyze", tags=["Core Analysis"])
async def analyze_url_endpoint(request: URLRequest):
    report = orchestrate_url_analysis(str(request.url))
    return report

if __name__ == "__main__":
    uvicorn.run("main_api:app", host="0.0.0.0", port=8000, reload=True)
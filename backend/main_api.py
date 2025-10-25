# main_api.py (FINAL, CORRECTED VERSION with CORS)
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl
from typing import Optional

# --- 1. IMPORT THE CORS MIDDLEWARE ---
from fastapi.middleware.cors import CORSMiddleware

from ml_handler import init_ml_handler
from orchestrator import orchestrate_url_analysis

# Initialize the FastAPI app
app = FastAPI(
    title="PhishEye Zero-Day Threat Analysis API",
    description="An API focused on detecting new and unknown phishing threats.",
    version="1.1.0"
)

# =========================================================================
# V V V V  THIS IS THE NEW CODE YOU MUST ADD  V V V V
# =========================================================================

# --- 2. DEFINE ALLOWED ORIGINS ---
# This tells your server which websites are allowed to request data from it.
origins = [
    # A wildcard for Chrome extensions is okay for local development.
    # It allows any extension running in your browser to connect.
    "chrome-extension://*",
    
    # Also add the default address for your Vite React dev server
    "http://localhost:5173", 
]

# --- 3. ADD THE CORS MIDDLEWARE TO YOUR APP ---
# This is the "permission slip" that allows your React frontend
# to communicate with your Python backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allows all headers
)

# =========================================================================
# ^ ^ ^ ^  END OF THE NEW CODE  ^ ^ ^ ^
# =========================================================================


# --- The rest of your file remains exactly the same ---

@app.on_event("startup")
def load_ml_model_on_startup():
    """
    This function runs ONCE when the API server starts.
    It loads the ML model into memory.
    """
    print("--- [API SERVER] Triggering ML Model Load ---")
    success = init_ml_handler(model_path="models/phishing_model.joblib")
    if not success:
        print("FATAL ERROR: Machine Learning Model could not be loaded.")

# Pydantic model for the request body
class URLRequest(BaseModel):
    url: HttpUrl
    screenshot_base64: Optional[str] = None # For future OCR use

@app.get("/", tags=["Health Check"])
def health_check():
    return {"status": "PhishEye Zero-Day Hunter API is active!"}

@app.post("/api/v1/analyze", tags=["Core Analysis"])
async def analyze_url_endpoint(request: URLRequest):
    """
    Receives a URL and returns a full threat analysis report with a focus
    on zero-day phishing indicators.
    """
    report = orchestrate_url_analysis(str(request.url), request.screenshot_base64)
    return report

# Standard entry point to run the server
if __name__ == "__main__":
    uvicorn.run("main_api:app", host="0.0.0.0", port=8000, reload=True)
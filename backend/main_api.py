# main_api.py (NEW VERSION)
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl
from typing import Optional

# --- KEY CHANGES START HERE ---
# 1. Import the ML handler's initialization function
from ml_handler import init_ml_handler
# 2. Import your orchestrator
from orchestrator import orchestrate_url_analysis
# --- KEY CHANGES END HERE ---

# Initialize the FastAPI app
app = FastAPI(
    title="PhishEye Zero-Day Threat Analysis API",
    description="An API focused on detecting new and unknown phishing threats.",
    version="1.1.0"
)

# --- ADD THIS STARTUP EVENT ---
@app.on_event("startup")
def load_ml_model_on_startup():
    """
    This function runs ONCE when the API server starts.
    It loads the ML model into memory.
    """
    print("--- [API SERVER] Triggering ML Model Load ---")
    # This calls the load_model() method on the singleton instance
    success = init_ml_handler(model_path="models/phishing_model.joblib")
    if not success:
        print("FATAL ERROR: Machine Learning Model could not be loaded.")
        # In a real app, you might want to prevent the server from starting
        # but for a hackathon, a loud error message is fine.

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
    # The call to the orchestrator remains the same.
    # The magic now happens inside the orchestrator.
    report = orchestrate_url_analysis(str(request.url), request.screenshot_base64)
    return report

# Standard entry point to run the server
if __name__ == "__main__":
    uvicorn.run("main_api:app", host="0.0.0.0", port=8000, reload=True)
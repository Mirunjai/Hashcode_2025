# main_api.py
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl
from typing import Optional
from orchestrator import orchestrate_url_analysis

# Initialize the FastAPI app
app = FastAPI(
    title="PhishEye Zero-Day Threat Analysis API",
    description="An API focused on detecting new and unknown phishing threats.",
    version="1.1.0"
)

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
    report = orchestrate_url_analysis(request.url, request.screenshot_base64)
    return report

# Standard entry point to run the server
if __name__ == "__main__":
    uvicorn.run("main_api:app", host="0.0.0.0", port=8000, reload=True)
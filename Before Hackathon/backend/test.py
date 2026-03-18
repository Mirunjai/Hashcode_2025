# test_backend.py
import requests
import json

# The address of your running FastAPI server
API_URL = "http://localhost:8000/api/v1/analyze"

def test_url(url_to_test: str):
    """Sends a URL to the backend and prints the response."""
    print(f"\n{'='*50}")
    print(f">>> TESTING URL: {url_to_test}")
    print(f"{'='*50}")
    
    try:
        # Prepare the data in the format the API expects
        payload = {"url": url_to_test}
        
        # Send the POST request to your running server
        response = requests.post(API_URL, json=payload)
        response.raise_for_status() 
        
        # Parse the JSON response from your API and print it nicely
        report = response.json()
        print("✅ SUCCESS! Got a valid response from the API:")
        print(json.dumps(report, indent=2))
        
    except requests.exceptions.RequestException as e:
        print(f"❌ TEST FAILED: Could not connect to the API. Is the server running? Error: {e}")

# --- URLs to Test ---
if __name__ == "__main__":
    # A known safe URL. Expect a LOW score and SAFE verdict.
    test_url("https://rural-indicate-bat-dem.trycloudflare.com")
    
    # A known suspicious URL. Expect a HIGH score and MALICIOUS verdict.
    test_url("http://secure-login-apple-id.com-verify.net")
# This script simulates how the backend will use your ML model.
# It should work without needing to run train_model.py again.

from ml_handler import ml_handler, init_ml_handler

def run_prediction_test():
    """
    Loads the model using the handler and predicts a list of test URLs.
    """
    print("--- Starting ML Model Integration Test ---")

    # 1. Initialize the ML Handler (This loads the model from the file)
    # This is the function the backend will call at startup.
    model_loaded = init_ml_handler()

    if not model_loaded:
        print("\n[FATAL] Model could not be loaded. Check 'models/phishing_model.joblib' exists.")
        return

    print("\n--- Model Loaded Successfully. Ready for Predictions. ---\n")

    # 2. Define a list of URLs to test
    test_urls = [
        # Obvious Phishing URLs
        "http://verify-your-bank-account-details.com/login",
        "https://apple-id-security-update-x9z.net/websrc",
        # Obvious Legitimate URLs
        "https://github.com/scikit-learn/scikit-learn",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        # Edge Cases
        "http://142.250.190.78", # IP Address URL (Google's IP)
        "https://你好.com" # Non-ASCII URL
    ]

    # 3. Predict each URL using the handler
    for url in test_urls:
        print(f"-> Analyzing URL: {url}")
        
        # This is the exact function the backend will call for each request.
        result = ml_handler.predict_url(url)
        
        if result['success']:
            print(f"   Verdict: {result['verdict']}")
            print(f"   Score:   {result['threat_score']}/100")
            print(f"   Action:  {result['action']}")
        else:
            print(f"   [ERROR] Prediction failed: {result.get('error', 'Unknown error')}")
        print("-" * 30)

if __name__ == "__main__":
    run_prediction_test()
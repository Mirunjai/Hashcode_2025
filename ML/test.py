# This script is the final check. It loads the fully trained model 
# and runs a few examples to ensure it's making smart predictions.

from ml_handler import ml_handler, init_ml_handler

def run_prediction_test():
    """
    Loads the trained model from the file and predicts a list of test URLs.
    """
    print("\n" + "="*50)
    print("--- RUNNING FINAL MODEL INTEGRATION TEST ---")
    print("="*50)

    # 1. Initialize the ML Handler. This loads the model from the .joblib file.
    # This is exactly what the backend server will do when it starts.
    model_loaded = init_ml_handler()

    if not model_loaded:
        print("\n[FATAL TEST FAILURE]")
        print("Model could not be loaded. This means 'models/phishing_model.joblib' is missing or corrupted.")
        print("Please run train_model.py successfully before running this test.")
        return

    print("\n--- Model Loaded Successfully. Beginning Predictions. ---\n")

    # 2. A list of diverse URLs to test the model's intelligence
    test_urls = [
        # --- Expected to be MALICIOUS (High Score) ---
        "http://secure-login-update-account-paypal.com/websrc",
        "https://apple-id-security-alert-x9z.org/login.php",
        "http://bankofamerica-online-secure-session.net/verify",
        
        # --- Expected to be SAFE (Low Score) ---
        "https://github.com/scikit-learn/scikit-learn",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://www.google.com/search?q=hello+world",
        
        # --- Edge Cases ---
        "http://142.250.190.78/some/path",  # IP Address URL (should be suspicious/malicious)
        "https://example.com/login-form-here", # "login" keyword on a safe domain
    ]

    # 3. Predict each URL and print the results clearly
    all_tests_passed = True
    for url in test_urls:
        print(f"-> Analyzing URL: {url}")
        
        # This is the function that gives the final result
        result = ml_handler.predict_url(url)
        
        if result['success']:
            verdict = result['verdict']
            score = result['threat_score']
            print(f"   Verdict: {verdict}")
            print(f"   Score:   {score}/100")
            
            # Basic logic check
            if "login" in url or "secure" in url or ".net" in url or ".org" in url:
                if score < 70:
                    print("   [TEST WARNING] Expected a higher score for this suspicious URL.")
                    all_tests_passed = False
            if "github" in url or "wikipedia" in url or "google" in url:
                if score > 30:
                     print("   [TEST WARNING] Expected a lower score for this legitimate URL.")
                     all_tests_passed = False
        else:
            print(f"   [TEST FAILED] Prediction failed: {result.get('error', 'Unknown error')}")
            all_tests_passed = False
        print("-" * 40)

    print("\n--- TEST SUMMARY ---")
    if all_tests_passed:
        print("✅ All tests passed. The model is behaving as expected!")
    else:
        print("❌ Some tests failed or showed warnings. Review the scores above.")
    print("="*50)


if __name__ == "__main__":
    run_prediction_test()
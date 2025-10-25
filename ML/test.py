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
        "http://paypal-verify-account-security.com/login",  # Obvious phishing
        
        # --- Expected to be SAFE (Low Score) ---
        "https://github.com/scikit-learn/scikit-learn",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://www.google.com/search?q=hello+world",
        "https://paypal.com",  # Legitimate PayPal
        "https://www.apple.com",  # Legitimate Apple
        
        # --- Edge Cases ---
        "http://142.250.190.78/some/path",  # IP Address URL (suspicious)
        "https://example.com/login-form-here", # "login" keyword on safe domain
        "https://your-bank.com/secure-login",  # Generic but legitimate
    ]

    # 3. Predict each URL and print the results clearly
    all_tests_passed = True
    
    print("EXPECTED PATTERNS:")
    print("- Phishing: domains with brand names + security words")
    print("- Safe: legitimate domains, even with 'login' paths")
    print("- Suspicious: IP addresses, unusual domains\n")
    
    for url in test_urls:
        print(f"-> Analyzing URL: {url}")
        
        # This is the function that gives the final result
        result = ml_handler.predict_url(url)
        
        if result['success']:
            verdict = result['verdict']
            score = result['threat_score']
            print(f"   Verdict: {verdict}")
            print(f"   Score:   {score}/100")
            
            # More intelligent test logic
            if "paypal-verify" in url or "apple-id-security" in url or "bankofamerica-online" in url:
                if score < 50:  # Lower threshold for obvious phishing
                    print("   ❌ [TEST FAILED] Expected higher score for obvious phishing URL.")
                    all_tests_passed = False
                else:
                    print("   ✅ Correctly identified as suspicious/malicious")
            
            elif "paypal.com" in url or "apple.com" in url or "github.com" in url:
                if score > 40:  # Higher threshold for legitimate sites
                    print("   ❌ [TEST FAILED] Expected lower score for legitimate domain.")
                    all_tests_passed = False
                else:
                    print("   ✅ Correctly identified as safe")
                    
            elif "142.250.190.78" in url:  # IP address
                if score < 30:
                    print("   ⚠️  [NOTE] IP address scored lower than expected")
                else:
                    print("   ✅ Correctly flagged IP address as suspicious")
                    
        else:
            print(f"   ❌ [TEST FAILED] Prediction failed: {result.get('error', 'Unknown error')}")
            all_tests_passed = False
        print("-" * 40)

    print("\n--- TEST SUMMARY ---")
    if all_tests_passed:
        print("✅ All tests passed. The model is behaving as expected!")
    else:
        print("❌ Some tests failed. The model needs improvement.")
        print("\nTROUBLESHOOTING STEPS:")
        print("1. Check if your training data is properly balanced")
        print("2. Verify feature extraction is working correctly")
        print("3. Ensure the model was trained with sufficient data")
        print("4. Check the distribution of your training dataset")
    print("="*50)

    # Additional diagnostic: Show model info
    print("\n--- MODEL DIAGNOSTICS ---")
    model_info = ml_handler.get_model_info()
    print(f"Model type: {model_info.get('model_type', 'Unknown')}")
    print(f"Features used: {model_info.get('feature_count', 'Unknown')}")
    print(f"Model fitted: {model_info.get('is_fitted', 'Unknown')}")


if __name__ == "__main__":
    run_prediction_test()
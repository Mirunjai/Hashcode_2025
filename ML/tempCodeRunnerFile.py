# test_final_system.py
from ml_handler import MLHandler

def test_final_system():
    """Test the complete system with the WHOIS-trained model"""
    
    print("🧪 FINAL SYSTEM TEST WITH WHOIS-TRAINED MODEL")
    print("=" * 60)
    
    # Use the new WHOIS-enabled model
    ml_handler = MLHandler(
        model_path="ML/models/phishing_model.joblib", 
        enable_whois=True
    )
    
    if not ml_handler.load_model():
        print("❌ Failed to load model. Please train with WHOIS first.")
        return
    
    test_urls = [
        # Legitimate (should have low scores)
        "https://github.com/scikit-learn/scikit-learn",
        "https://paypal.com",
        "https://google.com",
        "https://www.apple.com",
        
        # Suspicious (should have medium scores)
        "https://example.com/login-form-here",
        "https://your-bank.com/secure-login",
        
        # Likely phishing (should have high scores)
        "http://secure-paypal-account-verify.com/login",
        "http://apple-id-security-confirm.com",
        "http://nonexistent-test-12345.com",
        "http://192.168.1.1/login.php"
    ]
    
    print("\n📊 PREDICTION RESULTS:")
    print("-" * 80)
    
    for url in test_urls:
        result = ml_handler.predict_url(url)
        
        if result['success']:
            # Get WHOIS info from features
            features = ml_handler.feature_extractor.extract_features(url)
            domain_age = features.get('domain_age', -1)
            whois_failed = features.get('whois_lookup_failed', -1)
            is_trusted = features.get('is_trusted_domain', 0)
            
            # Determine expected result
            if is_trusted == 1 or domain_age > 365:  # Trusted or >1 year old
                expected = "LOW"
            elif whois_failed == 1 or domain_age == -1:  # WHOIS failed or no age
                expected = "HIGH" 
            else:
                expected = "MEDIUM"
            
            # Score analysis
            score = result['threat_score']
            if score < 30:
                actual = "LOW"
            elif score < 70:
                actual = "MEDIUM"
            else:
                actual = "HIGH"
            
            match = "✅" if expected == actual else "❌"
            
            print(f"{match} {url}")
            print(f"   Score: {score}/100 | Verdict: {result['verdict']}")
            print(f"   Domain Age: {domain_age} days | WHOIS Failed: {whois_failed} | Trusted: {is_trusted}")
            print(f"   Expected: {expected} | Actual: {actual}")
        else:
            print(f"❌ {url}")
            print(f"   Error: {result.get('error', 'Unknown error')}")
        
        print()

if __name__ == "__main__":
    test_final_system()
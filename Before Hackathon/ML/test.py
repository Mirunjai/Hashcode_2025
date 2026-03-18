# test_hybrid_approach.py
from whois_enhanced_predictor import whois_predictor

def test_hybrid_system():
    """Test the hybrid approach (robust base + WHOIS enhancement)"""
    
    print("🧪 HYBRID SYSTEM TEST: Robust Base + WHOIS Enhancement")
    print("=" * 60)
    
    if not whois_predictor.load_model():
        print("❌ Failed to load model.")
        return
    
    test_urls = [
        # Legitimate (should have low scores)
        "https://github.com/scikit-learn/scikit-learn",
        "https://paypal.com",
        "https://google.com",
        "https://www.apple.com",
        
        # Suspicious 
        "https://example.com/login-form-here",
        "https://your-bank.com/secure-login",
        
        # Likely phishing (should have high scores)
        "http://secure-paypal-account-verify.com/login",
        "http://apple-id-security-confirm.com",
        "http://nonexistent-test-12345.com",
        "http://192.168.1.1/login.php"
    ]
    
    print("\n📊 HYBRID PREDICTION RESULTS:")
    print("-" * 80)
    
    for url in test_urls:
        result = whois_predictor.predict_with_whois_enhancement(url)
        
        if result['success']:
            print(f"🔗 {url}")
            print(f"   Final Score: {result['threat_score']}/100")
            print(f"   Base Score: {result['base_score']}/100")
            print(f"   WHOIS Adjustment: {result['whois_adjustment']:+d}")
            print(f"   Verdict: {result['verdict']}")
            print(f"   Domain Age: {result['domain_age']} days")
            print(f"   WHOIS Failed: {result['whois_failed']}")
            print(f"   Trusted: {result['is_trusted']}")
            
            # Evaluate result
            if result['is_trusted'] == 1 and result['threat_score'] < 30:
                print("   ✅ Correctly identified as safe")
            elif result['whois_failed'] == 1 and result['threat_score'] > 60:
                print("   ✅ Correctly flagged as suspicious")
            else:
                print("   ⚠️  Review needed")
        else:
            print(f"❌ {url} - Error: {result.get('error', 'Unknown')}")
        
        print()

if __name__ == "__main__":
    test_hybrid_system()
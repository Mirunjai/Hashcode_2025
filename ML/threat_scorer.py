# threat_scorer.py
import joblib
from feature_extractor import FeatureExtractor

class ThreatScorer:
    def __init__(self, model_path='phishing_model.pkl'):
        print("Loading ML model...")
        self.model = joblib.load(model_path)
        self.feature_extractor = FeatureExtractor()
        print("Threat scorer ready!")
    
    def analyze_url(self, url):
        """Main function that backend will call"""
        print(f"Analyzing: {url}")
        
        # Extract features
        features = self.feature_extractor.extract_features(url)
        
        # Get ML prediction probability
        probability = self.model.predict_proba([features])[0][1]  # Probability it's phishing
        threat_score = int(probability * 100)
        
        # Determine verdict
        if threat_score < 30:
            verdict = "🟢 SAFE"
            action = "Allow access"
        elif threat_score < 70:
            verdict = "🟡 SUSPICIOUS" 
            action = "Show warning"
        else:
            verdict = "🔴 MALICIOUS"
            action = "BLOCK ACCESS"
        
        return {
            'threat_score': threat_score,
            'verdict': verdict,
            'action': action,
            'confidence': round(probability, 3),
            'features_analyzed': len(features)
        }

# DEMO FUNCTION
def demo():
    scorer = ThreatScorer()
    
    test_urls = [
        "http://fake-paypal-account-verify.com",
        "https://paypal.com",
        "http://netflix-billing-update-security.com", 
        "https://github.com",
        "http://192.168.1.1/login.php"
    ]
    
    print("\n" + "="*50)
    print("PHISHING DETECTION DEMO")
    print("="*50)
    
    for url in test_urls:
        result = scorer.analyze_url(url)
        print(f"\nURL: {url}")
        print(f"Threat Score: {result['threat_score']}/100")
        print(f"Verdict: {result['verdict']}")
        print(f"Action: {result['action']}")
        print(f"Confidence: {result['confidence']:.1%}")
        print("-" * 30)

if __name__ == "__main__":
    demo()
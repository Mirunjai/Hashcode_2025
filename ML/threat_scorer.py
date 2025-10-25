import joblib
from feature_extractor import FeatureExtractor

class ThreatScorer:
    def __init__(self, model_path='phishing_model.pkl'):
        """Initializes the scorer by loading the trained ML model."""
        print("🧠 Loading ML model and feature extractor...")
        self.model = joblib.load(model_path)
        self.feature_extractor = FeatureExtractor()
        print("✅ Threat scorer is ready!")
    
    def analyze_url(self, url):
        """
        Analyzes a single URL and returns a detailed threat assessment.
        """
        print(f"\n🔎 Analyzing: {url}")
        
        # Extract both the dictionary (for analysis) and the list (for prediction)
        features_dict, features_list = self.feature_extractor.extract_features(url)
        
        # Get ML prediction probability
        probability = self.model.predict_proba([features_list])[0][1] # Probability it's phishing
        threat_score = int(probability * 100)
        
        # --- Generate Verdict and Action ---
        if threat_score < 30:
            verdict = "🟢 SAFE"
            action = "Allow access"
        elif threat_score < 70:
            verdict = "🟡 SUSPICIOUS" 
            action = "Show a warning to the user"
        else:
            verdict = "🔴 MALICIOUS"
            action = "BLOCK ACCESS immediately"
            
        # --- Generate Reasoning Highlights ---
        highlights = []
        if features_dict['domain_age_days'] != -1 and features_dict['domain_age_days'] < 180:
            highlights.append(f"HIGH RISK: Domain is very new (only {features_dict['domain_age_days']} days old).")
        if not features_dict['is_https']:
            highlights.append("RISK: Connection is not secure (HTTP).")
        if features_dict['has_ip']:
            highlights.append("HIGH RISK: URL uses a direct IP address, hiding its domain.")
        if features_dict['num_hyphens'] > 2:
            highlights.append("SUSPICIOUS: URL contains multiple hyphens, a common phishing tactic.")
        if probability > 0.5 and not highlights:
             highlights.append("SUSPICIOUS: The URL's structure matches common phishing patterns learned by the model.")

        return {
            'url': url,
            'threat_score': threat_score,
            'verdict': verdict,
            'action': action,
            'confidence': f"{probability:.2%}",
            'reasoning_highlights': highlights if highlights else ["This URL appears to be safe."]
        }

# --- DEMO FUNCTION ---
def demo():
    scorer = ThreatScorer()
    
    test_urls = [
        "http://paypal-verify-account-secure-logins.com", # Should be high risk
        "https://www.github.com/scikit-learn",             # Should be safe
        "http://193.56.29.141/login/index.php"             # Should be high risk (IP)
    ]
    
    print("\n" + "="*50)
    print("ADVANCED PHISHING DETECTION DEMO")
    print("="*50)
    
    for url in test_urls:
        result = scorer.analyze_url(url)
        print(f"URL: {result['url']}")
        print(f"Threat Score: {result['threat_score']}/100 | Verdict: {result['verdict']}")
        print("Reasoning:")
        for reason in result['reasoning_highlights']:
            print(f"  - {reason}")
        print("-" * 50)

if __name__ == "__main__":
    demo()
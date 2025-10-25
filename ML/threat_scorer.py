# threat_scorer.py
import joblib
import pandas as pd
from feature_extractor import FeatureExtractor

class AdvancedThreatScorer:
    def __init__(self, model_path='models/phishing_model.joblib'):
        print("🧠 Loading ADVANCED ML model...")
        try:
            model_payload = joblib.load(model_path)
            self.model = model_payload['model']
            self.feature_names = model_payload['feature_names']
            self.feature_extractor = FeatureExtractor()
            print("✅ Advanced threat scorer ready!")
            print(f"📊 Using {len(self.feature_names)} features")
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            raise
    
    def analyze_url(self, url):
        """Analyze URL with advanced features"""
        print(f"🔍 Analyzing: {url}")
        
        try:
            # Extract features using your advanced extractor
            features_dict = self.feature_extractor.extract_features(url)
            
            # Convert to DataFrame with same column order as training
            features_df = pd.DataFrame([features_dict])
            
            # Ensure all expected features are present
            for feature in self.feature_names:
                if feature not in features_df.columns:
                    features_df[feature] = -1  # Default value for missing features
            
            # Reorder columns to match training
            features_df = features_df[self.feature_names]
            
            # Handle any infinite/NaN values
            features_df = features_df.replace([float('inf'), float('-inf')], 0)
            features_df = features_df.fillna(-1)
            
            # Get prediction
            probability = self.model.predict_proba(features_df)[0][1]
            threat_score = int(probability * 100)
            
            # Determine verdict
            if threat_score < 25:
                verdict = "🟢 SAFE"
                action = "Allow access"
            elif threat_score < 65:
                verdict = "SUSPICIOUS" 
                action = "Show warning"
            else:
                verdict = "MALICIOUS"
                action = "BLOCK ACCESS"
            
            # Get top contributing features
            contributing_features = self._get_contributing_features(features_df.iloc[0])
            
            return {
                'threat_score': threat_score,
                'verdict': verdict,
                'action': action,
                'confidence': round(probability, 3),
                'features_analyzed': len(features_dict),
                'top_contributors': contributing_features[:3],  # Top 3 contributing features
                'domain_age': features_dict.get('domain_age', 'Unknown'),
                'keyword_count': features_dict.get('keyword_count', 0)
            }
            
        except Exception as e:
            print(f"Error analyzing URL: {e}")
            return {
                'threat_score': -1,
                'verdict': "ERROR",
                'action': "Review manually",
                'confidence': 0,
                'error': str(e)
            }
    
    def _get_contributing_features(self, features_series):
        """Get features that contributed most to the decision"""
        importances = self.model.feature_importances_
        feature_contributions = []
        
        for i, (feature, value) in enumerate(features_series.items()):
            if i < len(importances):
                contribution = importances[i] * abs(value)
                feature_contributions.append((feature, contribution))
        
        # Sort by contribution
        return sorted(feature_contributions, key=lambda x: x[1], reverse=True)

# DEMO FUNCTION
def demo_advanced():
    scorer = AdvancedThreatScorer()
    
    test_urls = [
        "http://verify-paypal-account-security-login.com",
        "https://paypal.com",
        "http://amazon-account-verification-update.net",
        "https://github.com",
        "http://192.168.1.1/login.php",
        "http://apple-id-confirm-secure.com"
    ]
    
    print("\n" + "="*60)
    print("ADVANCED PHISHING DETECTION DEMO")
    print("="*60)
    
    for url in test_urls:
        result = scorer.analyze_url(url)
        print(f"\nURL: {url}")
        print(f"Threat Score: {result['threat_score']}/100")
        print(f"Verdict: {result['verdict']}")
        print(f"Action: {result['action']}")
        print(f"Confidence: {result['confidence']:.1%}")
        
        if 'top_contributors' in result:
            print(f"Top Contributors: {result['top_contributors'][:2]}")
        if 'domain_age' in result and result['domain_age'] != -1:
            print(f"Domain Age: {result['domain_age']} days")
        
        print("-" * 40)

if __name__ == "__main__":
    demo_advanced()
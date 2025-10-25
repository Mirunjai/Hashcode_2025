# whois_enhanced_predictor.py
import joblib
import pandas as pd
from pathlib import Path

class WHOISEnhancedPredictor:
    """
    Uses a robust base model and enhances predictions with WHOIS data
    """
    
    def __init__(self, model_path: str = "ML/models/phishing_model_robust.joblib"):
        self.model_path = Path(model_path)
        self.base_model = None
        self.feature_names = None
        self.feature_extractor = None
        self.is_loaded = False
        
    def load_model(self):
        """Load the robust base model"""
        try:
            if not self.model_path.exists():
                raise FileNotFoundError(f"Model file not found: {self.model_path}")
            
            print("Loading robust base model...")
            model_payload = joblib.load(self.model_path)
            
            self.base_model = model_payload['model']
            self.feature_names = model_payload.get('feature_names', [])
            # Use WHOIS-enabled extractor for prediction
            from feature_extractor import FeatureExtractor
            self.feature_extractor = FeatureExtractor(enable_whois=True)
            self.is_loaded = True
            
            print(f"✅ Robust model loaded successfully!")
            print(f"   Features: {len(self.feature_names)}")
            print(f"   Model type: {type(self.base_model).__name__}")
            print(f"   WHOIS enabled for prediction: True")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to load model: {e}")
            self.is_loaded = False
            return False
    
    def predict_with_whois_enhancement(self, url: str) -> dict:
        """
        Make prediction with WHOIS-based score adjustment
        """
        if not self.is_loaded:
            success = self.load_model()
            if not success:
                return self._error_response("Model not loaded")
        
        try:
            # Extract features with WHOIS
            features_dict = self.feature_extractor.extract_features(url)
            
            # Prepare features for base model (exclude WHOIS features)
            base_features = {k: v for k, v in features_dict.items() if k in self.feature_names}
            features_df = pd.DataFrame([base_features])
            
            # Ensure all expected features are present
            for feature in self.feature_names:
                if feature not in features_df.columns:
                    features_df[feature] = -1
            
            features_df = features_df[self.feature_names]
            features_df = features_df.fillna(-1).replace([float('inf'), float('-inf')], -1)
            
            # Get base prediction
            base_probability = self.base_model.predict_proba(features_df)[0][1]
            base_score = int(base_probability * 100)
            
            # Apply WHOIS enhancements
            final_score = self._apply_whois_enhancement(base_score, features_dict)
            
            # Generate verdict
            verdict, action = self._classify_threat(final_score)
            
            return {
                'success': True,
                'threat_score': final_score,
                'base_score': base_score,
                'whois_adjustment': final_score - base_score,
                'verdict': verdict,
                'action': action,
                'confidence': round(base_probability, 3),
                'domain_age': features_dict.get('domain_age', -1),
                'whois_failed': features_dict.get('whois_lookup_failed', 1),
                'is_trusted': features_dict.get('is_trusted_domain', 0),
                'model_loaded': True
            }
            
        except Exception as e:
            print(f"Prediction error for {url}: {e}")
            return self._error_response(str(e))
    
    def _apply_whois_enhancement(self, base_score: int, features: dict) -> int:
        """
        Apply WHOIS-based adjustments to the base score
        """
        adjusted_score = base_score
        
        # Domain age adjustments (older = safer)
        domain_age = features.get('domain_age', -1)
        if domain_age > 365:  # More than 1 year old
            adjusted_score -= 20
        elif domain_age > 30:  # More than 1 month old
            adjusted_score -= 10
        elif domain_age == -1:  # WHOIS failed or no data
            adjusted_score += 15
        
        # Trusted domain adjustment
        if features.get('is_trusted_domain', 0) == 1:
            adjusted_score -= 25
        
        # WHOIS failure adjustment (failed lookups = suspicious)
        if features.get('whois_lookup_failed', 1) == 1:
            adjusted_score += 10
        
        # Domain not found adjustment (very suspicious)
        if features.get('whois_domain_not_found', 0) == 1:
            adjusted_score += 25
        
        # Ensure score stays within bounds
        return max(0, min(100, adjusted_score))
    
    def _classify_threat(self, score: int) -> tuple:
        """Convert threat score to verdict and action"""
        if score < 25:
            return "🟢 SAFE", "Allow access"
        elif score < 65:
            return "🟡 SUSPICIOUS", "Show warning"
        else:
            return "🔴 MALICIOUS", "Block access"
    
    def _error_response(self, error_msg: str) -> dict:
        """Standard error response"""
        return {
            'success': False,
            'error': error_msg,
            'threat_score': -1,
            'verdict': 'ERROR',
            'action': 'Review manually',
            'model_loaded': self.is_loaded
        }

# Singleton instance
whois_predictor = WHOISEnhancedPredictor()
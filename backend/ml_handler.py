# ml_handler.py
import joblib
import pandas as pd
from pathlib import Path
from feature_extractor import FeatureExtractor

class MLHandler:
    """
    Main ML interface for the phishing detection system.
    Handles model loading, prediction, and management.
    """
    
    def __init__(self, model_path: str = "models/phishing_model.joblib"):
        self.model_path = Path(model_path)
        self.model = None
        self.feature_extractor = None
        self.feature_names = None
        self.is_loaded = False
        
    def load_model(self):
        """Load the trained model and feature extractor"""
        try:
            if not self.model_path.exists():
                raise FileNotFoundError(f"Model file not found: {self.model_path}")
            
            print("Loading ML model...")
            model_payload = joblib.load(self.model_path)
            
            self.model = model_payload['model']
            self.feature_names = model_payload.get('feature_names', [])
            self.feature_extractor = FeatureExtractor()
            self.is_loaded = True
            
            print(f"Model loaded successfully!")
            print(f"Features: {len(self.feature_names)}")
            print(f"Model type: {type(self.model).__name__}")
            
            return True
            
        except Exception as e:
            print(f"Failed to load model: {e}")
            self.is_loaded = False
            return False
    
    def predict_url(self, url: str) -> dict:
        """
        Main prediction function - called by browser extension and backend
        """
        if not self.is_loaded:
            success = self.load_model()
            if not success:
                return self._error_response("Model not loaded")
        
        try:
            # Extract features
            features_dict = self.feature_extractor.extract_features(url)
            
            # Convert to proper format for model
            features_df = self._prepare_features(features_dict)
            
            # Make prediction
            probability = self.model.predict_proba(features_df)[0][1]
            threat_score = int(probability * 100)
            
            # Generate verdict
            verdict, action = self._classify_threat(threat_score)
            
            return {
                'success': True,
                'threat_score': threat_score,
                'verdict': verdict,
                'action': action,
                'confidence': round(probability, 3),
                'url': url,
                'features': features_dict, # Expose the calculated features for the scoring engine
                'features_analyzed': len(features_dict),
                'model_loaded': True
            }
            
        except Exception as e:
            print(f"Prediction error for {url}: {e}")
            return self._error_response(str(e))
    
    def predict_batch(self, urls: list) -> list:
        """Predict multiple URLs at once (for dashboard/analytics)"""
        results = []
        for url in urls:
            results.append(self.predict_url(url))
        return results
    
    def get_model_info(self) -> dict:
        """Get information about the loaded model"""
        if not self.is_loaded:
            return {'error': 'Model not loaded'}
        
        return {
            'model_type': type(self.model).__name__,
            'feature_count': len(self.feature_names),
            'features': self.feature_names,
            'model_path': str(self.model_path),
            'is_fitted': hasattr(self.model, 'classes_')
        }
    
    def _prepare_features(self, features_dict: dict) -> pd.DataFrame:
        """Convert features dictionary to model input format"""
        # Ensure all expected features are present
        features_df = pd.DataFrame([features_dict])
        
        # Add missing features with default values
        for feature in self.feature_names:
            if feature not in features_df.columns:
                features_df[feature] = -1  # Default for missing
        
        # Reorder columns to match training
        features_df = features_df[self.feature_names]
        
        # Handle NaN/infinite values
        features_df = features_df.fillna(-1)
        features_df = features_df.replace([float('inf'), float('-inf')], -1)
        
        return features_df
    
    def _classify_threat(self, score: int) -> tuple:
        """Convert threat score to verdict and action"""
        if score < 25:
            return "SAFE", "Allow access"
        elif score < 65:
            return "SUSPICIOUS", "Show warning"
        else:
            return "MALICIOUS", "Block access"
    
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

# Singleton instance for easy access
ml_handler = MLHandler()

# Convenience functions
def init_ml_handler(model_path: str = None):
    """Initialize the ML handler (call this at app startup)"""
    global ml_handler
    if model_path:
        ml_handler = MLHandler(model_path)
    return ml_handler.load_model()

def predict_url(url: str):
    """Convenience function for single URL prediction"""
    return ml_handler.predict_url(url)
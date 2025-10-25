# feature_extractor.py
import re
import math
from collections import Counter
from urllib.parse import urlparse

class FeatureExtractor:
    def extract_features(self, url):
        """Convert a URL into numerical features for ML model"""
        print(f"Extracting features from: {url}")
        
        features = {
            # Length features
            'url_length': len(url),
            'domain_length': len(urlparse(url).netloc),
            
            # Symbol counts
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_slashes': url.count('/'),
            'num_equals': url.count('='),
            'num_question_marks': url.count('?'),
            'num_at_symbols': url.count('@'),
            
            # Security indicators
            'has_ip': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
            'is_https': 1 if url.startswith('https') else 0,
            
            # Suspicious keywords
            'has_login': 1 if 'login' in url.lower() else 0,
            'has_verify': 1 if 'verify' in url.lower() else 0,
            'has_secure': 1 if 'secure' in url.lower() else 0,
            'has_account': 1 if 'account' in url.lower() else 0,
            'has_bank': 1 if 'bank' in url.lower() else 0,
            'has_paypal': 1 if 'paypal' in url.lower() else 0,
            
            # Statistical features
            'entropy': self._calculate_entropy(url),
            'vowel_ratio': self._count_vowels(url) / len(url) if len(url) > 0 else 0,
        }
        
        print(f"Extracted {len(features)} features")
        return list(features.values())
    
    def _calculate_entropy(self, text):
        """Calculate randomness in URL - phishing URLs often have high entropy"""
        if not text: 
            return 0
        counter = Counter(text)
        entropy = 0
        for count in counter.values():
            p = count / len(text)
            entropy -= p * math.log2(p)
        return entropy
    
    def _count_vowels(self, text):
        return sum(1 for char in text.lower() if char in 'aeiou')

# TEST IT IMMEDIATELY!
if __name__ == "__main__":
    extractor = FeatureExtractor()
    
    test_urls = [
        "http://fake-paypal-login.com",  # Should look suspicious
        "https://paypal.com",             # Should look safe
        "http://192.168.1.1/login",       # IP address - suspicious
    ]
    
    for url in test_urls:
        features = extractor.extract_features(url)
        print(f"Features for '{url}': {features[:5]}...")  # Show first 5 features
        print("---")
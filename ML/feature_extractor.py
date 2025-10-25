# feature_extractor.py
import re
import math
import whois
from datetime import datetime
from collections import Counter
from urllib.parse import urlparse

class FeatureExtractor:
    def _get_domain_features(self, domain):
        """Extracts domain-specific features using WHOIS lookups."""
        try:
            w = whois.whois(domain)
            
            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date

            if creation_date and expiration_date:
                domain_age_days = (datetime.now() - creation_date).days
                domain_lifespan_days = (expiration_date - creation_date).days
            else:
                domain_age_days = -1 # Indicate data not found
                domain_lifespan_days = -1

            return {
                'domain_age_days': domain_age_days,
                'domain_lifespan_days': domain_lifespan_days
            }
        except Exception:
            # If WHOIS fails, return neutral/default values
            return { 'domain_age_days': -1, 'domain_lifespan_days': -1 }

    def extract_features(self, url):
        """
        Convert a URL into a dictionary of features for analysis and a list
        of numerical values for the ML model.
        """
        domain = urlparse(url).netloc
        
        features_dict = {
            # Lexical Features
            'url_length': len(url),
            'domain_length': len(domain),
            'num_dots': url.count('.'),
            'num_hyphens_domain': domain.count('-'),
            'num_slashes': url.count('/'),
            'num_at_symbols': url.count('@'),
            'has_ip': 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain) else 0,
            'is_https': 1 if url.startswith('https') else 0,
            
            # Keyword Features
            'has_login': 1 if 'login' in url.lower() else 0,
            'has_verify': 1 if 'verify' in url.lower() else 0,
            'has_secure': 1 if 'secure' in url.lower() else 0,
            'has_account': 1 if 'account' in url.lower() else 0,
            
            # Statistical Feature
            'entropy': self._calculate_entropy(url),
        }
        
        # Domain-Based Features (with WHOIS)
        domain_features = self._get_domain_features(domain)
        features_dict.update(domain_features)
        
        # Return both the dictionary (for reasoning) and an ordered list (for the model)
        return features_dict, list(features_dict.values())

    def get_feature_names(self):
        """Returns the ordered list of feature names."""
        # This must match the order in extract_features
        return [
            'url_length', 'domain_length', 'num_dots', 'num_hyphens_domain', 
            'num_slashes', 'num_at_symbols', 'has_ip', 'is_https', 'has_login', 
            'has_verify', 'has_secure', 'has_account', 'entropy', 
            'domain_age_days', 'domain_lifespan_days'
        ]

    def _calculate_entropy(self, text):
        if not text: return 0
        counter = Counter(text)
        entropy = -sum((count/len(text)) * math.log2(count/len(text)) for count in counter.values())
        return entropy
    
# --- TEST IT IMMEDIATELY! ---
if __name__ == "__main__":
    extractor = FeatureExtractor()
    test_urls = [
        "https://www.google.com",                  # Safe
        "http://amazon-account-logins.com",     # Suspicious, likely new domain
    ]
    for url in test_urls:
        print(f"\n--- Analyzing '{url}' ---")
        features_dict, features_list = extractor.extract_features(url)
        print("Extracted Dictionary:")
        for key, value in features_dict.items():
            print(f"  {key}: {value}")
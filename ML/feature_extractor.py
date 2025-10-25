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
            
            # Handle cases where dates are in lists
            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date

            if creation_date and expiration_date:
                domain_age_days = (datetime.now() - creation_date).days
                domain_lifespan_days = (expiration_date - creation_date).days
            else:
                domain_age_days = -1 # Use -1 to indicate data not found
                domain_lifespan_days = -1

            return {
                'domain_age_days': domain_age_days,
                'domain_lifespan_days': domain_lifespan_days
            }
        except Exception as e:
            # If WHOIS fails, return neutral/default values
            print(f"⚠️  WHOIS lookup failed for {domain}: {e}")
            return {
                'domain_age_days': -1,
                'domain_lifespan_days': -1
            }

    def extract_features(self, url):
        """
        Convert a URL into a dictionary and a list of numerical features.
        The dictionary is for analysis, the list is for the ML model.
        """
        domain = urlparse(url).netloc
        
        # --- Lexical Features ---
        lexical_features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'num_dots': url.count('.'),
            'num_hyphens': domain.count('-'),
            'num_slashes': url.count('/'),
            'num_at_symbols': url.count('@'),
            'has_ip': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
            'is_https': 1 if url.startswith('https') else 0,
            'has_login': 1 if 'login' in url.lower() else 0,
            'has_verify': 1 if 'verify' in url.lower() else 0,
            'has_secure': 1 if 'secure' in url.lower() else 0,
            'has_account': 1 if 'account' in url.lower() else 0,
            'entropy': self._calculate_entropy(url),
        }
        
        # --- Domain-Based Features ---
        domain_features = self._get_domain_features(domain)
        
        # --- Combine all features ---
        all_features_dict = {**lexical_features, **domain_features}
        
        # Return both the dictionary for analysis and the list for the model
        return all_features_dict, list(all_features_dict.values())

    def _calculate_entropy(self, text):
        """Calculate randomness in the URL string."""
        if not text: return 0
        counter = Counter(text)
        entropy = 0
        for count in counter.values():
            p = count / len(text)
            entropy -= p * math.log2(p)
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
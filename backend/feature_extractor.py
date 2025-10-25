# feature_extractor.py
from urllib.parse import urlparse
import re
import json
import whois
from datetime import datetime, timezone  # <--- MODIFIED THIS LINE

class FeatureExtractor:
    """
    Extracts lexical and WHOIS features from a given URL.
    This is the main class for Member 1's work.
    """
    def __init__(self):
        pass

    def get_lexical_features(self, url, hostname):
        """
        Extracts all the lexical (string-based) features.
        """
        features = {}
        
        # 1. URL Length
        features['url_length'] = len(url)
        # 2. Hostname Length
        features['hostname_length'] = len(hostname)
        # 3. Count Hyphens in Hostname
        features['hostname_hyphens'] = hostname.count('-')
        # 4. Check for IP Address in Hostname
        ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
        features['uses_ip_address'] = 1 if re.match(ip_pattern, hostname) else 0
        # 5. Count '@' symbol in the URL
        features['count_at_symbol'] = url.count('@')
        # 6. Count '.' in hostname
        features['hostname_dots'] = hostname.count('.')
        # 7. Count of 'www' in hostname
        features['count_www'] = hostname.count('www')
        # 8. Count of '/' in the full URL
        features['count_slashes'] = url.count('/')
        
        return features

    def get_whois_features(self, hostname):
        """
        Extracts domain-based features using WHOIS lookups.
        This is our key competitive advantage!
        """
        features = {}
        try:
            domain_info = whois.whois(hostname)
            
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                # Calculate the age
                today = datetime.now(timezone.utc)  # <--- MODIFIED THIS LINE
                age = (today - creation_date).days
                features['domain_age'] = age
            else:
                features['domain_age'] = -1

            if domain_info.expiration_date and domain_info.creation_date:
                expiration_date = domain_info.expiration_date
                creation_date = domain_info.creation_date
                
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                    
                lifespan = (expiration_date - creation_date).days
                features['domain_lifespan'] = lifespan
            else:
                features['domain_lifespan'] = -1
        
        except Exception as e:
            print(f"WHOIS lookup failed for {hostname}: {e}")
            features['domain_age'] = -1
            features['domain_lifespan'] = -1
            
        return features

    def extract_features(self, url):
        """
        The main method that takes a URL and returns a dictionary of all features.
        """
        print(f"Analyzing URL: {url}")
        
        try:
            if not url.startswith('http'):
                url = 'http://' + url
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname if parsed_url.hostname else ''
            
            if not hostname:
                print("Could not parse hostname. Returning empty features.")
                return {}
                
        except ValueError:
            print(f"Malformed URL: {url}. Returning empty features.")
            return {}

        lexical_features = self.get_lexical_features(url, hostname)
        whois_features = self.get_whois_features(hostname)
        all_features = {**lexical_features, **whois_features}
        
        return all_features

# This part is for testing your code directly
if __name__ == '__main__':
    extractor = FeatureExtractor()
    
    sample_url_good = "google.com"
    extracted_features_good = extractor.extract_features(sample_url_good)
    
    print("\n--- Testing FeatureExtractor (WHOIS) ---")
    print(f"Features for '{sample_url_good}':")
    print(json.dumps(extracted_features_good, indent=2))
    print("------------------------------------------")
    
    sample_url_bad = "github-security.com"
    extracted_features_bad = extractor.extract_features(sample_url_bad)
    print(f"\nFeatures for '{sample_url_bad}':")
    print(json.dumps(extracted_features_bad, indent=2))
    print("------------------------------------------")
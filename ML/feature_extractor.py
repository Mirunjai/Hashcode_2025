import re
from urllib.parse import urlparse
import whois
from datetime import datetime, timezone  # <-- Using the CORRECT timezone import
import math

class FeatureExtractor:
    """
    Extracts lexical and WHOIS features from a given URL.
    This version combines the comprehensive feature set from the old code
    with the superior organization and timezone-awareness of the new code.
    """
    def __init__(self):
        # Using the comprehensive phishing keywords set for the powerful 'keyword_count' feature
        self.phishing_keywords = {
            'login', 'secure', 'account', 'update', 'verify', 'webscr', 'signin', 
            'banking', 'confirm', 'ebayisapi', 'apple', 'microsoft', 'google', 
            'paypal', 'amazon'
        }

    def _calculate_entropy(self, text: str) -> float:
        """Calculates the Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob if p > 0])
        return entropy

    def get_lexical_features(self, url: str, domain: str, path: str) -> dict:
        """
        Extracts the full, comprehensive set of lexical features.
        """
        features = {}
        features['url_length'] = len(url)
        features['hostname_length'] = len(domain)
        features['path_length'] = len(path)
        features['fd_length'] = len(path.split('/')[-1])
        features['count-'] = url.count('-')
        features['count@'] = url.count('@')
        features['count?'] = url.count('?')
        features['count%'] = url.count('%')
        features['count.'] = url.count('.')
        features['count='] = url.count('=')
        features['count-http'] = url.count('http')
        features['count-https'] = url.count('https')
        features['count-www'] = url.count('www')
        features['count-digits'] = sum(c.isdigit() for c in url)
        features['count-letters'] = sum(c.isalpha() for c in url)
        features['count-dir'] = path.count('/')
        features['has_ip'] = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0
        features['has_shortening'] = 1 if re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs', url) else 0
        features['keyword_count'] = sum(1 for keyword in self.phishing_keywords if keyword in url.lower())
        features['url_entropy'] = self._calculate_entropy(url)
        features['domain_entropy'] = self._calculate_entropy(domain)
        return features

    def get_whois_features(self, domain: str) -> dict:
        """
        Extracts domain-based features using WHOIS with robust, timezone-aware logic.
        """
        features = {}
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            expiration_date = domain_info.expiration_date

            if creation_date:
                creation_date_clean = creation_date[0] if isinstance(creation_date, list) else creation_date
                # Using the CORRECT timezone-aware 'now'
                today = datetime.now(timezone.utc)
                age = (today - creation_date_clean).days
                features['domain_age'] = age
            else:
                features['domain_age'] = -1

            if expiration_date and creation_date:
                expiration_date_clean = expiration_date[0] if isinstance(expiration_date, list) else expiration_date
                creation_date_clean = creation_date[0] if isinstance(creation_date, list) else creation_date
                lifespan = (expiration_date_clean - creation_date_clean).days
                features['domain_lifespan'] = lifespan
            else:
                features['domain_lifespan'] = -1
        
        except Exception:
            # Keep error handling simple: if anything fails, we get default values.
            features['domain_age'] = -1
            features['domain_lifespan'] = -1
            
        return features

    def extract_features(self, url: str) -> dict:
        """
        Main method that orchestrates feature extraction.
        """
        # A list of default feature names for consistent error handling
        default_feature_keys = [
            'url_length', 'hostname_length', 'path_length', 'fd_length', 'count-', 'count@',
            'count?', 'count%', 'count.', 'count=', 'count-http', 'count-https', 'count-www',
            'count-digits', 'count-letters', 'count-dir', 'has_ip', 'has_shortening',
            'keyword_count', 'url_entropy', 'domain_entropy', 'domain_age', 'domain_lifespan'
        ]

        try:
            if not re.match(r'^https?://', url):
                url = "http://" + url
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path

            if not domain:
                raise ValueError("Could not parse domain/hostname from URL.")

            lexical = self.get_lexical_features(url, domain, path)
            whois = self.get_whois_features(domain)
            
            # Combine the feature dictionaries
            return {**lexical, **whois}

        except Exception as e:
            print(f"[Warning] Feature extraction failed for URL '{url}': {e}. Using default values.")
            return {key: -1 for key in default_feature_keys}
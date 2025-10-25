# feature_extractor_fast.py
import re
import math
from urllib.parse import urlparse

class FastFeatureExtractor:
    """
    Fast feature extractor for training - skips slow WHOIS lookups
    """
    def __init__(self):
        self.phishing_keywords = {
            'login', 'secure', 'account', 'update', 'verify', 'webscr', 'signin', 
            'banking', 'confirm', 'ebayisapi', 'apple', 'microsoft', 'google', 
            'paypal', 'amazon'
        }

    def _calculate_entropy(self, text: str) -> float:
        if not text: return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob if p > 0])
        return entropy

    def extract_features(self, url: str) -> dict:
        try:
            if not re.match(r'^https?://', url):
                url = "http://" + url
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path

            if not domain:
                raise ValueError("Could not parse domain/hostname from URL.")

            # Lexical features only - no WHOIS
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
            features['has_shortening'] = 1 if re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl', url) else 0
            features['keyword_count'] = sum(1 for keyword in self.phishing_keywords if keyword in url.lower())
            features['url_entropy'] = self._calculate_entropy(url)
            features['domain_entropy'] = self._calculate_entropy(domain)
            
            # Set WHOIS features to defaults
            features['whois_lookup_failed'] = 1  # Always failed during training
            features['domain_age'] = -1
            features['domain_lifespan'] = -1
            
            return features

        except Exception as e:
            # Return default features if extraction fails
            default_features = {
                'url_length': -1, 'hostname_length': -1, 'path_length': -1, 'fd_length': -1,
                'count-': -1, 'count@': -1, 'count?': -1, 'count%': -1, 'count.': -1, 'count=': -1,
                'count-http': -1, 'count-https': -1, 'count-www': -1, 'count-digits': -1,
                'count-letters': -1, 'count-dir': -1, 'has_ip': -1, 'has_shortening': -1,
                'keyword_count': -1, 'url_entropy': -1, 'domain_entropy': -1,
                'whois_lookup_failed': 1, 'domain_age': -1, 'domain_lifespan': -1
            }
            return default_features
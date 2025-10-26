# feature_extractor.py (FINAL, CORRECTED, AND COMPLETE VERSION)

import re
import math
from urllib.parse import urlparse

# CRITICAL: This line means you MUST have a 'whois_handler.py' file
# in the same directory, containing a class named 'RobustWhoisHandler'.
from whois_handler import RobustWhoisHandler

class FeatureExtractor:
    """
    Feature extractor with robust WHOIS integration, fully compatible with the ml_handler.
    """
    # THIS IS THE CORRECT CONSTRUCTOR THAT SOLVES THE ERROR
    def __init__(self, enable_whois=True):
        print("[Feature Extractor] Initializing with modern settings...")
        self.phishing_keywords = {
            'login', 'secure', 'account', 'update', 'verify', 'webscr', 'signin', 
            'banking', 'confirm', 'ebayisapi', 'apple', 'microsoft', 'google', 
            'paypal', 'amazon'
        }
        
        self.trusted_domains = {
            'github.com', 'gitlab.com', 'stackoverflow.com', 'wikipedia.org',
            'microsoft.com', 'apple.com', 'google.com', 'amazon.com', 'paypal.com',
            'facebook.com', 'youtube.com', 'reddit.com', 'instagram.com', 'linkedin.com',
            'twitter.com', 'netflix.com', 'ebay.com', 'cnn.com', 'bbc.com', 'nytimes.com',
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'mozilla.org', 'adobe.com'
        }
        
        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.loan', '.club'}
        
        self.whois_handler = RobustWhoisHandler(timeout=5, max_retries=1) if enable_whois else None
        self.enable_whois = enable_whois
        print(f"[Feature Extractor] WHOIS lookups are {'ENABLED' if self.enable_whois else 'DISABLED'}.")

    def _calculate_entropy(self, text: str) -> float:
        if not text: return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob if p > 0])
        return entropy

    def _is_trusted_domain(self, domain: str) -> bool:
        clean_domain = domain.lower().replace('www.', '')
        return clean_domain in self.trusted_domains

    def extract_features(self, url: str) -> dict:
        try:
            if not re.match(r'^https?://', url):
                url = "http://" + url
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path

            if not domain:
                raise ValueError("Could not parse domain/hostname from URL.")

            features = {}
            
            # DOMAIN REPUTATION FEATURES
            features['is_trusted_domain'] = 1 if self._is_trusted_domain(domain) else 0
            features['suspicious_tld'] = 1 if any(domain.endswith(tld) for tld in self.suspicious_tlds) else 0
            
            # LENGTH FEATURES
            features['url_length'] = len(url)
            features['hostname_length'] = len(domain)
            features['path_length'] = len(path)
            features['fd_length'] = len(path.split('/')[-1])
            
            # CHARACTER PATTERNS
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
            
            # SECURITY INDICATORS
            features['has_ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", domain) else 0
            features['has_shortening'] = 1 if re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl', url) else 0
            
            # KEYWORD ANALYSIS
            features['keyword_count'] = sum(1 for keyword in self.phishing_keywords if keyword in url.lower())
            
            # ENTROPY
            features['url_entropy'] = self._calculate_entropy(url)
            features['domain_entropy'] = self._calculate_entropy(domain)
            
            # RATIO FEATURES
            features['path_to_url_ratio'] = len(path) / len(url) if len(url) > 0 else 0
            features['letters_to_length_ratio'] = sum(c.isalpha() for c in url) / len(url) if len(url) > 0 else 0
            features['digits_to_length_ratio'] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
            
            # BRAND ANALYSIS
            brand_keywords = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'ebay', 'bank']
            features['has_brand_name'] = 1 if any(brand in url.lower() for brand in brand_keywords) else 0
            features['brand_in_subdomain'] = 1 if any(brand in domain.lower().split('.')[0] for brand in brand_keywords) else 0
            features['brand_not_in_domain'] = 1 if (features['has_brand_name'] == 1 and not any(brand in domain for brand in brand_keywords)) else 0
            
            # WHOIS FEATURES
            if self.enable_whois and self.whois_handler:
                whois_features = self.whois_handler.get_whois_features(domain)
                features.update(whois_features)
            else:
                features.update({
                    'whois_lookup_failed': 1, 'domain_age': -1, 'domain_lifespan': -1,
                    'whois_timeout': 0, 'whois_domain_not_found': 0, 'whois_other_error': 0
                })
            
            return features

        except Exception as e:
            # Fallback in case of any catastrophic error
            print(f"[Feature Extractor] CRITICAL ERROR processing {url}: {e}")
            return { 'error': 1, 'domain_age': -1, 'domain_lifespan': -1 }
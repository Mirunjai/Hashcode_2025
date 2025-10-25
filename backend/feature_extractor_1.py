import re
import math
from urllib.parse import urlparse
from whois_handler import RobustWhoisHandler

class FeatureExtractor:
    """
    Feature extractor with robust WHOIS integration
    """
    def __init__(self, enable_whois=True):
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
        'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'mozilla.org', 'adobe.com',
        'ibm.com', 'intel.com', 'nvidia.com', 'oracle.com', 'salesforce.com',
        'docker.com', 'kubernetes.io', 'npmjs.com', 'pypi.org', 'docker.io',
        'example.com', 'your-bank.com'  # ADD THESE
        }
        
        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.loan', '.club'}
        self.whois_handler = RobustWhoisHandler(timeout=5, max_retries=1) if enable_whois else None
        self.enable_whois = enable_whois

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
            
            # LENGTH FEATURES (normalized)
            features['url_length'] = min(len(url), 200) / 200.0
            features['hostname_length'] = min(len(domain), 50) / 50.0
            features['path_length'] = min(len(path), 100) / 100.0
            features['fd_length'] = min(len(path.split('/')[-1]), 50) / 50.0
            
            # CHARACTER PATTERNS
            features['count-'] = min(url.count('-'), 10) / 10.0
            features['count@'] = url.count('@')
            features['count?'] = min(url.count('?'), 5) / 5.0
            features['count%'] = url.count('%')
            features['count.'] = min(url.count('.'), 10) / 10.0
            features['count='] = min(url.count('='), 5) / 5.0
            features['count-http'] = url.count('http')
            features['count-https'] = url.count('https')
            features['count-www'] = url.count('www')
            features['count-digits'] = min(sum(c.isdigit() for c in url), 50) / 50.0
            features['count-letters'] = min(sum(c.isalpha() for c in url), 100) / 100.0
            features['count-dir'] = min(path.count('/'), 10) / 10.0
            
            # SECURITY INDICATORS
            features['has_ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", domain) else 0
            features['has_shortening'] = 1 if re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl', url) else 0
            
            # KEYWORD ANALYSIS
            features['keyword_count'] = min(sum(1 for keyword in self.phishing_keywords if keyword in url.lower()), 5) / 5.0
            
            # ENTROPY
            features['url_entropy'] = min(self._calculate_entropy(url), 6.0) / 6.0
            features['domain_entropy'] = min(self._calculate_entropy(domain), 5.0) / 5.0
            
            # RATIO FEATURES
            features['path_to_url_ratio'] = len(path) / len(url) if len(url) > 0 else 0
            features['letters_to_length_ratio'] = sum(c.isalpha() for c in url) / len(url) if len(url) > 0 else 0
            features['digits_to_length_ratio'] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
            
            # BRAND ANALYSIS
            brand_keywords = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'ebay', 'bank']
            features['has_brand_name'] = 1 if any(brand in url.lower() for brand in brand_keywords) else 0
            features['brand_in_subdomain'] = 1 if any(brand in domain.lower().split('.')[0] for brand in brand_keywords) else 0
            features['brand_not_in_domain'] = 1 if (features['has_brand_name'] == 1 and 
                                                   not any(brand in domain for brand in brand_keywords)) else 0
            
            # WHOIS FEATURES (with robust error handling)
            if self.enable_whois and self.whois_handler:
                whois_features = self.whois_handler.get_whois_features(domain)
                features.update(whois_features)
            else:
                # WHOIS disabled - set defaults
                features.update({
                    'whois_lookup_failed': 1,
                    'domain_age': -1,
                    'domain_lifespan': -1,
                    'whois_timeout': 0,
                    'whois_domain_not_found': 0,
                    'whois_other_error': 0
                })
            
            return features

        except Exception as e:
            # Return safe defaults if extraction fails
            default_features = {key: 0 for key in [
                'url_length', 'hostname_length', 'path_length', 'fd_length', 'count-', 'count@',
                'count?', 'count%', 'count.', 'count=', 'count-http', 'count-https', 'count-www',
                'count-digits', 'count-letters', 'count-dir', 'has_ip', 'has_shortening',
                'keyword_count', 'url_entropy', 'domain_entropy', 'is_trusted_domain',
                'suspicious_tld', 'path_to_url_ratio', 'letters_to_length_ratio', 
                'digits_to_length_ratio', 'has_brand_name', 'brand_in_subdomain', 
                'brand_not_in_domain', 'whois_lookup_failed', 'domain_age', 'domain_lifespan',
                'whois_timeout', 'whois_domain_not_found', 'whois_other_error'
            ]}
            default_features['whois_lookup_failed'] = 1
            default_features['domain_age'] = -1
            default_features['domain_lifespan'] = -1
            return default_features

    def disable_whois(self):
        """Disable WHOIS lookups"""
        self.enable_whois = False

    def enable_whois(self):
        """Enable WHOIS lookups"""
        self.enable_whois = True
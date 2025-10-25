import re
from urllib.parse import urlparse
import whois
from datetime import datetime
import math
from collections import Counter

class FeatureExtractor:
    """
    Extracts lexical and WHOIS features from a given URL.
    Returns a dictionary of features.
    """
    def __init__(self):
        # Using a set for faster lookups
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
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def extract_features(self, url: str) -> dict:
        """
        Main method to extract all features from a URL.
        Handles errors gracefully, returning default values.
        """
        features = {}
        
        try:
            # Add scheme if missing for proper parsing
            if not re.match(r'^https?://', url):
                url = "http://" + url
                
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            # Lexical Features
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
            features['count-https'] = url.count('httpsis')
            features['count-www'] = url.count('www')
            features['count-digits'] = sum(c.isdigit() for c in url)
            features['count-letters'] = sum(c.isalpha() for c in url)
            features['count-dir'] = path.count('/')
            features['has_ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0
            features['has_shortening'] = 1 if re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url) else 0
            features['keyword_count'] = sum(1 for keyword in self.phishing_keywords if keyword in url.lower())
            features['url_entropy'] = self._calculate_entropy(url)
            features['domain_entropy'] = self._calculate_entropy(domain)

            # WHOIS Features
            domain_age = -1
            domain_lifespan = -1
            
            try:
                whois_info = whois.whois(domain)
                if whois_info.creation_date:
                    creation_date = whois_info.creation_date[0] if isinstance(whois_info.creation_date, list) else whois_info.creation_date
                    domain_age = (datetime.now() - creation_date).days
                
                if whois_info.expiration_date:
                    expiration_date = whois_info.expiration_date[0] if isinstance(whois_info.expiration_date, list) else whois_info.expiration_date
                    if whois_info.creation_date:
                         creation_date = whois_info.creation_date[0] if isinstance(whois_info.creation_date, list) else whois_info.creation_date
                         domain_lifespan = (expiration_date - creation_date).days
            except Exception:
                # WHOIS can fail for many reasons (new TLDs, protected domains, etc.)
                # Default to -1 to indicate data not available
                pass

            features['domain_age'] = domain_age
            features['domain_lifespan'] = domain_lifespan
            
        except Exception as e:
            # Generic catch for any URL parsing errors
            print(f"Error processing URL '{url}': {e}. Using default feature values.")
            # Populate with default values if URL processing fails
            default_keys = [
                'url_length', 'hostname_length', 'path_length', 'fd_length', 'count-', 'count@',
                'count?', 'count%', 'count.', 'count=', 'count-http', 'count-https', 'count-www',
                'count-digits', 'count-letters', 'count-dir', 'has_ip', 'has_shortening',
                'keyword_count', 'url_entropy', 'domain_entropy', 'domain_age', 'domain_lifespan'
            ]
            features = {key: -1 for key in default_keys}

        return features
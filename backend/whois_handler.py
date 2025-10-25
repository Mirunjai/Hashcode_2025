# whois_handler.py
import whois
from datetime import datetime, timezone
import socket
import threading
import time
from functools import lru_cache

class RobustWhoisHandler:
    """
    Robust WHOIS handler with timeout, caching, and comprehensive error handling
    """
    
    def __init__(self, timeout=10, max_retries=2):
        self.timeout = timeout
        self.max_retries = max_retries
        self._cache = {}
        
    def whois_lookup_with_timeout(self, domain: str) -> dict:
        """
        Perform WHOIS lookup with timeout and retries
        """
        for attempt in range(self.max_retries):
            try:
                # Use threading to implement timeout
                result = {}
                exception = None
                
                def do_whois():
                    nonlocal result, exception
                    try:
                        result = whois.whois(domain)
                    except Exception as e:
                        exception = e
                
                thread = threading.Thread(target=do_whois)
                thread.daemon = True
                thread.start()
                thread.join(timeout=self.timeout)
                
                if thread.is_alive():
                    # Thread is still running - timeout occurred
                    raise TimeoutError(f"WHOIS lookup timed out after {self.timeout} seconds")
                
                if exception:
                    raise exception
                    
                return result
                
            except TimeoutError:
                if attempt == self.max_retries - 1:
                    return {'error': 'timeout'}
                time.sleep(1)  # Wait before retry
                
            except whois.exceptions.WhoisDomainNotFoundError as e:
                # Domain doesn't exist in WHOIS
                if attempt == self.max_retries - 1:
                    return {'error': 'domain_not_found'}
                time.sleep(1)
                
            except whois.exceptions.WhoisCommandFailed as e:
                # WHOIS command failed
                if attempt == self.max_retries - 1:
                    return {'error': f'whois_command_failed: {str(e)}'}
                time.sleep(1)
                
            except whois.exceptions.WhoisPrivateRegistryError as e:
                # Private registry (like .com)
                if attempt == self.max_retries - 1:
                    return {'error': 'private_registry'}
                time.sleep(1)
                
            except whois.exceptions.WhoisQuotaExceeded as e:
                # Rate limiting
                if attempt == self.max_retries - 1:
                    return {'error': 'quota_exceeded'}
                time.sleep(2)  # Longer wait for quota
                
            except socket.gaierror as e:
                # DNS resolution error
                if attempt == self.max_retries - 1:
                    return {'error': f'dns_error: {str(e)}'}
                time.sleep(1)
                
            except Exception as e:
                # Catch-all for any other exceptions
                if attempt == self.max_retries - 1:
                    return {'error': f'unknown_error: {str(e)}'}
                time.sleep(1)
        
        return {'error': 'max_retries_exceeded'}
    
    def get_whois_features(self, domain: str) -> dict:
        """
        Extract WHOIS features with comprehensive error handling
        """
        # Clean domain (remove www. etc.)
        clean_domain = domain.lower().replace('www.', '').split('/')[0]
        
        # Check cache first
        if clean_domain in self._cache:
            return self._cache[clean_domain]
        
        features = {
            'whois_lookup_failed': 1,
            'domain_age': -1,
            'domain_lifespan': -1,
            'whois_timeout': 0,
            'whois_domain_not_found': 0,
            'whois_private_registry': 0,
            'whois_quota_exceeded': 0,
            'whois_other_error': 0
        }
        
        # Skip WHOIS for IP addresses
        if self._is_ip_address(clean_domain):
            features['whois_lookup_failed'] = 1
            features['whois_other_error'] = 1
            self._cache[clean_domain] = features
            return features
        
        # Perform WHOIS lookup
        whois_data = self.whois_lookup_with_timeout(clean_domain)
        
        if 'error' in whois_data:
            # Handle different error types
            error_type = whois_data['error']
            features['whois_lookup_failed'] = 1
            
            if 'timeout' in error_type:
                features['whois_timeout'] = 1
            elif 'domain_not_found' in error_type:
                features['whois_domain_not_found'] = 1
            elif 'private_registry' in error_type:
                features['whois_private_registry'] = 1
            elif 'quota_exceeded' in error_type:
                features['whois_quota_exceeded'] = 1
            else:
                features['whois_other_error'] = 1
                
            self._cache[clean_domain] = features
            return features
        
        # WHOIS succeeded - extract features
        features['whois_lookup_failed'] = 0
        features['whois_timeout'] = 0
        features['whois_domain_not_found'] = 0
        features['whois_private_registry'] = 0
        features['whois_quota_exceeded'] = 0
        features['whois_other_error'] = 0
        
        try:
            # Extract creation date
            creation_date = whois_data.creation_date
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if isinstance(creation_date, datetime):
                    today = datetime.now(timezone.utc)
                    age_days = (today - creation_date).days
                    features['domain_age'] = max(0, age_days)
                else:
                    features['domain_age'] = -1
            else:
                features['domain_age'] = -1
            
            # Extract expiration date and calculate lifespan
            expiration_date = whois_data.expiration_date
            if creation_date and expiration_date:
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if (isinstance(creation_date, datetime) and 
                    isinstance(expiration_date, datetime)):
                    lifespan = (expiration_date - creation_date).days
                    features['domain_lifespan'] = max(0, lifespan)
                else:
                    features['domain_lifespan'] = -1
            else:
                features['domain_lifespan'] = -1
                
        except Exception as e:
            # If any error occurs during date processing, mark as failed
            features['whois_lookup_failed'] = 1
            features['whois_other_error'] = 1
            features['domain_age'] = -1
            features['domain_lifespan'] = -1
        
        # Cache the result
        self._cache[clean_domain] = features
        return features
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if the domain is actually an IP address"""
        import re
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        return re.match(ip_pattern, domain) is not None
    
    def clear_cache(self):
        """Clear the WHOIS cache"""
        self._cache.clear()
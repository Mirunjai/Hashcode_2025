# content_analyzer.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def analyze_page_content(url: str) -> dict:
    """
    Fetches the live webpage and analyzes its DOM for high-confidence phishing indicators.
    """
    print(f"[Field Agent] Investigating live content at: {url}")
    features = {
        'has_password_form': False,
        'form_action_is_external': False,
        'fetch_error': False
    }
    
    headers = {'User-Agent': 'Mozilla/5.0 PhishEyeBot/1.0'}

    try:
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check for password fields
        if soup.find('input', {'type': 'password'}):
            features['has_password_form'] = True

        # CRITICAL CHECK: Does a form submit data to a different domain?
        forms = soup.find_all('form')
        if forms:
            action = forms[0].get('action', '')
            if action.startswith('http') and urlparse(action).netloc != urlparse(url).netloc:
                features['form_action_is_external'] = True

    except requests.RequestException as e:
        print(f"[Field Agent] Error fetching {url}: {e}")
        features['fetch_error'] = True

    return features
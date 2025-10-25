# data_loader.py
import pandas as pd
import requests

def load_phishing_data():
    """Simple data loader - tries real data, falls back to synthetic"""
    print("Loading phishing data...")
    
    # Try to get real data first
    try:
        url = "http://data.phishtank.com/data/online-valid.csv"
        df = pd.read_csv(url)
        phishing_urls = df['url'].tolist()[:500]  # Take first 500
        print(f"Loaded {len(phishing_urls)} real phishing URLs")
    except:
        print("Using synthetic data")
        phishing_urls = [
            "http://verify-paypal-account.com", "https://apple-id-secure-login.net",
            "http://microsoft-online-security.com", "http://netflix-billing-update.org",
            "http://amazon-account-verification.com", "http://bankofamerica-secure-login.net",
            "http://google-drive-security-alert.com", "http://facebook-login-confirm.com",
            "http://whatsapp-verification-code.com", "http://instagram-account-recovery.com",
            "http://192.168.1.1/login.php", "http://secure-login-bank.com",
            "http://update-your-password.com", "http://account-verification-required.com"
        ] * 35  # Scale to ~500 URLs
    
    return phishing_urls

def load_legitimate_data():
    """Load legitimate URLs"""
    legitimate_urls = [
        "https://google.com", "https://youtube.com", "https://facebook.com", 
        "https://amazon.com", "https://wikipedia.org", "https://reddit.com",
        "https://instagram.com", "https://linkedin.com", "https://twitter.com",
        "https://microsoft.com", "https://apple.com", "https://netflix.com",
        "https://paypal.com", "https://github.com", "https://stackoverflow.com",
        "https://ebay.com", "https://cnn.com", "https://bbc.com", "https://nytimes.com",
        "https://chase.com", "https://bankofamerica.com", "https://wellsfargo.com"
    ] * 25  # Scale to ~500 URLs
    
    print(f"Loaded {len(legitimate_urls)} legitimate URLs")
    return legitimate_urls

def get_balanced_dataset():
    """Return balanced dataset for training"""
    phishing_urls = load_phishing_data()
    legitimate_urls = load_legitimate_data()
    
    # Create DataFrame
    df_phishing = pd.DataFrame({'url': phishing_urls, 'label': 1})
    df_legitimate = pd.DataFrame({'url': legitimate_urls, 'label': 0})
    
    # Combine and shuffle
    df = pd.concat([df_phishing, df_legitimate], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"Final dataset: {len(df_phishing)} phishing, {len(df_legitimate)} legitimate")
    return df

# Test it
if __name__ == "__main__":
    df = get_balanced_dataset()
    print(f"\Sample URLs:")
    print("Phishing:", df[df['label'] == 1]['url'].iloc[0])
    print("Legitimate:", df[df['label'] == 0]['url'].iloc[0])
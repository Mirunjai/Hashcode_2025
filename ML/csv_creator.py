# csv_creator.py
import pandas as pd
from pathlib import Path

def create_clean_balanced_dataset():
    """
    Creates a clean, realistic dataset with proper legitimate URLs
    """
    SOURCE_DIR = Path(__file__).parent / "data"
    INPUT_FILE = SOURCE_DIR / "online.csv"  # Your phishing data
    OUTPUT_FILE = SOURCE_DIR / "phishing_site_urls.csv"
    
    print("Creating CLEAN balanced dataset...")
    
    # Read phishing URLs
    df_phish = pd.read_csv(INPUT_FILE)
    # Take diverse phishing samples
    phishing_urls = df_phish['url'].dropna().unique()[:8000]
    
    # REAL legitimate URLs - these should look completely normal
    legitimate_urls = [
        # Major legitimate domains with common paths
        "https://github.com/scikit-learn/scikit-learn",
        "https://github.com/tensorflow/tensorflow",
        "https://stackoverflow.com/questions/tagged/python",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://www.google.com/search?q=weather",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.facebook.com/groups/technology",
        "https://www.amazon.com/gp/product/B08N5WRWNW",
        "https://www.paypal.com/us/home",
        "https://www.apple.com/iphone",
        "https://www.microsoft.com/en-us/windows",
        "https://www.netflix.com/browse",
        "https://www.instagram.com/explore/tags/tech",
        "https://www.linkedin.com/jobs/search",
        "https://www.reddit.com/r/programming",
        "https://www.ebay.com/itm/123456",
        "https://www.cnn.com/2024/01/01/tech",
        "https://www.bbc.com/news/technology",
        "https://www.nytimes.com/section/technology",
        "https://www.chase.com/personal",
        "https://www.bankofamerica.com/online-banking",
        "https://www.wellsfargo.com/help/security",
        "https://www.theverge.com/2024/1/1",
        "https://techcrunch.com/startups",
        "https://web.mit.edu/research",
        "https://www.weather.com/forecast",
        "https://www.mozilla.org/firefox",
        "https://www.ubuntu.com/download",
        "https://wordpress.org/showcase",
        "https://www.adobe.com/creativecloud",
        "https://www.ibm.com/cloud",
        "https://www.intel.com/content/www/us/en/products",
        "https://www.nvidia.com/en-us/geforce",
        
        # More generic but legitimate patterns
        "https://example.com/login",
        "https://example.com/signin", 
        "https://example.com/account",
        "https://example.com/secure",
        "https://example.com/verify",
        "https://example.com/update",
        "https://example.com/confirm",
        "https://example.com/banking",
        "https://example.com/payment",
        
        # Educational and government
        "https://www.harvard.edu/research",
        "https://www.stanford.edu/admission",
        "https://www.nasa.gov/mission_pages",
        "https://www.whitehouse.gov/briefing-room",
        
        # Tech companies
        "https://www.ibm.com/products",
        "https://www.oracle.com/cloud",
        "https://www.salesforce.com/products",
        "https://www.sap.com/products",
        
        # E-commerce
        "https://www.walmart.com/ip/123456",
        "https://www.target.com/p/product",
        "https://www.bestbuy.com/site/product",
        
        # News and media
        "https://www.reuters.com/technology",
        "https://www.bloomberg.com/technology",
        "https://www.wsj.com/tech",
        "https://www.forbes.com/technology",
        
        # Cloud services
        "https://aws.amazon.com/console",
        "https://cloud.google.com/products",
        "https://azure.microsoft.com/services",
        
        # Social media with paths
        "https://twitter.com/home",
        "https://www.pinterest.com/search/pins",
        "https://www.tumblr.com/dashboard",
        "https://www.flickr.com/explore",
        
        # Development
        "https://gitlab.com/explore/projects",
        "https://bitbucket.org/dashboard/overview",
        "https://www.npmjs.com/package/react",
        "https://pypi.org/project/requests",
        
        # Company websites with secure sections
        "https://www.ibm.com/account/login",
        "https://www.oracle.com/customer/portal",
        "https://www.salesforce.com/help/secure",
        "https://www.sap.com/support/update"
    ]
    
    # Generate more legitimate URLs by combining domains with common paths
    base_domains = [
        "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
        "youtube.com", "wikipedia.org", "reddit.com", "instagram.com", "linkedin.com",
        "twitter.com", "netflix.com", "paypal.com", "github.com", "stackoverflow.com",
        "ebay.com", "cnn.com", "bbc.com", "nytimes.com", "chase.com"
    ]
    
    common_paths = [
        "", "/", "/home", "/about", "/contact", "/help", "/support", 
        "/products", "/services", "/blog", "/news", "/careers", "/login",
        "/signin", "/account", "/profile", "/search", "/privacy", "/terms"
    ]
    
    for domain in base_domains:
        for path in common_paths:
            legitimate_urls.append(f"https://{domain}{path}")
            legitimate_urls.append(f"https://www.{domain}{path}")
    
    # Remove duplicates and take the same number as phishing URLs
    legitimate_urls = list(set(legitimate_urls))
    if len(legitimate_urls) > len(phishing_urls):
        legitimate_urls = legitimate_urls[:len(phishing_urls)]
    else:
        # If we don't have enough legitimate URLs, take what we have
        phishing_urls = phishing_urls[:len(legitimate_urls)]
    
    print(f"Phishing URLs: {len(phishing_urls)}")
    print(f"Legitimate URLs: {len(legitimate_urls)}")
    
    # Create DataFrames
    df_phish_clean = pd.DataFrame({'URL': phishing_urls, 'Label': 'bad'})
    df_legit_clean = pd.DataFrame({'URL': legitimate_urls, 'Label': 'good'})
    
    # Combine and shuffle
    final_df = pd.concat([df_phish_clean, df_legit_clean], ignore_index=True)
    final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save
    final_df.to_csv(OUTPUT_FILE, index=False)
    print(f"✅ Created clean dataset with {len(final_df)} URLs")
    print(f"   - Phishing: {len(df_phish_clean)}")
    print(f"   - Legitimate: {len(df_legit_clean)}")
    
    # Show some samples
    print("\nSample legitimate URLs:")
    for url in legitimate_urls[:5]:
        print(f"   {url}")
    
    print("\nSample phishing URLs:")  
    for url in phishing_urls[:5]:
        print(f"   {url}")

if __name__ == "__main__":
    create_clean_balanced_dataset()
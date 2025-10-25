# data_loader.py
import pandas as pd
from pathlib import Path

def get_balanced_dataset():
    """
    Load a larger, more reliable dataset from a local CSV file.
    This is much more stable than relying on a live URL.
    """
    DATA_PATH = Path(__file__).parent / "data" / "phishing_site_urls.csv"

    print("Loading reliable dataset from local CSV...")

    if not DATA_PATH.exists():
        print(f"[ERROR] Dataset not found at {DATA_PATH}")
        print("Please ensure 'phishing_site_urls.csv' is in a 'data' subfolder.")
        # Return an empty DataFrame to prevent a crash
        return pd.DataFrame({'url': [], 'label': []})

    try:
        df_phish_source = pd.read_csv(DATA_PATH)
        
        # Check if the CSV has the expected 'url' column from PhishTank
        if 'url' not in df_phish_source.columns:
            print("[FATAL ERROR] The provided CSV does not have a 'url' column. Please use the CSV from PhishTank.")
            return pd.DataFrame()
            
        phishing_urls = df_phish_source['url'].tolist()
        # Let's take a large sample for good training, but not the whole file if it's huge
        phishing_urls = phishing_urls[:40] 
        print(f"✅ Loaded {len(phishing_urls)} phishing URLs from local file.")
        
    except Exception as e:
        print(f"[FATAL ERROR] Could not read or process the CSV file: {e}")
        return pd.DataFrame()

    # --- Step 2: Create a list of Legitimate URLs ---
    # Since the PhishTank file only contains bad URLs, we must provide our own good ones.
    legitimate_urls = [
        "https://google.com", "https://youtube.com", "https://facebook.com",
        "https://amazon.com", "https://wikipedia.org", "https://reddit.com",
        "https://instagram.com", "https://linkedin.com", "https://twitter.com",
        "https://microsoft.com", "https://apple.com", "https://netflix.com",
        "https://paypal.com", "https://github.com", "https://stackoverflow.com",
        "https://ebay.com", "https://cnn.com", "https://bbc.com", "https://nytimes.com",
        "https://chase.com", "https://bankofamerica.com", "https://wellsfargo.com",
        "https://theverge.com", "https://techcrunch.com", "https://mit.edu"
    ]
    print(f"Generated a base list of {len(legitimate_urls)} legitimate URLs.")

    # --- Step 3: Balance the dataset ---
    # We will create an equal number of legitimate and phishing URLs
    num_phish = len(phishing_urls)
    # This trick repeats the legit list until it's long enough, then slices it to the exact size needed.
    balanced_legitimate_urls = (legitimate_urls * (num_phish // len(legitimate_urls) + 1))[:num_phish]
    print(f"Balanced dataset will use {len(phishing_urls)} phishing and {len(balanced_legitimate_urls)} legitimate URLs.")

    # --- Step 4: Assemble the final DataFrame ---
    df_phishing = pd.DataFrame({'url': phishing_urls, 'label': 1})
    df_legitimate = pd.DataFrame({'url': balanced_legitimate_urls, 'label': 0})
    
    # Combine, drop any duplicates, and shuffle
    df = pd.concat([df_phishing, df_legitimate], ignore_index=True)
    df.drop_duplicates(subset=['url'], inplace=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print("\n--- Dataset Assembly Complete ---")
    print(f"Final dataset size: {len(df)} URLs")
    print(f"Final distribution: {df['label'].value_counts().to_dict()}")
    return df

if __name__ == "__main__":
    dataset = get_balanced_dataset()
    if not dataset.empty:
        print("\nSample from final dataset:")
        print(dataset.head())
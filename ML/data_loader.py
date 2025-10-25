import pandas as pd
from pathlib import Path

def get_balanced_dataset(sample_size: int = None):
    """
    Loads the balanced dataset from 'phishing_site_urls.csv'.
    This version is robust: it checks data availability before sampling
    to guarantee a balanced output and prevent crashes.
    """
    DATA_PATH = Path(__file__).parent / "data" / "phishing_site_urls.csv"
    print(f"Loading balanced dataset from: {DATA_PATH}")

    if not DATA_PATH.exists():
        print(f"\n[FATAL ERROR] Required training file not found: {DATA_PATH}")
        return pd.DataFrame()

    try:
        df = pd.read_csv(DATA_PATH)
        df.rename(columns={'URL': 'url', 'Label': 'label'}, inplace=True)
        df['label'] = df['label'].map({'bad': 1, 'good': 0})
        df.dropna(subset=['url', 'label'], inplace=True)
        df['label'] = df['label'].astype(int)
        
        # --- ROBUST BALANCING LOGIC ---
        df_phish_full = df[df['label'] == 1]
        df_legit_full = df[df['label'] == 0]

        # Determine the maximum possible sample size based on the smallest class
        smallest_class_size = min(len(df_phish_full), len(df_legit_full))
        
        if smallest_class_size == 0:
            print("[FATAL ERROR] One class has zero samples. Cannot create a balanced dataset.")
            return pd.DataFrame()

        n_per_class = smallest_class_size
        
        # If a smaller sample is requested, use that, but cap it at what's available
        if sample_size:
            if sample_size // 2 > smallest_class_size:
                print(f"[Warning] Requested {sample_size // 2} samples per class, but only {smallest_class_size} are available.")
            n_per_class = min(sample_size // 2, smallest_class_size)
            print(f"Using a smaller sample of {n_per_class * 2} total URLs for speed.")
        
        # Take the final sample from each class
        df_phish_sample = df_phish_full.sample(n=n_per_class, random_state=42)
        df_legit_sample = df_legit_full.sample(n=n_per_class, random_state=42)
        
        # Combine and shuffle
        final_df = pd.concat([df_phish_sample, df_legit_sample], ignore_index=True)
        final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)
        # --- END OF ROBUST LOGIC ---

        print("\n--- Dataset Assembly Complete ---")
        print(f"Final dataset size: {len(final_df)} URLs")
        print(f"Final distribution: {final_df['label'].value_counts().to_dict()}")
        
        return final_df

    except Exception as e:
        print(f"\n[FATAL ERROR] Failed to process the balanced CSV file: {e}")
        return pd.DataFrame()

if __name__ == "__main__":
    print("--- Testing data_loader.py with a small sample (400) ---")
    small_dataset = get_balanced_dataset(sample_size=400)
    print("\n--- Testing data_loader.py with the full balanced dataset ---")
    full_dataset = get_balanced_dataset()
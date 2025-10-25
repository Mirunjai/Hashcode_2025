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
        df = pd.read_csv(DATA_PATH)
        
        # The CSV has 'URL' and 'Label' columns. Standardize them.
        df.rename(columns={'URL': 'url', 'Label': 'label'}, inplace=True)
        
        # Convert labels 'bad' -> 1 and 'good' -> 0
        df['label'] = df['label'].map({'bad': 1, 'good': 0})
        
        # Drop any rows where conversion failed
        df.dropna(subset=['url', 'label'], inplace=True)
        df['label'] = df['label'].astype(int)

        # Shuffle the dataset
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        print(f"Dataset loaded: {len(df)} total URLs.")
        print(f"Distribution: {df['label'].value_counts().to_dict()}")
        
        # Let's use a large but manageable sample for the hackathon
        return df.sample(n=20000, random_state=42) if len(df) > 20000 else df

    except Exception as e:
        print(f"Error processing CSV file: {e}")
        return pd.DataFrame({'url': [], 'label': []})


if __name__ == "__main__":
    dataset = get_balanced_dataset()
    if not dataset.empty:
        print("\nSample from loaded dataset:")
        print(dataset.head())
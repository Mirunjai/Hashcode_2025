# data_loader.py
import pandas as pd

def load_real_data():
    """Downloads a real phishing dataset."""
    print("Downloading real-world phishing data from a trusted source...")
    try:
        # A well-known, reliable dataset for phishing
        url = "https://data.mendeley.com/public-files/datasets/h3cgnj8hft/files/41d55b71-7533-4226-80d4-a8208a2b53c3/file_downloaded"
        df = pd.read_csv(url)
        # Rename columns to match your expected format
        df.rename(columns={'URL': 'url', 'Label': 'label'}, inplace=True)
        # Convert labels: 'good' -> 0, 'bad' -> 1
        df['label'] = df['label'].apply(lambda x: 1 if x == 'bad' else 0)
        print(f"Successfully loaded {len(df)} URLs.")
        return df[['url', 'label']]
    except Exception as e:
        print(f"Download failed: {e}. Falling back to sample data.")
        return None # Return None to signal fallback
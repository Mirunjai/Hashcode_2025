import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
from pathlib import Path
from tqdm import tqdm

# NEW: Import the necessary libraries for parallel processing
from concurrent.futures import ThreadPoolExecutor, as_completed

from feature_extractor import FeatureExtractor
from data_loader import get_balanced_dataset

def train_with_advanced_features():
    """
    Train model with a PARALLELIZED advanced feature extractor for maximum speed.
    """
    BASE_DIR = Path(__file__).parent
    MODEL_DIR = BASE_DIR / "models"
    MODEL_PATH = MODEL_DIR / "phishing_model.joblib"
    
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    print("Loading dataset...")
    df = get_balanced_dataset()
    if df.empty:
        print("Dataset is empty. Aborting training.")
        return
    print(f"Dataset loaded: {len(df)} URLs")

    print("Extracting ADVANCED features from URLs using multiple threads...")
    extractor = FeatureExtractor()
    features_list = []
    
    # --- START OF PARALLEL FEATURE EXTRACTION BLOCK ---
    # We create a ThreadPoolExecutor, which manages a pool of worker threads.
    # `max_workers=16` means up to 16 URLs will be processed at the same time.
    # This is ideal for network-bound tasks like WHOIS lookups.
    with ThreadPoolExecutor(max_workers=16) as executor:
        # We submit a job to the executor for each URL. This returns a "future" object.
        # We store these futures in a dictionary to link them back to the original URL if an error occurs.
        futures = {executor.submit(extractor.extract_features, url): url for url in df['url']}
        
        # `as_completed` yields futures as they finish, allowing us to process results immediately.
        # We wrap this in `tqdm` to create a live progress bar.
        for future in tqdm(as_completed(futures), total=len(df['url']), desc="Extracting features"):
            try:
                # `future.result()` gets the return value (the features dict) from the function.
                # If the function raised an exception, .result() will re-raise it here.
                features = future.result()
                features_list.append(features)
            except Exception as e:
                # If an error occurred in one of the threads, we can catch it.
                url = futures[future]
                print(f"\n[Warning] Failed to extract features from: {url} - Error: {e}")
                # Append an empty dict as a placeholder for the failed URL.
                features_list.append({})
    # --- END OF PARALLEL FEATURE EXTRACTION BLOCK ---
    
    print("\nConverting features to DataFrame...")
    
    X = pd.DataFrame(features_list)
    y = df['label'].values
    
    print(f"Feature extraction complete:")
    print(f"   Samples: {X.shape[0]}")
    print(f"   Features: {X.shape[1]}")
    
    X = X.replace([float('inf'), float('-inf')], 0).fillna(-1)
    
    print("Splitting data into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training RandomForestClassifier model (using faster settings)...")
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        random_state=42, 
        n_jobs=-1,
        class_weight='balanced'
    )
    model.fit(X_train, y_train)

    print("Evaluating model...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'])

    print(f"\nModel Accuracy: {accuracy:.4f}")
    print("Classification Report:")
    print(report)

    print(f"Saving model to {MODEL_PATH}...")
    try:
        model_payload = {
            'model': model,
            'feature_names': X.columns.tolist()
        }
        joblib.dump(model_payload, MODEL_PATH)
        print("Model saved successfully!")
            
    except Exception as e:
        print(f"Error saving model: {e}")

if __name__ == "__main__":
    train_with_advanced_features()
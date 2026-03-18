# train_model_with_whois.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
from pathlib import Path
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

from feature_extractor import FeatureExtractor
from data_loader import get_balanced_dataset

def train_with_whois_features(enable_whois_during_training=True):
    """
    Train model with optional WHOIS features
    """
    BASE_DIR = Path(__file__).parent
    MODEL_DIR = BASE_DIR / "models"
    MODEL_PATH = MODEL_DIR / "phishing_model.joblib"
    
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    print("Loading dataset...")
    df = get_balanced_dataset(sample_size=4000)
    if df.empty:
        print("Dataset is empty. Aborting training.")
        return
    print(f"Dataset loaded: {len(df)} URLs")
    
    print(f"Extracting features with WHOIS = {enable_whois_during_training}...")
    extractor = FeatureExtractor(enable_whois=enable_whois_during_training)
    features_list = []
    
    # Use ThreadPoolExecutor but with limited workers for WHOIS to avoid rate limiting
    max_workers = 4 if enable_whois_during_training else 16
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(extractor.extract_features, url): url for url in df['url']}
        
        for future in tqdm(as_completed(futures), total=len(df['url']), desc="Extracting features"):
            try:
                features = future.result()
                features_list.append(features)
            except Exception as e:
                url = futures[future]
                print(f"\n[Warning] Failed to extract features from: {url} - Error: {e}")
                features_list.append({})
    
    print("\nConverting features to DataFrame...")
    X = pd.DataFrame(features_list)
    y = df['label'].values
    
    print(f"Feature extraction complete:")
    print(f"   Samples: {X.shape[0]}")
    print(f"   Features: {X.shape[1]}")
    
    # Clean the data
    X = X.replace([float('inf'), float('-inf')], 0).fillna(-1)
    
    print("Splitting data into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        min_samples_split=8,
        min_samples_leaf=4,
        max_features='sqrt',
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
    
    # Show WHOIS feature statistics if enabled
    if enable_whois_during_training:
        whois_failures = X['whois_lookup_failed'].sum()
        whois_success = len(X) - whois_failures
        print(f"\nWHOIS Statistics:")
        print(f"   Successful lookups: {whois_success}")
        print(f"   Failed lookups: {whois_failures}")
        print(f"   Success rate: {whois_success/len(X)*100:.1f}%")

    print(f"Saving model to {MODEL_PATH}...")
    try:
        model_payload = {
            'model': model,
            'feature_names': X.columns.tolist(),
            'training_accuracy': accuracy,
            'whois_enabled_during_training': enable_whois_during_training
        }
        joblib.dump(model_payload, MODEL_PATH)
        print("Model saved successfully!")
            
    except Exception as e:
        print(f"Error saving model: {e}")

if __name__ == "__main__":
    # Train without WHOIS first (faster, more reliable)
    print("=== TRAINING WITHOUT WHOIS (Recommended) ===")
    train_with_whois_features(enable_whois_during_training=True)
    
    # Uncomment to train with WHOIS (slower, might have failures)
    # print("\n=== TRAINING WITH WHOIS (Experimental) ===")
    # train_with_whois_features(enable_whois_during_training=True)
# train_model_domain_aware.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
from pathlib import Path
from tqdm import tqdm

from feature_extractor import FeatureExtractor
from data_loader import get_balanced_dataset

def train_domain_aware_model():
    """
    Train model with domain-aware features and sample weighting
    """
    BASE_DIR = Path(__file__).parent
    MODEL_DIR = BASE_DIR / "models"
    MODEL_PATH = MODEL_DIR / "phishing_model.joblib"
    
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    print("Loading dataset...")
    df = get_balanced_dataset(sample_size=3000)  # Use more data
    if df.empty:
        print("Dataset is empty. Aborting training.")
        return
    print(f"Dataset loaded: {len(df)} URLs")

    print("Extracting DOMAIN-AWARE features...")
    extractor = FeatureExtractor()
    features_list = []
    
    # Extract features and track trusted domains
    trusted_urls = []
    for url in tqdm(df['url'], desc="Extracting features"):
        try:
            features = extractor.extract_features(url)
            features_list.append(features)
            
            # Track if this is a trusted domain
            if features.get('is_trusted_domain', 0) == 1:
                trusted_urls.append(True)
            else:
                trusted_urls.append(False)
        except Exception as e:
            print(f"\n[Warning] Failed to extract features: {e}")
            features_list.append({})
            trusted_urls.append(False)
    
    print("\nConverting features to DataFrame...")
    X = pd.DataFrame(features_list)
    y = df['label'].values
    
    print(f"Feature extraction complete:")
    print(f"   Samples: {X.shape[0]}")
    print(f"   Features: {X.shape[1]}")
    print(f"   Trusted domains found: {sum(trusted_urls)}")
    
    # Clean the data
    X = X.replace([float('inf'), float('-inf')], 0).fillna(0)
    
    print("Splitting data into training and testing sets...")
    X_train, X_test, y_train, y_test, trusted_train, trusted_test = train_test_split(
        X, y, trusted_urls, test_size=0.2, random_state=42, stratify=y
    )

    # CREATE SAMPLE WEIGHTS: Give higher weight to trusted domains that are legitimate
    sample_weights = np.ones(len(X_train))
    for i, (trusted, label) in enumerate(zip(trusted_train, y_train)):
        if trusted and label == 0:  # Trusted + legitimate
            sample_weights[i] = 2.0  # Higher weight
        elif not trusted and label == 1:  # Untrusted + phishing
            sample_weights[i] = 1.5  # Medium weight
    
    print("Training Domain-Aware RandomForest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=10,
        min_samples_leaf=5,
        max_features='sqrt',
        random_state=42, 
        n_jobs=-1,
        class_weight='balanced'
    )
    
    # Train with sample weights
    model.fit(X_train, y_train, sample_weight=sample_weights)

    print("Evaluating model...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'])

    print(f"\nModel Accuracy: {accuracy:.4f}")
    print("Classification Report:")
    print(report)
    
    # Test trusted domain performance
    trusted_test = np.array(trusted_test)
    trusted_accuracy = accuracy_score(y_test[trusted_test], y_pred[trusted_test])
    print(f"Trusted domains accuracy: {trusted_accuracy:.4f}")

    print(f"Saving model to {MODEL_PATH}...")
    try:
        model_payload = {
            'model': model,
            'feature_names': X.columns.tolist(),
            'training_accuracy': accuracy,
            'extractor_type': 'DomainAwareFeatureExtractor'
        }
        joblib.dump(model_payload, MODEL_PATH)
        print("Model saved successfully!")
            
    except Exception as e:
        print(f"Error saving model: {e}")

if __name__ == "__main__":
    train_domain_aware_model()
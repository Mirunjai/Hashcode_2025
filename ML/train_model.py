# train_model.py (updated)
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
from pathlib import Path
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# Use the fast extractor instead
from feature_extractor import FastFeatureExtractor
from data_loader import get_balanced_dataset

def train_with_fast_features():
    """
    Train model with FAST feature extractor (no WHOIS during training)
    """
    BASE_DIR = Path(__file__).parent
    MODEL_DIR = BASE_DIR / "models"
    MODEL_PATH = MODEL_DIR / "phishing_model.joblib"
    
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    print("Loading dataset...")
    # Use MORE data for better training
    df = get_balanced_dataset(sample_size=2000)  # Increased from 200
    if df.empty:
        print("Dataset is empty. Aborting training.")
        return
    print(f"Dataset loaded: {len(df)} URLs")

    print("Extracting FAST features from URLs (no WHOIS lookups)...")
    extractor = FastFeatureExtractor()
    features_list = []
    
    # Extract features sequentially for reliability
    for url in tqdm(df['url'], desc="Extracting features"):
        try:
            features = extractor.extract_features(url)
            features_list.append(features)
        except Exception as e:
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

    print("Training RandomForestClassifier model...")
    # Use better parameters
    model = RandomForestClassifier(
        n_estimators=100,  # More trees
        max_depth=15,      # Deeper trees
        min_samples_split=10,
        min_samples_leaf=5,
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
    
    # Check if accuracy is reasonable
    if accuracy < 0.7:
        print("\n⚠️  WARNING: Model accuracy is low. Consider:")
        print("   - Using more training data")
        print("   - Checking feature quality")
        print("   - Trying different model parameters")

    print(f"Saving model to {MODEL_PATH}...")
    try:
        model_payload = {
            'model': model,
            'feature_names': X.columns.tolist(),
            'training_accuracy': accuracy
        }
        joblib.dump(model_payload, MODEL_PATH)
        print("Model saved successfully!")
            
    except Exception as e:
        print(f"Error saving model: {e}")

if __name__ == "__main__":
    train_with_fast_features()
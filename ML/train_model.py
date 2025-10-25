# train_model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
from pathlib import Path
from tqdm import tqdm

# Import your advanced feature extractor
from feature_extractor import FeatureExtractor
from data_loader import get_balanced_dataset

tqdm.pandas()

def train_with_advanced_features():
    """
    Train model with the advanced feature extractor
    """
    BASE_DIR = Path(__file__).parent
    MODEL_DIR = BASE_DIR / "models"
    MODEL_PATH = MODEL_DIR / "phishing_model.joblib"
    
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    print("Loading dataset...")
    
    try:
        df = get_balanced_dataset()
        print(f"Dataset loaded: {len(df)} URLs")
    except Exception as e:
        print(f"Error loading data: {e}")
        return

    print("Extracting ADVANCED features from URLs...")
    extractor = FeatureExtractor()
    
    # Extract features with progress bar
    features_list = []
    failed_urls = 0
    
    for url in tqdm(df['url'], desc="Extracting features"):
        try:
            features = extractor.extract_features(url)
            features_list.append(features)
        except Exception as e:
            print(f"Failed to extract features from: {url} - {e}")
            features_list.append({})
            failed_urls += 1
    
    if failed_urls > 0:
        print(f"Failed to process {failed_urls} URLs")
    
    # Convert to DataFrame - handle dictionary features
    print("Converting features to DataFrame...")
    
    # Get all possible feature keys
    all_keys = set()
    for features in features_list:
        if features:  # Only if features is not empty
            all_keys.update(features.keys())
    
    # Create DataFrame with all features
    processed_features = []
    for features in features_list:
        if features:
            row = {key: features.get(key, -1) for key in all_keys}
        else:
            row = {key: -1 for key in all_keys}  # Default values for failed extraction
        processed_features.append(row)
    
    X = pd.DataFrame(processed_features)
    y = df['label'].values
    
    print(f"Feature extraction complete:")
    print(f"   Samples: {X.shape[0]}")
    print(f"   Features: {X.shape[1]}")
    print(f"   Feature names: {list(X.columns)}")
    
    # Handle any infinite or NaN values
    X = X.replace([float('inf'), float('-inf')], 0)
    X = X.fillna(-1)
    
    print("Splitting data into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training RandomForestClassifier model...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42, 
        n_jobs=-1,
        max_depth=15,
        min_samples_split=5
    )
    model.fit(X_train, y_train)

    print("Evaluating model...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'])

    print(f"\nModel Accuracy: {accuracy:.4f}")
    print("Classification Report:")
    print(report)

    # Save model with feature information
    print(f"Saving model to {MODEL_PATH}...")
    try:
        model_payload = {
            'model': model,
            'feature_names': X.columns.tolist(),
            'feature_importances': dict(zip(X.columns, model.feature_importances_))
        }
        joblib.dump(model_payload, MODEL_PATH)
        print("Model saved successfully!")
        
        # Show top features
        print("\nTop 10 Most Important Features:")
        feature_imp = sorted(model_payload['feature_importances'].items(), 
                           key=lambda x: x[1], reverse=True)
        for name, imp in feature_imp[:10]:
            print(f"   {name}: {imp:.4f}")
            
    except Exception as e:
        print(f"Error saving model: {e}")

if __name__ == "__main__":
    train_with_advanced_features()
# train_robust_without_whois.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
from pathlib import Path
from tqdm import tqdm

from feature_extractor import FeatureExtractor
from data_loader import get_balanced_dataset

def train_robust_model():
    """
    Train a high-accuracy model WITHOUT WHOIS for reliable base predictions
    """
    BASE_DIR = Path(__file__).parent
    MODEL_DIR = BASE_DIR / "models"
    MODEL_PATH = MODEL_DIR / "phishing_model_robust.joblib"
    
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    print("🚀 TRAINING ROBUST MODEL (NO WHOIS)")
    print("=" * 60)
    
    print("Loading larger dataset...")
    df = get_balanced_dataset(sample_size=5000)  # Use more data
    if df.empty:
        print("Dataset is empty. Aborting training.")
        return
    print(f"Dataset loaded: {len(df)} URLs")
    print(f"Distribution: {df['label'].value_counts().to_dict()}")

    print("\nExtracting features WITHOUT WHOIS (fast and reliable)...")
    extractor = FeatureExtractor(enable_whois=False)  # No WHOIS during training
    features_list = []
    
    # Fast extraction without WHOIS
    for url in tqdm(df['url'], desc="Extracting features"):
        try:
            features = extractor.extract_features(url)
            features_list.append(features)
        except Exception as e:
            print(f"\n[Warning] Failed to extract features: {e}")
            features_list.append({})
    
    print("\nConverting features to DataFrame...")
    X = pd.DataFrame(features_list)
    y = df['label'].values
    
    print(f"✅ Feature extraction complete:")
    print(f"   Samples: {X.shape[0]}")
    print(f"   Features: {X.shape[1]}")
    
    # Clean the data
    X = X.replace([float('inf'), float('-inf')], -1).fillna(-1)
    
    print("Splitting data into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training Robust RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=25,
        min_samples_split=5,
        min_samples_leaf=2,
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

    print(f"\n📊 MODEL PERFORMANCE:")
    print(f"   Accuracy: {accuracy:.4f}")
    print("Classification Report:")
    print(report)
    
    if accuracy < 0.75:
        print("❌ Accuracy too low. Consider:")
        print("   - Using more training data")
        print("   - Checking feature quality")
        print("   - Adjusting model parameters")
    else:
        print("✅ Model accuracy is good!")

    print(f"\n💾 Saving robust model to {MODEL_PATH}...")
    try:
        model_payload = {
            'model': model,
            'feature_names': X.columns.tolist(),
            'training_accuracy': accuracy,
            'whois_enabled': False,
            'model_type': 'Robust_No_WHOIS'
        }
        joblib.dump(model_payload, MODEL_PATH)
        print("✅ Robust model saved successfully!")
            
    except Exception as e:
        print(f"❌ Error saving model: {e}")

if __name__ == "__main__":
    train_robust_model()
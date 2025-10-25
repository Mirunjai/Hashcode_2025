import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import matplotlib.pyplot as plt

# --- Local Modules ---
from feature_extractor import FeatureExtractor
from data_loader import load_real_data # <-- IMPORTING THE NEW LOADER

def create_sample_data():
    """Fallback function to create sample data if the download fails."""
    print("Creating local sample training data...")
    phishing_urls = [
        "http://verify-paypal-account.com", "https://apple-id-secure-login.net", "http://192.168.1.1/login.php",
        "http://microsoft-online-security.com", "http://netflix-billing-update.org", "http://amazon-account-verification.com",
    ]
    legitimate_urls = [
        "https://paypal.com", "https://apple.com", "https://microsoft.com",
        "https://netflix.com", "https://amazon.com", "https://github.com",
    ]
    urls = phishing_urls + legitimate_urls
    labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)
    return pd.DataFrame({'url': urls, 'label': labels})

def main():
    print("Starting Advanced ML Model Training Pipeline...")
    
    # 1. Load Data (with fallback)
    df = load_real_data()
    if df is None:
        df = create_sample_data()
    
    print(f"Using dataset with {len(df)} URLs ({df['label'].sum()} phishing, {len(df) - df['label'].sum()} legitimate)")
    
    # 2. Extract Features
    extractor = FeatureExtractor()
    print("Extracting features from all URLs (this may take a moment for large datasets)...")
    # Using list comprehension for speed
    X = [extractor.extract_features(url) for url in df['url']]
    y = df['label']
    
    # Define feature names for the visualization
    feature_names = [
        'url_length', 'domain_length', 'num_dots', 'num_hyphens', 'num_slashes',
        'num_equals', 'num_question_marks', 'num_at_symbols', 'has_ip', 'is_https',
        'has_login', 'has_verify', 'has_secure', 'has_account', 'has_bank', 'has_paypal',
        'entropy', 'vowel_ratio'
    ]
    
    # 3. Split Data
    # stratify=y ensures the phishing/legit ratio is the same in train and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"Training on {len(X_train)} samples, testing on {len(X_test)} samples.")
    
    # 4. Train Model
    print("Training Random Forest model...")
    # n_jobs=-1 uses all available CPU cores for faster training on the large dataset
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    # 5. Evaluate Model
    print("\n" + "="*30)
    print("MODEL EVALUATION")
    print("="*30)
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    print(f"Accuracy: {accuracy:.2%}")
    print("\nClassification Report:")
    # Provides precision, recall, f1-score - crucial for judging
    print(classification_report(y_test, predictions, target_names=['Legitimate', 'Phishing']))
    
    # 6. Save the Production Model
    joblib.dump(model, 'phishing_model.pkl')
    print("Production-ready model saved as 'phishing_model.pkl'")
    
    # 7. Generate and Save Feature Importance Chart (for the presentation!)
    try:
        importances = model.feature_importances_
        feature_importance_df = pd.DataFrame({'feature': feature_names, 'importance': importances})
        feature_importance_df = feature_importance_df.sort_values('importance', ascending=False).head(10)

        plt.figure(figsize=(10, 6))
        plt.barh(feature_importance_df['feature'], feature_importance_df['importance'])
        plt.xlabel("Importance")
        plt.ylabel("Feature")
        plt.title("Top 10 Most Important Features in Phishing Detection")
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plt.savefig('feature_importance.png')
        print("Feature importance chart saved as 'feature_importance.png'")
    except Exception as e:
        print(f"Could not generate feature importance chart. Reason: {e}")


if __name__ == "__main__":
    main()
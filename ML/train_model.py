# train_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
from feature_extractor import FeatureExtractor

def create_sample_data():
    """Create sample data since we might not have internet for PhishTank"""
    print("Creating sample training data...")
    
    # These are realistic examples - phishing sites often use these patterns
    phishing_urls = [
        "http://verify-paypal-account.com",
        "https://apple-id-secure-login.net", 
        "http://microsoft-online-security.com",
        "http://netflix-billing-update.org",
        "http://amazon-account-verification.com",
        "http://bankofamerica-secure-login.net",
        "http://google-drive-security-alert.com",
        "http://facebook-login-confirm.com",
        "http://whatsapp-verification-code.com",
        "http://instagram-account-recovery.com",
        "http://192.168.1.1/login.php",
        "http://secure-login-bank.com",
        "http://update-your-password.com",
        "http://account-verification-required.com",
        "http://suspicious-activity-alert.com"
    ]
    
    legitimate_urls = [
        "https://paypal.com",
        "https://apple.com",
        "https://microsoft.com",
        "https://netflix.com", 
        "https://amazon.com",
        "https://bankofamerica.com",
        "https://google.com",
        "https://facebook.com",
        "https://whatsapp.com",
        "https://instagram.com",
        "https://github.com",
        "https://stackoverflow.com",
        "https://wikipedia.org",
        "https://youtube.com",
        "https://reddit.com"
    ]
    
    # Combine and label (1 = phishing, 0 = legitimate)
    urls = phishing_urls + legitimate_urls
    labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)
    
    return pd.DataFrame({'url': urls, 'label': labels})

def main():
    print("Starting ML Model Training...")
    
    # 1. Load data
    df = create_sample_data()
    print(f"Dataset: {len(df)} URLs ({sum(df['label'])} phishing, {len(df)-sum(df['label'])} legitimate)")
    
    # 2. Extract features
    extractor = FeatureExtractor()
    print("Extracting features from URLs...")
    X = [extractor.extract_features(url) for url in df['url']]
    y = df['label']
    
    # 3. Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    print(f"Training on {len(X_train)} samples, testing on {len(X_test)} samples")
    
    # 4. Train model
    print("Training Random Forest model...")
    model = RandomForestClassifier(n_estimators=50, random_state=42)  # Smaller for speed
    model.fit(X_train, y_train)
    
    # 5. Evaluate
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    print(f"Model Accuracy: {accuracy:.2%}")
    
    # Show some predictions
    print("\nSample Predictions:")
    for i in range(3):
        url = df.iloc[i]['url']
        actual = "PHISHING" if df.iloc[i]['label'] == 1 else "SAFE"
        pred = "PHISHING" if predictions[i] == 1 else "SAFE"
        print(f"   {url[:40]}... -> Actual: {actual}, Predicted: {pred}")
    
    # 6. Save model
    joblib.dump(model, 'phishing_model.pkl')
    print("Model saved as 'phishing_model.pkl'")
    
    # 7. Save feature names for reference
    feature_names = [
        'url_length', 'domain_length', 'num_dots', 'num_hyphens', 'num_slashes',
        'num_equals', 'num_question_marks', 'num_at_symbols', 'has_ip', 'is_https',
        'has_login', 'has_verify', 'has_secure', 'has_account', 'has_bank', 'has_paypal',
        'entropy', 'vowel_ratio'
    ]
    print(f"Features used: {', '.join(feature_names)}")

if __name__ == "__main__":
    main()
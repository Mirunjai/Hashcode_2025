# analyze_url.py
import pandas as pd
import numpy as np
from ml_handler import ml_handler, init_ml_handler

def analyze_url_detailed(url):
    """
    Analyze a URL and show exactly how each feature contributes to the score
    """
    print(f"\n🔍 DETAILED ANALYSIS FOR: {url}")
    print("=" * 60)
    
    # Load model and get prediction
    if not ml_handler.is_loaded:
        init_ml_handler()
    
    result = ml_handler.predict_url(url)
    
    if not result['success']:
        print(f"❌ Error: {result.get('error', 'Unknown error')}")
        return
    
    # Get the feature values used for this prediction
    features_dict = ml_handler.feature_extractor.extract_features(url)
    features_df = ml_handler._prepare_features(features_dict)
    
    print(f"📊 Overall Threat Score: {result['threat_score']}/100")
    print(f"🎯 Verdict: {result['verdict']}")
    print(f"🤖 Confidence: {result['confidence']:.3f}")
    print(f"🔢 Features Analyzed: {result['features_analyzed']}")
    
    print(f"\n📈 FEATURE BREAKDOWN:")
    print("-" * 60)
    
    # Get feature importances from the model
    importances = ml_handler.model.feature_importances_
    feature_names = ml_handler.feature_names
    
    # Calculate contribution for each feature
    feature_contributions = []
    feature_row = features_df.iloc[0]
    
    for i, feature_name in enumerate(feature_names):
        if i < len(importances):
            importance = importances[i]
            value = feature_row[feature_name]
            
            # Calculate contribution (importance * normalized value)
            # For binary features: contribution = importance * value
            # For continuous features: we normalize the contribution
            if feature_name in ['has_ip', 'has_shortening', 'whois_lookup_failed']:
                # Binary features - direct contribution
                contribution = importance * value * 100
            else:
                # Continuous features - scale the contribution
                contribution = importance * abs(value) * 10
            
            feature_contributions.append({
                'feature': feature_name,
                'value': value,
                'importance': importance,
                'contribution': contribution
            })
    
    # Sort by absolute contribution
    feature_contributions.sort(key=lambda x: abs(x['contribution']), reverse=True)
    
    # Display top contributors
    print(f"\n🏆 TOP CONTRIBUTING FEATURES:")
    for i, fc in enumerate(feature_contributions[:10]):
        contribution_type = "🟥 INCREASES threat" if fc['contribution'] > 0 else "🟩 DECREASES threat"
        print(f"{i+1:2d}. {fc['feature']:25} = {fc['value']:8.2f} | "
              f"Contribution: {fc['contribution']:6.2f} | {contribution_type}")
    
    # Show feature categories
    print(f"\n📋 FEATURE CATEGORIES ANALYSIS:")
    analyze_by_category(features_dict, feature_contributions)
    
    # Show raw feature values
    print(f"\n🔍 RAW FEATURE VALUES (first 15):")
    for i, (feature, value) in enumerate(features_dict.items()):
        if i < 15:  # Show first 15 features
            print(f"   {feature:25} = {value}")
        else:
            break
    
    return result, feature_contributions

def analyze_by_category(features_dict, contributions):
    """Analyze contributions by feature categories"""
    categories = {
        '📏 Length Features': ['url_length', 'hostname_length', 'path_length', 'fd_length'],
        '🔤 Character Counts': ['count-', 'count@', 'count?', 'count%', 'count.', 'count=', 
                               'count-digits', 'count-letters', 'count-dir'],
        '🌐 Protocol & Structure': ['count-http', 'count-https', 'count-www', 'has_ip', 'has_shortening'],
        '🎯 Keywords & Entropy': ['keyword_count', 'url_entropy', 'domain_entropy'],
        '📅 Domain Age': ['domain_age', 'domain_lifespan', 'whois_lookup_failed']
    }
    
    category_scores = {}
    
    for category, features in categories.items():
        cat_contrib = 0
        cat_features = []
        
        for fc in contributions:
            if fc['feature'] in features:
                cat_contrib += fc['contribution']
                cat_features.append(fc['feature'])
        
        if cat_features:
            category_scores[category] = cat_contrib
            direction = "🟥" if cat_contrib > 0 else "🟩"
            print(f"   {category:30} {direction} {cat_contrib:7.2f}")
    
    return category_scores

def compare_urls(urls):
    """Compare multiple URLs side by side"""
    print(f"\n🔀 COMPARING {len(urls)} URLs:")
    print("=" * 80)
    
    results = []
    for url in urls:
        result, contributions = analyze_url_detailed(url)
        top_contributors = [fc for fc in contributions[:3]]
        results.append({
            'url': url,
            'score': result['threat_score'],
            'verdict': result['verdict'],
            'top_features': top_contributors
        })
    
    print(f"\n📊 COMPARISON SUMMARY:")
    print("-" * 80)
    for res in results:
        print(f"🔗 {res['url']}")
        print(f"   Score: {res['score']}/100 | Verdict: {res['verdict']}")
        print(f"   Top features: ", end="")
        for tf in res['top_features']:
            print(f"{tf['feature']}({tf['contribution']:.1f}) ", end="")
        print("\n")

def interactive_analysis():
    """Interactive mode to analyze multiple URLs"""
    print("🎯 URL Threat Score Analyzer")
    print("Enter URLs to analyze (type 'quit' to exit):")
    
    while True:
        url = input("\n🔗 Enter URL: ").strip()
        if url.lower() in ['quit', 'exit', 'q']:
            break
        if url:
            analyze_url_detailed(url)

if __name__ == "__main__":
    # Example analysis of problematic URLs
    test_urls = [
        "https://github.com/scikit-learn/scikit-learn",
        "http://secure-login-update-account-paypal.com/websrc",
        "https://paypal.com",
        "https://example.com/login-form-here"
    ]
    
    # Analyze each URL in detail
    for url in test_urls:
        analyze_url_detailed(url)
    
    # Compare them
    compare_urls(test_urls)
    
    # Uncomment for interactive mode:
    # interactive_analysis()
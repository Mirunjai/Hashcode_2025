# orchestrator.py
from feature_extractor import extract_network_features
from ml_handler import get_ml_prediction
from content_analyzer import analyze_page_content
from scoring_engine import calculate_final_score
from typing import Optional

def orchestrate_url_analysis(url: str, screenshot_base64: Optional[str] = None):
    """The main workflow controller that manages the entire analysis process."""
    print(f"\n--- [PM] Starting zero-day focused investigation for: {url} ---")
    
    network_features = extract_network_features(url)
    content_features = analyze_page_content(url)
    ml_probability = get_ml_prediction(network_features)
    
    # (Optional OCR logic could be added here if a screenshot is provided)

    final_report = calculate_final_score(network_features, content_features, ml_probability)
    final_report['url'] = url
    print(f"--- [PM] Investigation complete. Verdict: {final_report['verdict']} ---")
    
    return final_report
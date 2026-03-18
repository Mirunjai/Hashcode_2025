# orchestrator.py (FINAL VERSION - SYNCHRONIZED WITH ml_handler.py AND UI)

from ml_handler import predict_url
from content_analyzer import analyze_page_content

def _create_ui_params(features: dict, ml_confidence: float) -> list:
    """Helper to translate raw features into the 'params' array for the UI."""
    param_map = {
        'url_length': ["URL Length Score", lambda v: min(v, 100)],
        'hostname_hyphens': ["Special Characters Count", lambda v: min(v * 25, 100)],
        'domain_age': ["Domain Age", lambda v: 100 if v == -1 else (100 if v < 30 else (60 if v < 180 else 10))],
        'uses_ip_address': ["Uses Direct IP", lambda v: 100 if v == 1 else 0],
        'domain_lifespan': ["Domain Registration Length", lambda v: 10 if v > 700 else 85],
    }
    ui_params = []
    for feature_key, (ui_label, score_func) in param_map.items():
        if feature_key in features:
            raw_value = features[feature_key]
            ui_params.append({'key': ui_label, 'value': int(score_func(raw_value))})
    ui_params.append({'key': 'ML Model Confidence', 'value': int(ml_confidence * 100)})
    return ui_params

def orchestrate_url_analysis(url: str, screenshot_base64: str = None):
    """
    Main workflow: gets the ML report, enriches it with content analysis,
    and formats the final package for the UI.
    """
    print(f"\n--- [Orchestrator] Starting analysis for: {url} ---")
    
    # STEP 1: Get the complete ML prediction from your friend's handler.
    # It now returns everything we need: verdict, score, and the features used.
    ml_report = predict_url(url)
    
    if not ml_report.get('success', False):
        return ml_report

    # STEP 2: Get supplementary live content analysis.
    content_features = analyze_page_content(url)
    
    # --- STEP 3: CONSTRUCT THE FINAL REPORT FOR THE UI ---
    all_features = ml_report.get('features', {})
    
    highlights = []
    domain_age = all_features.get('domain_age', 365)
    if domain_age != -1 and domain_age < 30:
        highlights.append(f"CRITICAL: Domain is brand new ({domain_age} days old).")
    if content_features.get('form_action_is_external'):
        highlights.append("CRITICAL: A form on this page sends data to an external domain.")
    if not highlights and ml_report.get('verdict') == 'MALICIOUS':
        highlights.append("HIGH RISK: The URL's structure strongly matches known phishing patterns.")
    if not highlights:
        highlights.append("INSIGHT: No critical risk indicators found.")

    final_report = {
        'url': url,
        'threatScore': ml_report.get('threat_score'),
        'category': ml_report.get('verdict'),
        'reasoning_highlights': highlights,
        'params': _create_ui_params(all_features, ml_report.get('confidence', 0))
    }
    
    print(f"--- [Orchestrator] Analysis complete. Final Verdict: {final_report['category']} ---")
    return final_report
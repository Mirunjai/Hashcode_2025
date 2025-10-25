# orchestrator.py (FINAL VERSION)
from ml_handler import predict_url # Now we only need this!
from content_analyzer import analyze_page_content
from scoring_engine import calculate_final_score

def orchestrate_url_analysis(url: str, screenshot_base64: str = None):
    """The main workflow controller that now gets everything from the ML handler."""
    print(f"\n--- [Orchestrator] Starting analysis for: {url} ---")
    
    # STEP 1: Get the complete ML prediction AND its features in one call.
    ml_report = predict_url(url)
    
    if not ml_report.get('success', False):
        return ml_report # Return error report immediately

    # STEP 2: Get supplementary content analysis.
    content_features = analyze_page_content(url)
    
    # STEP 3: Pass all collected intelligence to the final judge.
    final_report = calculate_final_score(ml_report, content_features)
    final_report['url'] = url
    print(f"--- [Orchestrator] Analysis complete. Final Verdict: {final_report.get('verdict')} ---")
    
    return final_report
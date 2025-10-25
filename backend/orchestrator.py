# orchestrator.py (CONFIRMED CORRECT - NO CHANGES NEEDED)

from ml_handler import predict_url
from content_analyzer import analyze_page_content
from scoring_engine import calculate_final_score

def orchestrate_url_analysis(url: str, screenshot_base64: str = None):
    """
    The main workflow controller for the backend. Its job is to delegate tasks
    to the specialized modules and pass the results to the final judge.
    This logic is correct and requires no changes.
    """
    print(f"\n--- [Orchestrator] Starting full analysis for: {url} ---")
    
    # STEP 1: Call the ML handler. It will return a full report including
    # the prediction AND the features it used.
    ml_report = predict_url(url)
    
    # If the ML part fails (e.g., model not loaded), immediately return the error.
    if not ml_report.get('success', False):
        return ml_report

    # STEP 2: Call the content analyzer to get supplementary intelligence
    # from the live webpage.
    content_features = analyze_page_content(url)
    
    # STEP 3: Pass both complete reports to the scoring engine. The engine is
    # now smart enough to extract the details it needs from these reports.
    final_report = calculate_final_score(ml_report, content_features)
    
    # For completeness, add the original URL to the final report.
    final_report['url'] = url
    
    print(f"--- [Orchestrator] Analysis complete. Final Verdict: {final_report.get('verdict')} ---")
    
    return final_report
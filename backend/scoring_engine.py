# scoring_engine.py

def calculate_final_score(network_feats: dict, content_feats: dict, ml_prob: float) -> dict:
    """
    Combines all intelligence into a final score, with a strong focus on zero-day indicators.
    """
    print("[Judge] Reviewing all reports for the final verdict...")
    
    # --- Define Weights, giving high importance to zero-day signals ---
    weights = {'ml': 0.5, 'domain_age': 0.3, 'content_critical': 0.2}

    # --- Convert evidence into 0-to-1 risk factors ---
    domain_age_days = network_feats.get('domain_age_days', 365)
    domain_age_risk = 1.0 if domain_age_days < 30 else 0.5 if domain_age_days < 90 else 0.0
    
    content_critical_risk = 1.0 if content_feats.get('form_action_is_external') else 0.0

    # --- Calculate Final Weighted Score ---
    final_score_prob = (ml_prob * weights['ml']) + \
                       (domain_age_risk * weights['domain_age']) + \
                       (content_critical_risk * weights['content_critical'])
    
    final_score_int = int(min(final_score_prob, 1.0) * 100)

    # --- Generate Reasoning Highlights with a zero-day focus ---
    highlights = []
    if domain_age_risk == 1.0:
        highlights.append(f"CRITICAL: Domain is brand new ({domain_age_days} days old), a primary indicator of a zero-day attack.")
    if content_critical_risk == 1.0:
        highlights.append("CRITICAL: Login form sends your data to a suspicious external domain.")
    if not network_feats.get('has_mx_record', True):
        highlights.append("HIGH RISK: Domain has no mail server, indicating it's not a legitimate business.")
    if ml_prob > 0.9:
        highlights.append("HIGH RISK: ML model detected strong patterns consistent with phishing.")
    
    if not highlights:
        highlights.append("INSIGHT: No critical zero-day indicators were found.")
        
    # --- Determine Verdict ---
    if final_score_int > 70: verdict = "MALICIOUS"
    elif final_score_int > 30: verdict = "SUSPICIOUS"
    else: verdict = "SAFE"

    return {
        'threat_score': final_score_int,
        'verdict': verdict,
        'reasoning_highlights': highlights
    }
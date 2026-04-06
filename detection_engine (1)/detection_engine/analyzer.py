from .detector import scan_email
from .classifier import classify
from .sender_profile import build_sender_profile

# Assemble final explainable result using content detector + sender profile

def analyze_email(subject, body, sender=""):
    # content detection
    scores = scan_email(subject, body, sender)
    content_label, content_details = classify(scores)

    # sender intelligence (parsing + checks)
    sender_profile = build_sender_profile(sender)

    # Determine final label using simple rules
    final_label = content_label
    if content_label == 'Phishing' or (sender_profile.get('risk_level') == 'High' and scores['phishing']['score'] > 0):
        final_label = 'Phishing'
    elif content_label == 'Fake Job Scam' or scores['job_scam']['score'] >= 8:
        final_label = 'Fake Job Scam'
    elif content_label == 'Spam':
        final_label = 'Spam'
    else:
        final_label = 'Safe'

    # If final label is severe, apply content-based reputation penalty to sender
    if final_label in ('Phishing', 'Fake Job Scam'):
        # apply penalty once
        if 'content-based risk escalation' not in sender_profile.get('issues', []):
            sender_profile['reputation_score'] = max(0, sender_profile.get('reputation_score', 100) - 30)
            sender_profile['issues'] = sender_profile.get('issues', []) + ['content-based risk escalation']
            # recalc risk level
            rs = sender_profile['reputation_score']
            if rs >= 70:
                sender_profile['risk_level'] = 'Low'
            elif rs >= 40:
                sender_profile['risk_level'] = 'Medium'
            else:
                sender_profile['risk_level'] = 'High'

    # Build reasons: content hits + sender issues
    reasons = []
    hits = []
    if isinstance(content_details, dict):
        hits = content_details.get('hits') or []
        if isinstance(hits, list):
            reasons.extend(hits)
    reasons.extend(sender_profile.get('issues', []))
    # deduplicate preserving order
    seen = set()
    final_reasons = []
    for r in reasons:
        if r not in seen:
            final_reasons.append(r)
            seen.add(r)

    # compute an explainable confidence (0-100)
    phishing_score = scores['phishing']['score']
    job_score = scores['job_scam']['score']
    spam_score = scores['spam']['score']

    content_strength = max(phishing_score * 12, job_score * 9, spam_score * 5)
    base_conf = int(min(80, max(5, content_strength)))
    sender_factor = int((100 - sender_profile.get('reputation_score', 100)) / 4)
    confidence = max(0, min(100, base_conf + sender_factor))

    # risk_score: 0 (no risk) .. 100 (high risk) - invert reputation for readability
    risk_score = max(0, min(100, 100 - sender_profile.get('reputation_score', 100)))

    # final sender_profile output must include only requested keys
    sp = {
        'claimed_name': sender_profile.get('claimed_name'),
        'email': sender_profile.get('email'),
        'domain': sender_profile.get('domain'),
        'reputation_score': sender_profile.get('reputation_score'),
        'risk_level': sender_profile.get('risk_level'),
        'issues': sender_profile.get('issues', [])
    }

    result = {
        'classification': final_label,
        'confidence': confidence,
        'risk_score': risk_score,
        'sender_profile': sp,
        'reasons': final_reasons
    }

    return result

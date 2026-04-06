def calculate_risk(sender, subject, content):
    """Calculate phishing risk score with detailed sender analysis"""
    import re
    from datetime import datetime
    from gmail_osint import estimate_gmail_age
    from ml_detector import ml_detector
    
    # Trusted domains whitelist
    TRUSTED_DOMAINS = [
        'google.com', 'accounts.google.com', 'gmail.com', 'googlemail.com',
        'linkedin.com', 'indeed.com', 'naukri.com', 'glassdoor.com',
        'monster.com', 'workday.com', 'stackoverflow.com', 'github.com',
        'microsoft.com', 'outlook.com', 'mql5.com', 'facebook.com',
        'twitter.com', 'instagram.com', 'paypal.com', 'amazon.com',
        'apple.com', 'netflix.com', 'adobe.com', 'spotify.com'
    ]
    
    # Fake job scam indicators
    FAKE_JOB_SCAM_INDICATORS = [
        'no interview required', 'registration fee', 'advance payment',
        'whatsapp hr', 'immediate joining', 'guaranteed income',
        'work from home no experience', 'earn 50000 monthly',
        'pay processing fee', 'refundable deposit', 'training fee',
        'earn lakhs', 'part time full payment', 'no qualification needed'
    ]
    
    def _clamp(value, min_value=0, max_value=100):
        return max(min_value, min(max_value, value))

    score = 0
    flags = []
    issues = []

    # Get ML prediction first
    ml_result = ml_detector.predict_email(subject, content, sender)
    
    # Extract email and domain from sender
    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender)
    email_address = email_match.group(0) if email_match else sender
    domain = email_address.split('@')[-1] if '@' in email_address else "unknown"
    
    # Check if sender is from trusted domain
    is_trusted_domain = domain.lower() in TRUSTED_DOMAINS
    if is_trusted_domain:
        score -= 30  # Significantly reduce risk for trusted domains
        issues.append(f"✓ Trusted domain: {domain}")
    
    # Extract name from sender
    name_match = re.match(r'^([^<]+)', sender)
    claimable_name = name_match.group(1).strip() if name_match else "Unknown Sender"
    
    # Check if it's a free email provider
    free_email_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", 
                           "icloud.com", "protonmail.com", "mail.com", "zoho.com", "yandex.com"]
    is_free_email = any(provider in domain.lower() for provider in free_email_providers)
    
    # Estimate Gmail age using OSINT techniques
    email_age = estimate_gmail_age(email_address)
    
    # Brand issues detection
    brand_issues = []
    spoofed_patterns = {
        "amaz0n": "Amazon", "paypa1": "PayPal", "g00gle": "Google",
        "micros0ft": "Microsoft", "app1e": "Apple", "faceb00k": "Facebook",
        "netfl1x": "Netflix", "paypal": "PayPal (potential spoof)"
    }
    
    for pattern, brand in spoofed_patterns.items():
        if pattern in sender.lower() or pattern in domain.lower():
            score += 40
            flags.append(f"Spoofed sender: {brand}")
            brand_issues.append(f"Impersonating {brand}")
            issues.append(f"⚠️ Brand impersonation detected: {brand}")

    # Smart job email detection
    text_content = f"{subject} {content}".lower()
    job_keywords = ['job', 'hr', 'recruitment', 'interview', 'career', 'position', 'vacancy']
    has_job_content = any(keyword in text_content for keyword in job_keywords)
    
    if has_job_content:
        # Check for fake job scam indicators
        scam_count = sum(1 for indicator in FAKE_JOB_SCAM_INDICATORS if indicator in text_content)
        
        if scam_count >= 2:
            # High confidence fake job scam
            score += 50
            flags.append(f"Fake job scam detected ({scam_count} indicators)")
            issues.append(f"🚨 Fake job scam: {scam_count} scam indicators found")
        elif is_trusted_domain:
            # Legitimate job alert from trusted source
            score -= 15
            issues.append("✓ Legitimate job alert from trusted source")
        elif scam_count == 1:
            # Moderate suspicion
            score += 15
            issues.append("⚠️ Job email with suspicious element")
        else:
            # Generic job email, low additional risk
            score += 5
    
    # Extended risky keywords (check body and subject) - excluding job-related if trusted
    risky_words = ["urgent", "verify", "suspended", "login", "password", "confirm", "account", "click here", 
                   "act now", "limited time", "expires", "update payment", "bank account", "social security",
                   "tax refund", "win", "prize", "lottery", "congratulations"]
    content_lower = content.lower()
    subject_lower = subject.lower()
    
    risky_keyword_count = 0
    for word in risky_words:
        if word in content_lower or word in subject_lower:
            score += 10
            risky_keyword_count += 1
            flags.append(f"Risky keyword: {word}")
    
    if risky_keyword_count > 3:
        issues.append(f"⚠️ Multiple suspicious keywords detected ({risky_keyword_count})")

    # Check for suspicious TLDs
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".club", ".info"]
    for tld in suspicious_tlds:
        if tld in domain.lower():
            score += 20
            flags.append(f"Suspicious domain: {tld}")
            issues.append(f"⚠️ Suspicious domain extension: {tld}")
            break
    
    # Check for suspicious URLs in body
    url_pattern = r'https?://[^\s<>"\']+'
    urls = re.findall(url_pattern, content)
    if len(urls) > 5:
        score += 15
        flags.append(f"Multiple URLs found: {len(urls)}")
        issues.append(f"⚠️ Excessive URLs detected: {len(urls)}")
    
    # Check for URL shorteners
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "ow.ly", "t.co", "short.link"]
    for shortener in shorteners:
        if shortener in content_lower:
            score += 15
            flags.append(f"URL shortener detected: {shortener}")
            issues.append(f"⚠️ URL shortener found: {shortener}")
            break
    
    # Check for urgency phrases
    urgency_phrases = ["act now", "immediate action", "within 24 hours", "expires today", "last chance"]
    for phrase in urgency_phrases:
        if phrase in content_lower:
            score += 12
            flags.append(f"Urgency tactic: {phrase}")
            issues.append(f"⚠️ Urgency tactic: '{phrase}'")
    
    # Check for personal info requests
    personal_info = ["ssn", "social security", "credit card", "bank account", "routing number", "cvv", "pin code"]
    for info in personal_info:
        if info in content_lower:
            score += 25
            flags.append(f"Requests sensitive info: {info}")
            issues.append(f"🚨 Requesting sensitive information: {info}")
            break
    
    # Check for free email from corporate sender
    if is_free_email and ("company" in claimable_name.lower() or "corporation" in claimable_name.lower() or "bank" in claimable_name.lower()):
        score += 20
        issues.append("⚠️ Corporate entity using free email service")
    
    # Gmail Age-based Risk Assessment (OSINT Intelligence)
    if email_age == "Likely New Gmail Account" and is_free_email:
        score += 10
        issues.append("⚠️ Newly created Gmail account - higher risk profile")
    elif email_age == "Likely Old Gmail Account":
        score -= 5  # Reduce risk for established accounts
        if score < 0:
            score = 0
    
    # Clamp rule-based score before combining with ML
    rule_based_score = _clamp(score)
    
    # Hybrid ML + Rule-based scoring
    if ml_result['ml_available']:
        # Combine: 60% ML score + 40% Rule-based score
        ml_risk_score = _clamp(ml_result['risk_score'])
        hybrid_score = int((ml_risk_score * 0.6) + (rule_based_score * 0.4))
        final_score = _clamp(hybrid_score)
        
        detection_method = "Hybrid (ML + Rules)"
        ml_confidence = ml_result['confidence']
        ml_prediction = ml_result['prediction']
    else:
        # Fallback to rule-based only
        ml_risk_score = 0
        final_score = rule_based_score
        detection_method = "Rule-Based Only"
        ml_confidence = 0.0
        ml_prediction = "N/A"

    # Calculate reputation score (inverse of clamped final score)
    reputation_score = _clamp(100 - final_score)

    # Determine risk level based on final score
    if final_score >= 70:
        verdict = "● HIGH RISK"
        verdict_label = "HIGH RISK"
    elif final_score >= 40:
        verdict = "● SUSPICIOUS"
        verdict_label = "SUSPICIOUS"
    else:
        verdict = "● SAFE"
        verdict_label = "SAFE"

    return {
        "score": final_score,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "flags": flags,
        # Additional detailed information
        "email": email_address,
        "domain": domain,
        "claimable_name": claimable_name,
        "is_free_email": is_free_email,
        "email_age": email_age,
        "brand_issues": brand_issues,
        "reputation_score": reputation_score,
        "issues": issues if issues else ["No issues detected"],
        # ML integration fields
        "ml_prediction": ml_prediction,
        "ml_confidence": ml_confidence,
        "detection_method": detection_method,
        "rule_based_score": rule_based_score,
        "ml_score": ml_risk_score
    }

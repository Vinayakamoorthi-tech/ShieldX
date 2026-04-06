import re
import requests
from email.utils import parseaddr

# Optional: for breach checking using HaveIBeenPwned API (replace YOUR_API_KEY)
HIBP_API_KEY = "YOUR_API_KEY"
HIBP_API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"

FREE_EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]

def is_free_email(email):
    domain = email.split("@")[-1].lower()
    return domain in FREE_EMAIL_DOMAINS

def has_gravatar(email):
    """
    Check if email has a gravatar profile.
    """
    import hashlib
    h = hashlib.md5(email.lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/{h}.json"
    try:
        r = requests.get(url, timeout=3)
        return r.status_code == 200
    except:
        return False

def username_age_score(email):
    """
    Estimate age from username patterns.
    Example: john1995 → likely old email
    """
    local_part = email.split("@")[0]
    # look for year patterns like 1990–2010
    match = re.search(r"(19\d{2}|20[01]\d)", local_part)
    return 2 if match else 0

def breach_score(email):
    """
    Optional: Check if email appeared in data breaches.
    Requires HIBP API Key.
    """
    if HIBP_API_KEY == "YOUR_API_KEY":
        return 0  # Skip if no API key configured
    
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "EmailOSINT"
    }
    try:
        r = requests.get(HIBP_API_URL.format(email), headers=headers, timeout=3)
        if r.status_code == 200:
            return 2  # appeared in breach → likely old
        else:
            return 0
    except:
        return 0

def estimate_gmail_age(email):
    """
    Returns a label: "Likely Old Gmail Account", "Medium Age Gmail Account", "Likely New Gmail Account", or "Not Gmail"
    """
    if not email or "@" not in email:
        return "Unknown"
    
    domain = email.split("@")[-1].lower()
    if domain != "gmail.com":
        return "Not Gmail"

    score = 0
    # Free email already known (gmail.com)
    score += 0

    # Gravatar
    if has_gravatar(email):
        score += 2

    # Username pattern
    score += username_age_score(email)

    # Breach history
    score += breach_score(email)

    # Define heuristic
    if score >= 3:
        return "Likely Old Gmail Account"
    elif score == 2:
        return "Medium Age Gmail Account"
    else:
        return "Likely New Gmail Account"

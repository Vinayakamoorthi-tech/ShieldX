"""Sender profile builder (privacy-first, OSINT-lite).

Functions:
- parse_sender(sender) -> {'claimed_name', 'email'}
- build_sender_profile(sender)

Returns structured dict with: claimed_name, email, domain, reputation_score, risk_level, issues

Notes:
- Uses safe, best-effort DNS/WHOIS lookups; failures handled gracefully.
- Designed to be testable: pure functions where possible and minimal side effects.
"""
from email.utils import parseaddr
import re
import time
from datetime import datetime
from difflib import SequenceMatcher

try:
    import dns.resolver
    DNS_AVAILABLE = True
except Exception:
    DNS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

from .patterns import FREE_EMAIL_DOMAINS, BRAND_KEYWORDS

SENDER_SUSPICIOUS_KEYWORDS = [
    'verify', 'security', 'support', 'billing', 'alert', 'urgent', 'hr', 'recruit', 'salary', 'payment', 'offer'
]


def _normalize_domain(domain: str):
    if not domain:
        return None
    domain = domain.strip().lower()
    domain = re.sub(r"^www\.", "", domain)
    return domain


def parse_sender(sender: str):
    """Safely parse claimed name and email from common sender header formats.

    Examples handled:
    - "Security <accounts-security@amazon-support-info.com>"
    - "Security Team (accounts-security@amazon-support-info.com)"
    - "accounts-security@amazon-support-info.com"
    """
    if not sender:
        return {'claimed_name': None, 'email': None}

    # find first email-like token
    m = re.search(r'([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})', sender)
    email = m.group(1).lower() if m else None

    claimed = None
    # prefer the part before angle bracket
    if '<' in sender and '>' in sender:
        claimed = sender.split('<', 1)[0].strip().strip('"')
    elif '(' in sender and ')' in sender:
        claimed = sender.split('(', 1)[0].strip().strip('"')
    else:
        name, _ = parseaddr(sender)
        if name:
            claimed = name.strip()
        else:
            if email:
                # take text before email if present
                before = sender.split(email)[0].strip()
                claimed = before.strip(' "<>()') or None
            else:
                claimed = None

    claimed = claimed or None
    return {'claimed_name': claimed, 'email': email}


def _detect_lookalike(domain: str):
    """Simple heuristics: hyphens, digits, and uncommon char substitutions."""
    if not domain:
        return False
    if '-' in domain:
        return True
    if re.search(r"\d", domain):
        return True
    # repeated characters or many punctuation
    if re.search(r"[^a-z0-9.-]", domain):
        return True
    return False


def _detect_brand_impersonation(domain: str):
    if not domain:
        return None
    name_part = domain.split('.')[0]
    issues = []
    for brand in BRAND_KEYWORDS:
        b = brand.lower()
        # exact substring (e.g., amaz0n -> amazon helps via obfuscation check later)
        if b in name_part and b != name_part:
            issues.append(f"contains brand keyword '{b}'")
            continue
        # fuzzy ratio check
        ratio = SequenceMatcher(None, name_part, b).ratio()
        if ratio > 0.78:
            issues.append(f"similar to brand '{b}' (ratio={ratio:.2f})")
            continue
        # common obfuscation substitutions
        trans = name_part.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's')
        if b in trans and b != trans:
            issues.append(f"contains obfuscated brand '{b}'")
    return issues if issues else None


def _check_mx(domain: str):
    if not domain:
        return None
    if not DNS_AVAILABLE:
        return None
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5.0)
        return len(answers) > 0
    except Exception:
        return False


def _check_spf(domain: str):
    if not domain:
        return None
    if not DNS_AVAILABLE:
        return None
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=5.0)
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.lower().startswith('v=spf1'):
                return True
        return False
    except Exception:
        return False


def _get_domain_age_days(domain: str):
    if not domain:
        return None
    if not WHOIS_AVAILABLE:
        return None
    try:
        w = whois.whois(domain)
        # some whois implementations return a list
        created = w.creation_date
        if not created:
            return None
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, str):
            try:
                created = datetime.fromisoformat(created)
            except Exception:
                return None
        if isinstance(created, datetime):
            delta = datetime.utcnow() - created
            return delta.days
        return None
    except Exception:
        return None


def build_sender_profile(sender: str):
    """Build a privacy-first sender profile dict.

    sender: raw header value or just an email address
    """
    parsed = parse_sender(sender or '')
    name = parsed.get('claimed_name')
    email = parsed.get('email') or ''

    local_part = ''
    domain = None
    if email and '@' in email:
        local_part, domain = email.split('@', 1)
        domain = _normalize_domain(domain)

    profile = {
        'claimed_name': name or None,
        'email': email or None,
        'domain': domain,
        'reputation_score': 100,
        'risk_level': 'Low',
        'issues': []
    }

    # checks and specific issues
    if domain and domain in FREE_EMAIL_DOMAINS:
        profile['issues'].append('free email domain')
        profile['reputation_score'] -= 30

    if domain and _detect_lookalike(domain):
        profile['issues'].append('look-alike domain (hyphens/digits)')
        profile['reputation_score'] -= 20

    brand_issues = _detect_brand_impersonation(domain) if domain else None
    if brand_issues:
        for it in brand_issues:
            profile['issues'].append(f"brand impersonation: {it}")
        profile['reputation_score'] -= 35

    # suspicious sender name keywords
    if name:
        low = name.lower()
        for kw in SENDER_SUSPICIOUS_KEYWORDS:
            if kw in low:
                profile['issues'].append(f"suspicious sender name: '{kw}'")
                profile['reputation_score'] -= 15
                break

    # MX and SPF checks (best-effort)
    try:
        mx = _check_mx(domain)
    except Exception:
        mx = None
    try:
        spf = _check_spf(domain)
    except Exception:
        spf = None

    if spf is False:
        profile['issues'].append('missing SPF')
        profile['reputation_score'] -= 10

    if mx is False:
        profile['issues'].append('missing MX')
        profile['reputation_score'] -= 40

    domain_age = None
    try:
        domain_age = _get_domain_age_days(domain)
    except Exception:
        domain_age = None

    if domain_age is not None and domain_age < 30:
        profile['issues'].append('newly registered domain')
        profile['reputation_score'] -= 20

    # clamp and compute risk_level
    profile['reputation_score'] = max(0, min(100, profile['reputation_score']))

    if profile['reputation_score'] >= 70:
        profile['risk_level'] = 'Low'
    elif profile['reputation_score'] >= 40:
        profile['risk_level'] = 'Medium'
    else:
        profile['risk_level'] = 'High'

    # add some extra metadata (non-required but useful for debugging/tests)
    profile['mx_present'] = mx
    profile['spf_present'] = spf
    profile['domain_age_days'] = domain_age
    # Merge passive OSINT findings (simulated/deterministic) to enrich and cross-check
    try:
        from .osint_checks import collect_sender_osint
        osint = collect_sender_osint(email or '')
    except Exception:
        osint = None

    if osint:
        # merge specific fields
        # prefer explicit OSINT flags for some checks
        if osint.get('is_free_email') and 'free email domain' not in profile['issues']:
            profile['issues'].append('free email domain')
        if osint.get('lookalike_domain') and 'look-alike domain (hyphens/digits)' not in profile['issues']:
            profile['issues'].append('look-alike domain (hyphens/digits)')
        # brand issues
        for bi in osint.get('brand_issues', []):
            label = f"brand impersonation: {bi}"
            if label not in profile['issues']:
                profile['issues'].append(label)
        # SPF/DKIM
        if profile.get('spf_present') is None:
            profile['spf_present'] = osint.get('spf_present')
            if profile['spf_present'] is False and 'missing SPF' not in profile['issues']:
                profile['issues'].append('missing SPF')
        if osint.get('dkim_present') is not None:
            profile['dkim_present'] = osint.get('dkim_present')
            if profile['dkim_present'] is False and 'missing DKIM' not in profile['issues']:
                profile['issues'].append('missing DKIM')
        # domain age
        if profile.get('domain_age_days') is None and osint.get('domain_age_days') is not None:
            profile['domain_age_days'] = osint.get('domain_age_days')
            if profile['domain_age_days'] < 30 and 'newly registered domain' not in profile['issues']:
                profile['issues'].append('newly registered domain')
        # merge issues from osint
        for issue in osint.get('issues', []):
            if issue not in profile['issues']:
                profile['issues'].append(issue)

        # conservative reputation: take the lower score between current and OSINT score
        oscore = osint.get('reputation_score')
        if isinstance(oscore, int):
            profile['reputation_score'] = max(0, min(100, min(profile['reputation_score'], oscore)))

        # recompute risk_level
        rs = profile['reputation_score']
        if rs >= 70:
            profile['risk_level'] = 'Low'
        elif rs >= 40:
            profile['risk_level'] = 'Medium'
        else:
            profile['risk_level'] = 'High'
    return profile

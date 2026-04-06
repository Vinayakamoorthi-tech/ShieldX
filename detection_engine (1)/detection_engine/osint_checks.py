"""Passive OSINT-style sender identity checks (simulated-friendly for MVP).

Provides:
- collect_sender_osint(sender_email: str) -> dict

No external paid APIs; uses DNS/WHOIS when available and simulates otherwise.
"""
import re
from datetime import datetime

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


def _extract_domain(email: str):
    if not email or '@' not in email:
        return None
    return email.split('@', 1)[1].lower().strip()


def _simulate_domain_age(domain: str):
    # deterministic simulation so tests are stable: use sum of char codes
    if not domain:
        return None
    s = sum(ord(c) for c in domain)
    # give a range 1..600 days
    age = (s % 600) + 1
    return age


def _get_domain_age_days(domain: str):
    if not domain:
        return None
    if WHOIS_AVAILABLE:
        try:
            w = whois.whois(domain)
            created = w.creation_date
            if not created:
                return _simulate_domain_age(domain)
            if isinstance(created, list):
                created = created[0]
            if isinstance(created, str):
                try:
                    created = datetime.fromisoformat(created)
                except Exception:
                    return _simulate_domain_age(domain)
            if isinstance(created, datetime):
                return (datetime.utcnow() - created).days
            return _simulate_domain_age(domain)
        except Exception:
            return _simulate_domain_age(domain)
    else:
        return _simulate_domain_age(domain)


def _check_spf(domain: str):
    if not domain:
        return False
    if DNS_AVAILABLE:
        try:
            answers = dns.resolver.resolve(domain, 'TXT', lifetime=5.0)
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.lower().startswith('v=spf1'):
                    return True
            return False
        except Exception:
            return False
    # simulated: assume popular domains tend to have SPF unless free-provider
    return False if domain in FREE_EMAIL_DOMAINS else True


def _check_dkim(domain: str):
    # DKIM presence is harder to check without knowing selector; simulate deterministically
    if not domain:
        return False
    # if domain is known free email provider, DKIM likely present for provider but not for custom lookalike
    if domain in FREE_EMAIL_DOMAINS:
        return True
    # simulate: domains containing brand keywords likely have DKIM
    for b in BRAND_KEYWORDS:
        if b in domain.lower():
            return True
    # deterministic fallback based on domain chars
    s = sum(ord(c) for c in domain)
    return (s % 2) == 0


def _detect_lookalike(domain: str):
    if not domain:
        return False
    if '-' in domain or re.search(r"\d", domain):
        return True
    if re.search(r"[^a-z0-9.-]", domain):
        return True
    return False


def _detect_brand_impersonation(domain: str):
    if not domain:
        return []
    name_part = domain.split('.')[0]
    issues = []
    for brand in BRAND_KEYWORDS:
        b = brand.lower()
        if b in name_part and b != name_part:
            issues.append(f"contains brand keyword '{b}'")
        # obfuscated check
        trans = name_part.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's')
        if b in trans and b != trans:
            issues.append(f"contains obfuscated brand '{b}'")
    return issues


def collect_sender_osint(sender_email: str) -> dict:
    """Collect passive OSINT about sender email and domain.

    Returns a dict with keys required by the integration step.
    """
    result = {
        "claimed_name": None,
        "email": sender_email or None,
        "domain": None,
        "is_free_email": False,
        "lookalike_domain": False,
        "brand_issues": [],
        "domain_age_days": None,
        "spf_present": None,
        "dkim_present": None,
        "reputation_score": 100,
        "risk_level": 'Low',
        "issues": []
    }

    if not sender_email or '@' not in sender_email:
        return result

    domain = _extract_domain(sender_email)
    result['domain'] = domain

    result['is_free_email'] = domain in FREE_EMAIL_DOMAINS
    if result['is_free_email']:
        result['issues'].append('free email domain')

    result['lookalike_domain'] = _detect_lookalike(domain)
    if result['lookalike_domain']:
        result['issues'].append('look-alike domain (hyphens/digits)')

    brand_issues = _detect_brand_impersonation(domain)
    if brand_issues:
        result['brand_issues'] = brand_issues
        result['issues'].append('brand impersonation: ' + '; '.join(brand_issues))

    age = _get_domain_age_days(domain)
    result['domain_age_days'] = age
    if age is not None:
        if age < 30:
            result['issues'].append('domain registered recently')
        elif age < 180:
            result['issues'].append('domain age: medium (30-180 days)')

    spf = _check_spf(domain)
    result['spf_present'] = spf
    if spf is False:
        result['issues'].append('missing SPF')

    dkim = _check_dkim(domain)
    result['dkim_present'] = dkim
    if dkim is False:
        result['issues'].append('missing DKIM')

    # reputation scoring
    score = 100
    if result['is_free_email']:
        score -= 30
    if result['lookalike_domain']:
        score -= 20
    if result['brand_issues']:
        score -= 40
    if age is not None:
        if age < 30:
            score -= 30
        elif age < 180:
            score -= 10
    if spf is False:
        score -= 15
    if dkim is False:
        score -= 10

    score = max(0, min(100, score))
    result['reputation_score'] = score
    if score >= 70:
        result['risk_level'] = 'Low'
    elif score >= 40:
        result['risk_level'] = 'Medium'
    else:
        result['risk_level'] = 'High'

    return result

from .preprocess import normalize
from .scorer import keyword_score
from .classifier import classify
from .patterns import (
    SPAM_KEYWORDS,
    PHISHING_KEYWORDS,
    PHISHING_HELPERS,
    URGENCY_KEYWORDS,
    JOB_CONTEXT_KEYWORDS,
    FAKE_JOB_KEYWORDS,
    FREE_EMAIL_DOMAINS
)


#scanning email for phishing, spam, and job scam indicators

def scan_email(subject, body, sender_email=""):
    text = normalize(subject + " " + body)

    result = {
        "phishing": {"score": 0, "hits": []},
        "spam": {"score": 0, "hits": []},
        "job_scam": {"score": 0, "hits": []}
    }

    # 🔴 PHISHING
    ps, ph = keyword_score(text, PHISHING_KEYWORDS, 3)
    uh, uh_hits = keyword_score(text, URGENCY_KEYWORDS, 2)
    phs, phs_hits = keyword_score(text, PHISHING_HELPERS, 2)

    result["phishing"]["score"] = ps + uh + phs
    result["phishing"]["hits"] = ph + uh_hits + phs_hits

    # 🟡 SPAM
    ss, sh = keyword_score(text, SPAM_KEYWORDS, 1)
    result["spam"]["score"] = ss
    result["spam"]["hits"] = sh

    # 🚨 FAKE JOB SCAM
    jc, jc_hits = keyword_score(text, JOB_CONTEXT_KEYWORDS, 2)
    js, js_hits = keyword_score(text, FAKE_JOB_KEYWORDS, 4)

    result["job_scam"]["score"] = jc + js
    result["job_scam"]["hits"] = jc_hits + js_hits

    # 🚨 Free email domain boost (job scam)
    if sender_email:
        domain = sender_email.split("@")[-1]
        if domain in FREE_EMAIL_DOMAINS:
            result["job_scam"]["score"] += 3
            result["job_scam"]["hits"].append("free email domain")

    return result



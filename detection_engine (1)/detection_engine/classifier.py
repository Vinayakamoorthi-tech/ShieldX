#classifying email based on scores
def classify(result):
    if result["job_scam"]["score"] >= 8:
        return "Fake Job Scam", result["job_scam"]

    if result["phishing"]["score"] >= 6:
        return "Phishing", result["phishing"]

    if result["spam"]["score"] >= 3:
        return "Spam", result["spam"]

    return "Safe", {}
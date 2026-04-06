#checking for presence of keywords and calculating scores
def keyword_score(text, keywords, weight):
    score = 0
    hits = []

    for kw in keywords:
        if kw in text:
            score += weight
            hits.append(kw)

    return score, hits
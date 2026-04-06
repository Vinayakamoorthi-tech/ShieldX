import re

def normalize(text):
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r'http\S+', ' URL ', text)   # replace links
    text = re.sub(r'\s+', ' ', text)
    return text

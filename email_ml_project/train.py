import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, classification_report
import joblib

dfs = []

# Load multi csv dataset3
csv_folder = "Data/multi csv/dataset3/"
for file in os.listdir(csv_folder):
    if file.endswith(".csv"):
        df = pd.read_csv(os.path.join(csv_folder, file))
        # Combine subject and body as text content, handle missing columns
        subject = df.get("subject", pd.Series([""] * len(df))).fillna("")
        body = df.get("body", pd.Series([""] * len(df))).fillna("")
        df["text"] = subject + " " + body
        df = df[["text", "label"]]
        dfs.append(df)
        print(f"✓ Loaded {file}: {len(df)} records")

# Load single csv dataset2 (URL-based phishing data)
try:
    df_single = pd.read_csv("Data/single csv/AI_MODEL/dataset2.csv")
    # Use Domain and Title for text representation
    domain = df_single.get("Domain", pd.Series([""] * len(df_single))).fillna("")
    title = df_single.get("Title", pd.Series([""] * len(df_single))).fillna("")
    df_single["text"] = domain + " " + title
    df_single = df_single[["text", "label"]]
    dfs.append(df_single)
    print(f"✓ Loaded dataset2.csv: {len(df_single)} records")
except Exception as e:
    print(f"⚠ Could not load dataset2.csv: {e}")

# Load text data
try:
    text_folder = "Data/text data/"
    texts, labels = [], []
    for label_dir in os.listdir(text_folder):
        label_path = os.path.join(text_folder, label_dir)
        if os.path.isdir(label_path):
            for file in os.listdir(label_path):
                with open(
                    os.path.join(label_path, file),
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as f:
                    texts.append(f.read())
                    labels.append(int(label_dir) if label_dir.isdigit() else label_dir)
    
    if texts:
        df_text = pd.DataFrame({"text": texts, "label": labels})
        dfs.append(df_text)
        print(f"✓ Loaded text data: {len(df_text)} records")
except Exception as e:
    print(f"⚠ Could not load text data: {e}")

# Combine all datasets
data = pd.concat(dfs, ignore_index=True)
print(f"\n📊 Total records: {len(data)}")
print(f"Labels distribution:\n{data['label'].value_counts()}\n")

data = data.sample(frac=1, random_state=42).reset_index(drop=True)


train, test = train_test_split(
    data,
    test_size=0.2,
    stratify=data["label"],
    random_state=42
)


vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=5000
)

X_train = vectorizer.fit_transform(train["text"])
X_test  = vectorizer.transform(test["text"])

model = MultinomialNB()
model.fit(X_train, train["label"])



pred = model.predict(X_test)

print("Accuracy:", accuracy_score(test["label"], pred))
print(classification_report(test["label"], pred))


os.makedirs("Model", exist_ok=True)

joblib.dump(model, "Model/model.pkl")
joblib.dump(vectorizer, "Model/vectorizer.pkl")

print("✅ Model saved successfully")

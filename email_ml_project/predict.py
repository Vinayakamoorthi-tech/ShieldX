import joblib

model = joblib.load("Model/model.pkl")
vectorizer = joblib.load("Model/vectorizer.pkl")

text = input("Enter email text: ")
vec = vectorizer.transform([text])
print("Prediction:", model.predict(vec)[0])

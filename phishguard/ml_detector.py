import joblib
import os

class MLPhishingDetector:
    def __init__(self):
        """Load trained ML model and vectorizer"""
        # Path to ML model folder
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        model_path = os.path.join(base_dir, 'email_ml_project', 'Model')
        
        try:
            self.model = joblib.load(os.path.join(model_path, 'model.pkl'))
            self.vectorizer = joblib.load(os.path.join(model_path, 'vectorizer.pkl'))
            self.available = True
            print("✅ ML Model loaded successfully")
        except Exception as e:
            print(f"⚠️ ML Model not found: {e}")
            self.model = None
            self.vectorizer = None
            self.available = False
    
    def predict_email(self, subject, body, sender):
        """
        Predict if email is phishing using ML model
        Returns: dict with prediction, confidence, risk_score
        """
        if not self.available:
            return {
                'prediction': 'Unknown',
                'confidence': 0.0,
                'risk_score': 50,
                'ml_available': False
            }
        
        try:
            # Combine email features (subject + body + sender)
            email_text = f"{subject} {body} {sender}"
            
            # Vectorize using TF-IDF
            features = self.vectorizer.transform([email_text])
            
            # Predict
            prediction = self.model.predict(features)[0]
            
            # Get probability scores
            try:
                probabilities = self.model.predict_proba(features)[0]
                # Assuming class 1 is phishing, class 0 is safe
                if len(probabilities) > 1:
                    phishing_confidence = float(probabilities[1])
                    safe_confidence = float(probabilities[0])
                else:
                    phishing_confidence = float(probabilities[0]) if prediction == 1 else 0.0
                    safe_confidence = 1.0 - phishing_confidence
            except:
                # If predict_proba not available, use binary prediction
                phishing_confidence = 1.0 if prediction == 1 else 0.0
                safe_confidence = 1.0 - phishing_confidence
            
            return {
                'prediction': 'Phishing' if prediction == 1 else 'Safe',
                'confidence': phishing_confidence,
                'risk_score': int(phishing_confidence * 100),
                'ml_available': True,
                'probabilities': {
                    'safe': safe_confidence,
                    'phishing': phishing_confidence
                }
            }
        
        except Exception as e:
            print(f"❌ ML Prediction error: {e}")
            return {
                'prediction': 'Error',
                'confidence': 0.0,
                'risk_score': 50,
                'ml_available': False
            }

# Global instance
ml_detector = MLPhishingDetector()

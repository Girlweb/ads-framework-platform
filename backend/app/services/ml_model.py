import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import pickle
import os

class AlertMLModel:

    def __init__(self):
        self.model = None
        self.model_path = "app/models/alert_classifier.pkl"
        self.is_trained = False
        self._train_with_synthetic_data()

    def _generate_training_data(self):
        # Synthetic training data based on real SOC knowledge
        training_samples = [
            # [severity, has_technique, keyword_risk, vt_score, hours_old] -> priority(0=low,1=med,2=high,3=critical)
            [1.0, 1.0, 1.0, 0.8, 0.1, 3],  # ransomware critical
            [1.0, 1.0, 0.9, 0.7, 0.2, 3],  # lateral movement critical
            [1.0, 0.8, 0.8, 0.6, 0.5, 3],  # critical severity high technique
            [0.75, 0.8, 0.85, 0.7, 1.0, 2], # C2 beacon high
            [0.75, 0.75, 0.6, 0.45, 2.0, 2], # powershell high
            [0.75, 0.7, 0.65, 0.3, 3.0, 2],  # phishing high severity
            [0.5, 0.5, 0.5, 0.2, 4.0, 1],   # brute force medium
            [0.5, 0.4, 0.3, 0.1, 8.0, 1],   # medium severity low technique
            [0.25, 0.2, 0.2, 0.0, 12.0, 0], # low severity informational
            [0.25, 0.1, 0.1, 0.0, 24.0, 0], # very low priority
            [1.0, 1.0, 1.0, 0.9, 0.05, 3],  # critical ransomware fresh
            [0.75, 0.9, 0.9, 0.8, 0.3, 3],  # high severity fresh C2
            [1.0, 0.5, 0.4, 0.1, 6.0, 2],   # critical severity older
            [0.5, 0.6, 0.7, 0.4, 2.0, 1],   # medium with some technique
            [0.75, 0.3, 0.3, 0.0, 10.0, 1], # high severity old low technique
            [0.25, 0.5, 0.6, 0.3, 5.0, 1],  # low severity but has technique
            [1.0, 0.8, 0.85, 0.65, 0.8, 3], # critical exfiltration
            [0.75, 0.7, 0.8, 0.5, 1.5, 2],  # high credential theft
            [0.5, 0.3, 0.3, 0.1, 15.0, 0],  # medium old informational
            [1.0, 0.9, 0.9, 0.75, 0.4, 3],  # critical lateral movement fresh
        ]
        X = np.array([s[:5] for s in training_samples])
        y = np.array([s[5] for s in training_samples])
        return X, y

    def _train_with_synthetic_data(self):
        X, y = self._generate_training_data()
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=5,
            random_state=42
        )
        self.model.fit(X, y)
        self.is_trained = True
        os.makedirs("app/models", exist_ok=True)
        with open(self.model_path, "wb") as f:
            pickle.dump(self.model, f)

    def predict_priority(self, features: dict) -> dict:
        if not self.is_trained:
            return {"priority_class": 1, "confidence": 0.5}
        severity_map = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
        feature_vector = np.array([[
            severity_map.get(features.get("severity", "low"), 0.25),
            features.get("technique_score", 0.0),
            features.get("keyword_score", 0.0),
            features.get("threat_intel_score", 0.0),
            features.get("hours_old", 1.0)
        ]])
        priority_class = self.model.predict(feature_vector)[0]
        probabilities = self.model.predict_proba(feature_vector)[0]
        confidence = float(max(probabilities))
        priority_labels = {
            0: "P5 - INFORMATIONAL",
            1: "P4 - LOW",
            2: "P3 - MEDIUM",
            3: "P2 - HIGH",
            4: "P1 - CRITICAL"
        }
        return {
            "priority_class": int(priority_class),
            "priority_label": priority_labels.get(int(priority_class), "P3 - MEDIUM"),
            "confidence": round(confidence * 100, 1),
            "probabilities": {
                "informational": round(float(probabilities[0]) * 100, 1) if len(probabilities) > 0 else 0,
                "low": round(float(probabilities[1]) * 100, 1) if len(probabilities) > 1 else 0,
                "medium": round(float(probabilities[2]) * 100, 1) if len(probabilities) > 2 else 0,
                "critical": round(float(probabilities[3]) * 100, 1) if len(probabilities) > 3 else 0,
            }
        }

alert_ml_model = AlertMLModel()

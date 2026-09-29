import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

MODEL_FILE = 'risk_model.pkl'

def generate_synthetic_data(samples=600):
    """
    Generate synthetic training data representing login patterns:
    Features: [login_hour, failed_attempts, login_frequency, ip_changed, time_gap]
    Labels: 0 = Normal, 1 = Suspicious, 2 = High Risk
    """
    np.random.seed(42)
    X = []
    y = []

    for _ in range(samples):
        login_hour = np.random.randint(0, 24)
        failed_attempts = np.random.choice([0, 1, 2, 3, 4, 5], p=[0.5, 0.2, 0.15, 0.08, 0.04, 0.03])
        login_freq = np.random.randint(1, 15)
        ip_changed = np.random.choice([0, 1], p=[0.8, 0.2])
        time_gap = np.random.randint(1, 300)

        # Rule-backed label generation for training
        if failed_attempts >= 3 or (time_gap < 5 and failed_attempts >= 2) or login_freq > 10:
            label = 2  # High Risk (e.g. brute-force pattern)
        elif failed_attempts >= 1 or ip_changed == 1 or login_hour < 5 or login_hour > 23:
            label = 1  # Suspicious
        else:
            label = 0  # Normal

        X.append([login_hour, failed_attempts, login_freq, ip_changed, time_gap])
        y.append(label)

    return np.array(X), np.array(y)

def train_and_save_model():
    """Train RandomForestClassifier on synthetic features and save to risk_model.pkl."""
    X, y = generate_synthetic_data()
    model = RandomForestClassifier(n_estimators=50, max_depth=6, random_state=42)
    model.fit(X, y)
    joblib.dump(model, MODEL_FILE)
    return model

def load_or_train_model():
    """Load pre-trained model from disk, or train a new one if missing."""
    if os.path.exists(MODEL_FILE):
        try:
            return joblib.load(MODEL_FILE)
        except Exception:
            return train_and_save_model()
    else:
        return train_and_save_model()

# Global model instance
_model = load_or_train_model()

def predict_risk_level(features):
    """
    Predict risk level given features: [login_hour, failed_attempts, login_frequency, ip_changed, time_gap]
    
    Returns string: 'Normal', 'Suspicious', or 'High Risk'
    """
    global _model
    if _model is None:
        _model = load_or_train_model()

    # Model prediction
    prediction = _model.predict([features])[0]
    
    # Direct safety override for extreme brute-force pattern
    failed_attempts = features[1]
    time_gap = features[4]
    if failed_attempts >= 3 or (time_gap < 5 and failed_attempts >= 2):
        return 'High Risk'

    risk_map = {
        0: 'Normal',
        1: 'Suspicious',
        2: 'High Risk'
    }
    return risk_map.get(prediction, 'Normal')

import joblib
from .feature_extractor import extract_features

model = joblib.load("/home/quor/Desktop/firewall/DEFENDER/venv/models/model.pkl")

def scan_file(file_path):

    features = extract_features(file_path)

    if features is None:
        return "Could not analyze file"

    pred = model.predict(features)[0]

    if pred == 0:
        return "⚠ Malware Detected"
    else:
        return "✓ Benign File"
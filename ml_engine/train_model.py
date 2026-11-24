import os
import json
from datetime import datetime
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from ml_engine.feature_extractor import FeatureExtractor

PRIORITY_CLASSES = ['Low', 'Medium', 'High', 'Critical']
PRIORITY_TO_LABEL = {name: i for i, name in enumerate(PRIORITY_CLASSES)}
LABEL_TO_PRIORITY = {i: name for i, name in enumerate(PRIORITY_CLASSES)}

def generate_synthetic_soc_data(n_samples=5000, random_state=42):
    """
    Generate realistic, high-fidelity synthetic SOC telemetry for training.
    Simulates real-world class distributions and realistic noise.
    """
    np.random.seed(random_state)
    records = []

    for _ in range(n_samples):
        # Sample an attack profile
        profile = np.random.choice(['ransomware_c2', 'brute_force', 'sqli', 'port_scan', 'benign_noise', 'phishing'], 
                                   p=[0.15, 0.25, 0.18, 0.18, 0.14, 0.10])

        if profile == 'ransomware_c2':
            sev = np.random.choice([75.0, 100.0], p=[0.2, 0.8])
            ti = np.random.uniform(75.0, 100.0)
            asset = np.random.choice([75.0, 100.0], p=[0.3, 0.7])
            freq = np.random.uniform(30.0, 95.0)
            vuln = np.random.choice([20.0, 85.0, 95.0], p=[0.2, 0.5, 0.3])
            port_risk = np.random.choice([90.0, 55.0], p=[0.8, 0.2])
            c2_flag = 1.0
            atk_code = 4.0 if np.random.rand() > 0.5 else 3.0

        elif profile == 'brute_force':
            sev = np.random.choice([50.0, 75.0], p=[0.4, 0.6])
            ti = np.random.uniform(50.0, 95.0)
            asset = np.random.choice([50.0, 75.0, 100.0], p=[0.4, 0.4, 0.2])
            freq = np.random.uniform(40.0, 100.0)
            vuln = 20.0
            port_risk = 90.0  # SSH 22 or RDP 3389
            c2_flag = 0.0
            atk_code = 1.0

        elif profile == 'sqli':
            sev = np.random.choice([50.0, 75.0, 100.0], p=[0.3, 0.5, 0.2])
            ti = np.random.uniform(40.0, 90.0)
            asset = np.random.choice([75.0, 100.0], p=[0.6, 0.4])
            freq = np.random.uniform(20.0, 70.0)
            vuln = 85.0
            port_risk = 55.0  # Web port 80/443
            c2_flag = 0.0
            atk_code = 2.0

        elif profile == 'port_scan':
            sev = np.random.choice([25.0, 50.0], p=[0.7, 0.3])
            ti = np.random.uniform(20.0, 70.0)
            asset = np.random.choice([25.0, 50.0, 75.0], p=[0.5, 0.4, 0.1])
            freq = np.random.uniform(60.0, 100.0)
            vuln = 20.0
            port_risk = 40.0
            c2_flag = 0.0
            atk_code = 5.0

        elif profile == 'phishing':
            sev = np.random.choice([50.0, 75.0], p=[0.4, 0.6])
            ti = np.random.uniform(60.0, 95.0)
            asset = np.random.choice([50.0, 75.0], p=[0.6, 0.4])
            freq = np.random.uniform(10.0, 40.0)
            vuln = 20.0
            port_risk = 55.0
            c2_flag = 0.0
            atk_code = 6.0

        else: # benign noise
            sev = np.random.choice([25.0, 50.0], p=[0.8, 0.2])
            ti = np.random.uniform(0.0, 25.0)
            asset = np.random.choice([25.0, 50.0], p=[0.7, 0.3])
            freq = np.random.uniform(5.0, 30.0)
            vuln = 20.0
            port_risk = 30.0
            c2_flag = 0.0
            atk_code = 10.0

        # Calculate ground truth priority based on composite risk
        composite_score = (
            (sev * 0.25) +
            (ti * 0.25) +
            (asset * 0.20) +
            (freq * 0.15) +
            (vuln * 0.15)
        )

        # Add slight stochastic noise for realistic ML boundary learning
        noise = np.random.normal(0, 3.5)
        noisy_score = np.clip(composite_score + noise, 0.0, 100.0)

        if noisy_score >= 80.0:
            target = 3  # Critical
        elif noisy_score >= 60.0:
            target = 2  # High
        elif noisy_score >= 35.0:
            target = 1  # Medium
        else:
            target = 0  # Low

        features = [sev, ti, asset, freq, vuln, port_risk, c2_flag, atk_code]
        records.append((features, target))

    X = np.array([r[0] for r in records], dtype=np.float32)
    y = np.array([r[1] for r in records], dtype=np.int32)
    return X, y

def train_and_save_model(model_save_path=None, metadata_save_path=None):
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if model_save_path is None:
        model_save_path = os.path.join(base_dir, 'models_ml', 'priority_rf_model.joblib')
    if metadata_save_path is None:
        metadata_save_path = os.path.join(base_dir, 'models_ml', 'model_metadata.json')

    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)

    print("Generating synthetic SOC telemetry training data (5,000 samples)...")
    X, y = generate_synthetic_soc_data(5000)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("Training Random Forest Classifier (100 estimators)...")
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    rf_model.fit(X_train, y_train)

    # Train baseline Decision Tree for comparison
    dt_model = DecisionTreeClassifier(max_depth=8, random_state=42)
    dt_model.fit(X_train, y_train)

    y_pred = rf_model.predict(X_test)
    y_pred_dt = dt_model.predict(X_test)

    rf_acc = float(accuracy_score(y_test, y_pred))
    dt_acc = float(accuracy_score(y_test, y_pred_dt))

    rep = classification_report(y_test, y_pred, target_names=PRIORITY_CLASSES, output_dict=True)
    cm = confusion_matrix(y_test, y_pred).tolist()

    feature_importances = {
        name: round(float(imp) * 100, 2)
        for name, imp in zip(FeatureExtractor.FEATURE_NAMES, rf_model.feature_importances_)
    }

    metadata = {
        'trained_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'model_type': 'RandomForestClassifier',
        'n_samples_trained': len(X_train),
        'n_samples_tested': len(X_test),
        'accuracy_rf': round(rf_acc * 100, 2),
        'accuracy_dt_baseline': round(dt_acc * 100, 2),
        'classes': PRIORITY_CLASSES,
        'feature_names': FeatureExtractor.FEATURE_NAMES,
        'feature_importances': feature_importances,
        'confusion_matrix': cm,
        'classification_report': rep
    }

    joblib.dump(rf_model, model_save_path)
    with open(metadata_save_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)

    print(f"Random Forest Model saved to: {model_save_path}")
    print(f"Model Metadata saved to: {metadata_save_path}")
    print(f"Model Test Accuracy: {rf_acc * 100:.2f}% (Baseline Decision Tree: {dt_acc * 100:.2f}%)")
    print("Feature Importances:")
    for feat, imp in sorted(feature_importances.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {feat}: {imp}%")

    return rf_model, metadata

if __name__ == '__main__':
    train_and_save_model()

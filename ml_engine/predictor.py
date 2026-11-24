import os
import json
import joblib
import numpy as np
from ml_engine.feature_extractor import FeatureExtractor

PRIORITY_CLASSES = ['Low', 'Medium', 'High', 'Critical']

class PriorityPredictor:
    def __init__(self, model_path=None, metadata_path=None):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        self.model_path = model_path or os.path.join(base_dir, 'models_ml', 'priority_rf_model.joblib')
        self.metadata_path = metadata_path or os.path.join(base_dir, 'models_ml', 'model_metadata.json')
        self.model = None
        self.metadata = None
        self._load()

    def _load(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception as e:
                print(f"Error loading ML model: {e}")
                self.model = None

        if os.path.exists(self.metadata_path):
            try:
                with open(self.metadata_path, 'r', encoding='utf-8') as f:
                    self.metadata = json.load(f)
            except Exception:
                self.metadata = None

    def reload(self):
        self._load()

    def is_ready(self):
        return self.model is not None

    def predict(self, feature_vector):
        """
        Run inference on feature vector.
        Returns:
            predicted_priority (str): 'Critical', 'High', 'Medium', or 'Low'
            confidence (float): 0.0 to 100.0
            probabilities (dict): probability for each class
            explainability (dict): factor contributions
        """
        if not self.is_ready():
            # Fallback if model is not trained yet
            return 'Medium', 50.0, {'Low': 0.25, 'Medium': 0.5, 'High': 0.15, 'Critical': 0.1}, {}

        features_2d = np.array(feature_vector, dtype=np.float32).reshape(1, -1)
        probs = self.model.predict_proba(features_2d)[0]
        pred_idx = int(np.argmax(probs))
        confidence = float(probs[pred_idx]) * 100.0
        predicted_class = PRIORITY_CLASSES[pred_idx]

        prob_dict = {PRIORITY_CLASSES[i]: round(float(probs[i]) * 100, 1) for i in range(len(PRIORITY_CLASSES))}

        # Calculate local explainability for this sample
        importances = self.model.feature_importances_
        # Weight by normalized feature magnitudes
        feat_norm = np.clip(feature_vector / 100.0, 0.05, 1.0)
        weighted_imp = importances * feat_norm
        if weighted_imp.sum() > 0:
            weighted_imp = (weighted_imp / weighted_imp.sum()) * 100.0

        explainability = {
            FeatureExtractor.FEATURE_NAMES[i]: round(float(weighted_imp[i]), 1)
            for i in range(len(FeatureExtractor.FEATURE_NAMES))
        }

        # Sort explainability descending
        explainability = dict(sorted(explainability.items(), key=lambda item: item[1], reverse=True))

        return predicted_class, round(confidence, 1), prob_dict, explainability

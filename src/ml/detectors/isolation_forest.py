from sklearn.ensemble import IsolationForest as SKIsolationForest
import numpy as np
from typing import Tuple, List, Dict
import logging

logger = logging.getLogger(__name__)

class IsolationForestDetector:
    """
    Isolation Forest for point anomaly detection.
    Good for: unusual single events, outliers
    """
    
    def __init__(
        self,
        contamination: float = 0.01,
        n_estimators: int = 100,
        max_features: float = 0.8,
        bootstrap: bool = True
    ):
        self.model = SKIsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_features=max_features,
            bootstrap=bootstrap,
            random_state=42,
            n_jobs=-1
        )
        self.feature_names: List[str] = []
        self.fitted = False
    
    def fit(self, features: np.ndarray, feature_names: List[str]) -> None:
        """Train on normal data"""
        logger.info(f"Training Isolation Forest on {len(features)} samples with {features.shape[1]} features")
        self.feature_names = feature_names
        self.model.fit(features)
        self.fitted = True
        logger.info("Isolation Forest training complete")
    
    def predict(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Returns:
            labels: -1 for anomaly, 1 for normal
            scores: anomaly scores (lower = more anomalous)
        """
        if not self.fitted:
            raise ValueError("Model not fitted yet. Call fit() first.")
        
        labels = self.model.predict(features)
        scores = self.model.decision_function(features)
        return labels, scores
    
    def explain(self, features: np.ndarray, top_n: int = 5) -> List[Dict[str, float]]:
        """
        Explain which features contributed most to anomaly.
        Returns top_n features for each sample.
        """
        explanations = []
        for sample in features:
            # Simple explanation: return the most extreme feature values
            feature_scores = {}
            for i, (name, value) in enumerate(zip(self.feature_names, sample)):
                feature_scores[name] = float(value)
            
            # Sort by absolute value (most extreme)
            sorted_features = sorted(
                feature_scores.items(),
                key=lambda x: abs(x[1]),
                reverse=True
            )[:top_n]
            
            explanations.append(dict(sorted_features))
        
        return explanations

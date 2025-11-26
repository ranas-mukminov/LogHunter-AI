import pytest
from src.ml.detectors.isolation_forest import IsolationForestDetector
import numpy as np

def test_isolation_forest_training():
    """Test Isolation Forest training"""
    detector = IsolationForestDetector(contamination=0.1, n_estimators=10)
    
    # Generate normal data
    np.random.seed(42)
    normal_data = np.random.randn(100, 5)
    
    feature_names = [f"feature_{i}" for i in range(5)]
    detector.fit(normal_data, feature_names)
    
    assert detector.fitted is True
    assert len(detector.feature_names) == 5

def test_isolation_forest_prediction():
    """Test Isolation Forest anomaly detection"""
    detector = IsolationForestDetector(contamination=0.1, n_estimators=10)
    
    np.random.seed(42)
    normal_data = np.random.randn(100, 5)
    feature_names = [f"feature_{i}" for i in range(5)]
    
    detector.fit(normal_data, feature_names)
    
    # Create anomalous data (far from normal distribution)
    anomaly = np.array([[10, 10, 10, 10, 10]])
    
    labels, scores = detector.predict(anomaly)
    
    # Should detect as anomaly
    assert labels[0] == -1
    assert scores[0] < 0

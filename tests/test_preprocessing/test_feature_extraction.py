import pytest
from src.preprocessing.features.extractor import FeatureExtractor
from src.models.normalized_event import ECSEvent
from datetime import datetime

def test_feature_extraction_basic():
    """Test basic feature extraction"""
    extractor = FeatureExtractor()
    
    event = ECSEvent(
        timestamp=datetime(2024, 1, 15, 14, 30),
        message="User login",
        original_log="test log",
        data_source="test",
        lh_entity_id="user:alice",
        user_name="alice",
        event_category=["authentication"],
        event_outcome="success"
    )
    
    features = extractor.extract(event)
    
    # Check temporal features
    assert features["hour_of_day"] == 14.0
    assert features["day_of_week"] == 0.0  # Monday
    assert features["is_business_hours"] == 1.0
    
    # Check user features
    assert features["has_user"] == 1.0
    assert features["is_auth_event"] == 1.0
    assert features["auth_success"] == 1.0

def test_feature_extraction_process():
    """Test process feature extraction"""
    extractor = FeatureExtractor()
    
    event = ECSEvent(
        timestamp=datetime.utcnow(),
        message="Process created",
        original_log="test",
        data_source="test",
        lh_entity_id="host:server1",
        process_name="powershell.exe",
        process_command_line="powershell.exe -enc ABC123"
    )
    
    features = extractor.extract(event)
    
    assert features["has_process"] == 1.0
    assert features["is_lolbin"] == 1.0
    assert features["has_encoded_cmd"] == 1.0
    assert features["cmdline_length"] > 0

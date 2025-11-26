from src.models.normalized_event import ECSEvent
from typing import Dict
import numpy as np
import math
from collections import Counter

class FeatureExtractor:
    """
    Extract ML features from normalized events.
    """
    
    def extract(self, event: ECSEvent) -> Dict[str, float]:
        """
        Extract all features from an event.
        """
        features = {}
        
        # Temporal features
        features.update(self._extract_temporal_features(event))
        
        # User behavior features
        features.update(self._extract_user_features(event))
        
        # Process features
        features.update(self._extract_process_features(event))
        
        # Network features
        features.update(self._extract_network_features(event))
        
        # String analysis features
        features.update(self._extract_string_features(event))
        
        return features
    
    def _extract_temporal_features(self, event: ECSEvent) -> Dict[str, float]:
        """Extract temporal pattern features"""
        return {
            "hour_of_day": float(event.timestamp.hour),
            "day_of_week": float(event.timestamp.weekday()),
            "is_business_hours": 1.0 if 9 <= event.timestamp.hour <= 18 else 0.0,
            "is_weekend": 1.0 if event.timestamp.weekday() >= 5 else 0.0,
        }
    
    def _extract_user_features(self, event: ECSEvent) -> Dict[str, float]:
        """Extract user behavior features"""
        features = {
            "has_user": 1.0 if event.user_name else 0.0,
        }
        
        # Authentication outcome
        if event.event_category and "authentication" in event.event_category:
            features["is_auth_event"] = 1.0
            features["auth_success"] = 1.0 if event.event_outcome == "success" else 0.0
            features["auth_failure"] = 1.0 if event.event_outcome == "failure" else 0.0
        else:
            features["is_auth_event"] = 0.0
            features["auth_success"] = 0.0
            features["auth_failure"] = 0.0
        
        return features
    
    def _extract_process_features(self, event: ECSEvent) -> Dict[str, float]:
        """Extract process execution features"""
        features = {
            "has_process": 1.0 if event.process_name else 0.0,
        }
        
        if event.process_name:
            # Known Living-off-the-Land Binaries (LOLBins)
            lolbins = {
                "powershell.exe", "cmd.exe", "wmic.exe", "mshta.exe", 
                "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
                "psexec.exe", "at.exe", "schtasks.exe"
            }
            features["is_lolbin"] = 1.0 if event.process_name.lower() in lolbins else 0.0
        else:
            features["is_lolbin"] = 0.0
        
        # Command line analysis
        if event.process_command_line:
            cmdline = event.process_command_line
            features["cmdline_length"] = float(len(cmdline))
            features["cmdline_entropy"] = self._compute_entropy(cmdline)
            features["has_encoded_cmd"] = 1.0 if any(enc in cmdline.lower() for enc in ["-enc", "-e ", "frombase64", "invoke-expression"]) else 0.0
        else:
            features["cmdline_length"] = 0.0
            features["cmdline_entropy"] = 0.0
            features["has_encoded_cmd"] = 0.0
        
        return features
    
    def _extract_network_features(self, event: ECSEvent) -> Dict[str, float]:
        """Extract network traffic features"""
        features = {
            "has_network": 1.0 if event.destination_ip else 0.0,
            "network_bytes": float(event.network_bytes) if event.network_bytes else 0.0,
            "network_packets": float(event.network_packets) if event.network_packets else 0.0,
        }
        
        # Port analysis
        if event.destination_port:
            features["dest_port"] = float(event.destination_port)
            features["is_high_port"] = 1.0 if event.destination_port > 1024 else 0.0
            features["is_common_port"] = 1.0 if event.destination_port in [80, 443, 22, 21, 25, 53] else 0.0
        else:
            features["dest_port"] = 0.0
            features["is_high_port"] = 0.0
            features["is_common_port"] = 0.0
        
        # DNS analysis
        if event.dns_question_name:
            features["dns_query_length"] = float(len(event.dns_question_name))
            features["dns_query_entropy"] = self._compute_entropy(event.dns_question_name)
            features["dns_subdomain_count"] = float(event.dns_question_name.count('.'))
        else:
            features["dns_query_length"] = 0.0
            features["dns_query_entropy"] = 0.0
            features["dns_subdomain_count"] = 0.0
        
        return features
    
    def _extract_string_features(self, event: ECSEvent) -> Dict[str, float]:
        """Extract string analysis features"""
        return {
            "message_length": float(len(event.message)),
            "message_entropy": self._compute_entropy(event.message),
        }
    
    def _compute_entropy(self, text: str) -> float:
        """Compute Shannon entropy of a string"""
        if not text:
            return 0.0
        
        # Count character frequencies
        counts = Counter(text)
        total = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in counts.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy

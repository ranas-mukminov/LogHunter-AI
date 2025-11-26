from clickhouse_driver import Client
from src.models.normalized_event import ECSEvent
from typing import List, Dict, Any
import logging
import json

logger = logging.getLogger(__name__)

class ClickHouseStorage:
    """
    ClickHouse storage for events and anomalies.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.client = None
        
    def connect(self) -> None:
        """Connect to ClickHouse"""
        try:
            self.client = Client(
                host=self.config.get("host", "localhost"),
                port=self.config.get("port", 9000),
                database=self.config.get("database", "loghunter"),
                user=self.config.get("user", "default"),
                password=self.config.get("password", "")
            )
            logger.info(f"Connected to ClickHouse at {self.config.get('host')}")
        except Exception as e:
            logger.error(f"Failed to connect to ClickHouse: {e}")
            raise
    
    def init_schema(self) -> None:
        """Initialize database schema"""
        # Create events table
        events_schema = """
        CREATE TABLE IF NOT EXISTS events (
            timestamp DateTime64(3),
            event_id String,
            data_source String,
            message String,
            event_kind String,
            event_category Array(String),
            event_outcome String,
            source_ip String,
            destination_ip String,
            user_name String,
            host_name String,
            process_name String,
            features String,
            anomaly_score Float32,
            is_anomaly UInt8,
            detector_results String
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMMDD(timestamp)
        ORDER BY (data_source, timestamp, event_id)
        TTL timestamp + INTERVAL 90 DAY
        """
        
        # Create anomalies table
        anomalies_schema = """
        CREATE TABLE IF NOT EXISTS anomalies (
            detected_at DateTime64(3),
            anomaly_id String,
            event_id String,
            entity_type String,
            entity_id String,
            combined_score Float32,
            detector_scores String,
            mitre_tactics Array(String),
            mitre_techniques Array(String),
            explanation String,
            recommended_actions Array(String),
            analyst_verdict String,
            feedback_at Nullable(DateTime),
            feedback_by Nullable(String)
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(detected_at)
        ORDER BY (detected_at, anomaly_id)
        """
        
        try:
            self.client.execute(events_schema)
            self.client.execute(anomalies_schema)
            logger.info("ClickHouse schema initialized")
        except Exception as e:
            logger.error(f"Failed to initialize schema: {e}")
            raise
    
    def insert_event(self, event: ECSEvent, anomaly_score: float = 0.0, is_anomaly: bool = False) -> None:
        """Insert a single event"""
        self.insert_events([event], [anomaly_score], [is_anomaly])
    
    def insert_events(self, events: List[ECSEvent], anomaly_scores: List[float], is_anomalies: List[bool]) -> None:
        """Insert multiple events"""
        if not events:
            return
        
        rows = []
        for event, score, is_anom in zip(events, anomaly_scores, is_anomalies):
            row = {
                "timestamp": event.timestamp,
                "event_id": event.lh_entity_id,
                "data_source": event.data_source,
                "message": event.message,
                "event_kind": event.event_kind,
                "event_category": event.event_category,
                "event_outcome": event.event_outcome or "",
                "source_ip": event.source_ip or "",
                "destination_ip": event.destination_ip or "",
                "user_name": event.user_name or "",
                "host_name": event.host_name or "",
                "process_name": event.process_name or "",
                "features": json.dumps(event.lh_features),
                "anomaly_score": score,
                "is_anomaly": 1 if is_anom else 0,
                "detector_results": ""
            }
            rows.append(row)
        
        try:
            self.client.execute(
                """
                INSERT INTO events (timestamp, event_id, data_source, message, event_kind, 
                                    event_category, event_outcome, source_ip, destination_ip, 
                                    user_name, host_name, process_name, features, 
                                    anomaly_score, is_anomaly, detector_results)
                VALUES
                """,
                rows
            )
            logger.info(f"Inserted {len(rows)} events into ClickHouse")
        except Exception as e:
            logger.error(f"Failed to insert events: {e}")
            raise
    
    def query_events(self, query: str) -> List[Dict[str, Any]]:
        """Execute a query and return results"""
        try:
            result = self.client.execute(query, with_column_types=True)
            columns = [col[0] for col in result[1]]
            rows = result[0]
            
            return [dict(zip(columns, row)) for row in rows]
        except Exception as e:
            logger.error(f"Query failed: {e}")
            raise

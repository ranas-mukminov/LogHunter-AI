from src.models.log_event import RawLogEvent
from src.models.normalized_event import ECSEvent
from datetime import datetime
import json
import logging
import hashlib

logger = logging.getLogger(__name__)

class ECSNormalizer:
    """
    Normalize various log formats to Elastic Common Schema (ECS).
    """
    
    def normalize(self, raw_event: RawLogEvent) -> ECSEvent:
        """
        Convert raw log event to ECS format.
        """
        try:
            # Try to parse as JSON first
            try:
                data = json.loads(raw_event.raw_data)
            except json.JSONDecodeError:
                data = {"message": raw_event.raw_data}
            
            # Extract timestamp
            timestamp = self._extract_timestamp(data, raw_event.timestamp)
            
            # Build entity ID
            entity_id = self._compute_entity_id(data)
            
            # Extract common fields
            event = ECSEvent(
                timestamp=timestamp,
                message=data.get("message", raw_event.raw_data),
                original_log=raw_event.raw_data,
                data_source=raw_event.source_type,
                lh_entity_id=entity_id,
                
                # Event categorization
                event_kind=data.get("event_kind", "event"),
                event_category=data.get("event_category", []),
                event_type=data.get("event_type", []),
                event_outcome=data.get("event_outcome"),
                event_action=data.get("event_action"),
                
                # Source
                source_ip=data.get("source_ip") or data.get("src_ip"),
                source_port=data.get("source_port") or data.get("src_port"),
                source_domain=data.get("source_domain"),
                source_user=data.get("source_user"),
                
                # Destination
                destination_ip=data.get("destination_ip") or data.get("dest_ip") or data.get("dst_ip"),
                destination_port=data.get("destination_port") or data.get("dest_port") or data.get("dst_port"),
                destination_domain=data.get("destination_domain"),
                
                # Host
                host_name=data.get("host_name") or data.get("hostname") or data.get("computer_name"),
                host_ip=data.get("host_ip"),
                host_os_family=data.get("host_os_family"),
                host_os_name=data.get("host_os_name"),
                
                # User
                user_name=data.get("user_name") or data.get("username") or data.get("account_name"),
                user_domain=data.get("user_domain") or data.get("domain"),
                user_id=data.get("user_id") or data.get("user_sid"),
                user_email=data.get("user_email"),
                
                # Process
                process_name=data.get("process_name") or data.get("image"),
                process_pid=data.get("process_pid") or data.get("pid"),
                process_executable=data.get("process_executable") or data.get("exe"),
                process_command_line=data.get("process_command_line") or data.get("cmdline") or data.get("command_line"),
                process_parent_name=data.get("process_parent_name") or data.get("parent_image"),
                process_parent_pid=data.get("process_parent_pid") or data.get("parent_pid"),
                process_parent_command_line=data.get("process_parent_command_line"),
                
                # File
                file_name=data.get("file_name") or data.get("target_filename"),
                file_path=data.get("file_path") or data.get("target_path"),
                file_hash_md5=data.get("file_hash_md5") or data.get("md5"),
                file_hash_sha256=data.get("file_hash_sha256") or data.get("sha256"),
                file_size=data.get("file_size"),
                
                # Network
                network_protocol=data.get("network_protocol") or data.get("protocol"),
                network_direction=data.get("network_direction"),
                network_bytes=data.get("network_bytes") or data.get("bytes"),
                network_packets=data.get("network_packets") or data.get("packets"),
                
                # DNS
                dns_question_name=data.get("dns_question_name") or data.get("query"),
                dns_question_type=data.get("dns_question_type") or data.get("query_type"),
                dns_response_code=data.get("dns_response_code"),
                
                # HTTP
                http_request_method=data.get("http_request_method") or data.get("method"),
                http_request_uri=data.get("http_request_uri") or data.get("uri") or data.get("url"),
                http_response_status_code=data.get("http_response_status_code") or data.get("status_code"),
                http_user_agent=data.get("http_user_agent") or data.get("user_agent"),
                
                # Cloud
                cloud_provider=data.get("cloud_provider"),
                cloud_account_id=data.get("cloud_account_id"),
                cloud_region=data.get("cloud_region"),
                cloud_service_name=data.get("cloud_service_name"),
            )
            
            return event
            
        except Exception as e:
            logger.error(f"Failed to normalize event: {e}")
            raise
    
    def _extract_timestamp(self, data: dict, fallback: datetime) -> datetime:
        """Extract timestamp from various fields"""
        ts_fields = ["@timestamp", "timestamp", "time", "datetime", "event_time"]
        for field in ts_fields:
            if field in data:
                try:
                    if isinstance(data[field], str):
                        return datetime.fromisoformat(data[field].replace('Z', '+00:00'))
                    elif isinstance(data[field], (int, float)):
                        return datetime.fromtimestamp(data[field])
                except Exception:
                    continue
        return fallback
    
    def _compute_entity_id(self, data: dict) -> str:
        """Compute entity ID based on user, host, or source IP"""
        # Priority: user > host > source_ip
        user = data.get("user_name") or data.get("username") or data.get("account_name")
        if user:
            return f"user:{user}"
        
        host = data.get("host_name") or data.get("hostname") or data.get("computer_name")
        if host:
            return f"host:{host}"
        
        src_ip = data.get("source_ip") or data.get("src_ip")
        if src_ip:
            return f"ip:{src_ip}"
        
        # Fallback to hash of the data
        data_hash = hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()[:8]
        return f"unknown:{data_hash}"

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class ECSEvent(BaseModel):
    """
    Normalized event following Elastic Common Schema (ECS).
    """
    # Core fields
    timestamp: datetime
    message: str
    
    # Event categorization
    event_kind: str = "event"  # alert, event, metric, state
    event_category: List[str] = Field(default_factory=list)  # authentication, network, process, file
    event_type: List[str] = Field(default_factory=list)  # start, end, access, creation, deletion
    event_outcome: Optional[str] = None  # success, failure, unknown
    event_action: Optional[str] = None  # logged-in, process-created, file-deleted
    
    # Source
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    source_domain: Optional[str] = None
    source_user: Optional[str] = None
    source_geo: Optional[Dict[str, Any]] = None
    
    # Destination
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    destination_domain: Optional[str] = None
    
    # Host
    host_name: Optional[str] = None
    host_ip: Optional[List[str]] = None
    host_os_family: Optional[str] = None
    host_os_name: Optional[str] = None
    
    # User
    user_name: Optional[str] = None
    user_domain: Optional[str] = None
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    
    # Process
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_executable: Optional[str] = None
    process_command_line: Optional[str] = None
    process_parent_name: Optional[str] = None
    process_parent_pid: Optional[int] = None
    process_parent_command_line: Optional[str] = None
    
    # File
    file_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash_md5: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_size: Optional[int] = None
    
    # Network
    network_protocol: Optional[str] = None
    network_direction: Optional[str] = None  # inbound, outbound, internal
    network_bytes: Optional[int] = None
    network_packets: Optional[int] = None
    
    # DNS
    dns_question_name: Optional[str] = None
    dns_question_type: Optional[str] = None
    dns_response_code: Optional[str] = None
    
    # HTTP
    http_request_method: Optional[str] = None
    http_request_uri: Optional[str] = None
    http_response_status_code: Optional[int] = None
    http_user_agent: Optional[str] = None
    
    # Cloud
    cloud_provider: Optional[str] = None
    cloud_account_id: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_service_name: Optional[str] = None
    
    # Original data
    original_log: str
    data_source: str
    
    # LogHunter metadata
    lh_entity_id: str  # Computed entity identifier
    lh_session_id: Optional[str] = None  # Session correlation
    lh_features: Dict[str, float] = Field(default_factory=dict)  # Extracted ML features
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

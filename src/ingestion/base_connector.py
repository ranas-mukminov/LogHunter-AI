from abc import ABC, abstractmethod
from typing import AsyncIterator, Optional
from src.models.log_event import RawLogEvent
import logging

logger = logging.getLogger(__name__)

class BaseConnector(ABC):
    """
    Abstract base class for log ingestion connectors.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.is_connected = False
    
    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to data source"""
        pass
    
    @abstractmethod
    async def stream(self) -> AsyncIterator[RawLogEvent]:
        """Stream log events from source"""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check connection health"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Gracefully close connection"""
        pass
    
    async def get_lag(self) -> int:
        """Get consumer lag (for queue-based sources)"""
        return 0

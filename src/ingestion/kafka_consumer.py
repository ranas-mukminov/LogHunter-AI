import asyncio
import json
from typing import AsyncIterator
from confluent_kafka import Consumer, KafkaError
from src.ingestion.base_connector import BaseConnector
from src.models.log_event import RawLogEvent
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class KafkaConnector(BaseConnector):
    """
    Ingests logs from Apache Kafka topics.
    """
    
    def __init__(self, config: dict):
        super().__init__(config)
        self.consumer: Consumer = None
        self.topics = config.get("topics", ["security-logs"])
        self.running = False
        
    async def connect(self) -> None:
        """Connect to Kafka brokers"""
        conf = {
            'bootstrap.servers': ','.join(self.config.get("brokers", ["localhost:9092"])),
            'group.id': self.config.get("consumer_group", "loghunter"),
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': False
        }
        
        try:
            self.consumer = Consumer(conf)
            self.consumer.subscribe(self.topics)
            self.is_connected = True
            self.running = True
            logger.info(f"Connected to Kafka brokers: {conf['bootstrap.servers']}")
        except Exception as e:
            logger.error(f"Failed to connect to Kafka: {e}")
            raise

    async def stream(self) -> AsyncIterator[RawLogEvent]:
        """Yield events from Kafka"""
        if not self.is_connected:
            await self.connect()
            
        while self.running:
            # Poll for message
            # We use a small timeout to allow checking self.running
            msg = self.consumer.poll(1.0)
            
            if msg is None:
                await asyncio.sleep(0.1)
                continue
                
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                else:
                    logger.error(f"Kafka error: {msg.error()}")
                    continue
            
            try:
                # Parse message
                value = msg.value().decode('utf-8')
                
                # Try to parse as JSON to extract metadata if possible, otherwise treat as raw string
                try:
                    data = json.loads(value)
                    raw_content = json.dumps(data)
                except json.JSONDecodeError:
                    raw_content = value
                    data = {}

                event = RawLogEvent(
                    source_type="kafka",
                    raw_data=raw_content,
                    metadata={
                        "topic": msg.topic(),
                        "partition": msg.partition(),
                        "offset": msg.offset(),
                        **data
                    }
                )
                
                yield event
                
                # Manually commit offset (in production might want to batch this)
                self.consumer.commit(msg)
                
            except Exception as e:
                logger.error(f"Error processing message: {e}")
                continue

    async def health_check(self) -> bool:
        """Check if consumer is active"""
        return self.is_connected and self.consumer is not None

    async def disconnect(self) -> None:
        """Close Kafka consumer"""
        self.running = False
        if self.consumer:
            self.consumer.close()
        self.is_connected = False
        logger.info("Disconnected from Kafka")

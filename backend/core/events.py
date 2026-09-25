"""
Kafka event publisher.

Events are published for:
  - Every custody transfer (initiated / accepted / rejected)
  - Every tamper detection alert
  - Every audit log entry (mirror to S3 via consumer)

Topics:
  forensics.custody  — custody transfer lifecycle events
  forensics.audit    — mirror of every audit log write
  forensics.alerts   — tamper detection and security alerts

The publisher is fire-and-forget from the API's perspective.
If Kafka is down, the event is logged as a warning — the API
still responds successfully (audit DB write is the source of truth).
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from aiokafka import AIOKafkaProducer

from core.config import settings

log = logging.getLogger(__name__)

_producer: AIOKafkaProducer | None = None


async def get_producer() -> AIOKafkaProducer:
    global _producer
    if _producer is None:
        _producer = AIOKafkaProducer(
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode(),
            acks="all",                # Wait for all replicas before ack
            enable_idempotence=True,   # Exactly-once delivery
        )
        await _producer.start()
    return _producer


async def publish(topic: str, payload: dict[str, Any]) -> None:
    """
    Publish a JSON payload to a Kafka topic.
    Failures are caught and logged — never raise to the caller.
    """
    try:
        producer = await get_producer()
        await producer.send_and_wait(
            topic,
            value={
                "event_id":   str(uuid.uuid4()),
                "published_at": datetime.now(timezone.utc).isoformat(),
                **payload,
            },
        )
    except Exception as exc:
        log.warning("Kafka publish failed (topic=%s): %s", topic, exc)


# ── Typed event helpers ───────────────────────────────────────────────────────

async def publish_custody_transfer(
    event_type:  str,
    evidence_id: uuid.UUID,
    from_user:   uuid.UUID,
    to_user:     uuid.UUID,
    transfer_id: uuid.UUID,
) -> None:
    await publish(settings.KAFKA_TOPIC_CUSTODY, {
        "event_type":   event_type,      # "initiated" | "accepted" | "rejected"
        "evidence_id":  str(evidence_id),
        "from_user_id": str(from_user),
        "to_user_id":   str(to_user),
        "transfer_id":  str(transfer_id),
    })


async def publish_tamper_alert(
    evidence_id:     uuid.UUID,
    stored_hash:     str,
    recomputed_hash: str,
    detected_by:     uuid.UUID,
    ip_address:      str,
) -> None:
    await publish(settings.KAFKA_TOPIC_ALERTS, {
        "event_type":       "tamper_detected",
        "severity":         "critical",
        "evidence_id":      str(evidence_id),
        "stored_hash":      stored_hash,
        "recomputed_hash":  recomputed_hash,
        "detected_by":      str(detected_by),
        "ip_address":       ip_address,
    })


async def publish_audit_mirror(audit_row: dict[str, Any]) -> None:
    """
    Mirror every audit log write to Kafka so the S3 consumer can
    archive it independently of the PostgreSQL database.
    """
    await publish(settings.KAFKA_TOPIC_AUDIT, {
        "event_type": "audit_mirror",
        **audit_row,
    })


async def shutdown_producer() -> None:
    global _producer
    if _producer:
        await _producer.stop()
        _producer = None

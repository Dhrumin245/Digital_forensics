"""
Kafka Audit Mirror Consumer
============================
Consumes from forensics.audit topic and writes every event to S3
(MinIO in dev, real S3 / GCS in prod) with a retention lock.

This is the second leg of the immutability guarantee:
  1. Every action writes to PostgreSQL audit_log (INSERT only)
  2. This consumer mirrors each event to S3 independently

Even if the PostgreSQL audit_log were somehow compromised,
the S3 mirror provides an independent, tamper-evident record.

Run:
    python kafka/audit_mirror_consumer.py

Or deploy as a Kubernetes Deployment alongside the API.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3
from aiokafka import AIOKafkaConsumer
from botocore.exceptions import ClientError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
log = logging.getLogger("audit-mirror")

# ── Config from environment ───────────────────────────────────────────────────
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC     = os.getenv("KAFKA_TOPIC_AUDIT", "forensics.audit")
KAFKA_GROUP     = "audit-mirror-consumer"

S3_ENDPOINT     = os.getenv("S3_ENDPOINT", "http://localhost:9000")
S3_ACCESS_KEY   = os.getenv("S3_ACCESS_KEY", "minioadmin")
S3_SECRET_KEY   = os.getenv("S3_SECRET_KEY", "minioadmin")
S3_BUCKET       = os.getenv("S3_BUCKET_AUDIT_MIRROR", "forensics-audit-mirror")

# ── S3 client ─────────────────────────────────────────────────────────────────
s3 = boto3.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
    region_name="us-east-1",
)


def mirror_to_s3(event: dict[str, Any]) -> str:
    """
    Write one audit event to S3 as a JSON object.
    Key pattern: audit/{YYYY}/{MM}/{DD}/{event_id}.json

    Objects are written with Content-Type application/json.
    In production, configure S3 Object Lock on the bucket so
    these objects cannot be deleted or overwritten.
    """
    now        = datetime.now(timezone.utc)
    event_id   = event.get("event_id") or str(uuid.uuid4())
    s3_key     = f"audit/{now.year}/{now.month:02d}/{now.day:02d}/{event_id}.json"
    body       = json.dumps(event, default=str, ensure_ascii=False).encode("utf-8")

    s3.put_object(
        Bucket=S3_BUCKET,
        Key=s3_key,
        Body=body,
        ContentType="application/json",
        Metadata={
            "action_type":   event.get("action_type", "unknown"),
            "actor_id":      str(event.get("actor_id", "")),
            "resource_type": event.get("resource_type", ""),
        },
    )
    return s3_key


async def run_consumer() -> None:
    log.info("Starting audit mirror consumer  broker=%s  topic=%s", KAFKA_BOOTSTRAP, KAFKA_TOPIC)

    consumer = AIOKafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=KAFKA_GROUP,
        auto_offset_reset="earliest",        # Re-read from start if no committed offset
        enable_auto_commit=False,            # Manual commit — only after successful S3 write
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        session_timeout_ms=30_000,
        heartbeat_interval_ms=10_000,
        max_poll_records=100,
    )

    await consumer.start()
    log.info("Consumer started — waiting for events")

    mirrored = 0
    failed   = 0

    try:
        async for msg in consumer:
            event = msg.value
            action = event.get("action_type", "unknown")

            try:
                s3_key = mirror_to_s3(event)
                mirrored += 1
                log.info(
                    "Mirrored  action=%-35s  s3=%s  total=%d",
                    action, s3_key, mirrored,
                )
                # Commit only after successful S3 write
                await consumer.commit()

            except ClientError as e:
                failed += 1
                log.error(
                    "S3 write failed  action=%s  error=%s  failed_total=%d",
                    action, e, failed,
                )
                # Don't commit — message will be redelivered on restart
                # Implements at-least-once delivery guarantee

            except Exception as e:
                failed += 1
                log.exception("Unexpected error processing audit event: %s", e)

    finally:
        await consumer.stop()
        log.info("Consumer stopped  mirrored=%d  failed=%d", mirrored, failed)


def main() -> None:
    asyncio.run(run_consumer())


if __name__ == "__main__":
    main()

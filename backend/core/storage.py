"""
Object storage service (MinIO / S3).

Evidence files are stored in MinIO with the key pattern:
    evidence/{case_id}/{evidence_id}/{filename}

Attachments:
    attachments/{finding_id}/{filename}

Files are NEVER served directly from S3 URLs — they always pass through
the FastAPI download endpoint so the integrity check fires on every access.
"""

from __future__ import annotations

import io
from uuid import UUID

import boto3
from botocore.exceptions import ClientError

from core.config import settings

# ── S3 client (boto3 works with MinIO) ───────────────────────────────────────
_s3 = boto3.client(
    "s3",
    endpoint_url=settings.S3_ENDPOINT,
    aws_access_key_id=settings.S3_ACCESS_KEY,
    aws_secret_access_key=settings.S3_SECRET_KEY,
    region_name="us-east-1",           # MinIO ignores this but boto3 requires it
)


def evidence_key(case_id: UUID, evidence_id: UUID, filename: str) -> str:
    """Return the canonical S3 key for an evidence file."""
    return f"evidence/{case_id}/{evidence_id}/{filename}"


def attachment_key(finding_id: UUID, filename: str) -> str:
    return f"attachments/{finding_id}/{filename}"


def upload_evidence(
    case_id:     UUID,
    evidence_id: UUID,
    filename:    str,
    data:        bytes,
    mime_type:   str,
) -> str:
    """
    Upload raw bytes to MinIO and return the storage key.
    The SHA-256 is NOT checked here — that is the caller's responsibility.
    """
    key = evidence_key(case_id, evidence_id, filename)
    _s3.put_object(
        Bucket=settings.S3_BUCKET_EVIDENCE,
        Key=key,
        Body=data,
        ContentType=mime_type,
        Metadata={"evidence_id": str(evidence_id)},
    )
    return key


def download_evidence(storage_key: str) -> bytes:
    """
    Download raw bytes from MinIO.
    Raises FileNotFoundError if the key does not exist.
    """
    try:
        resp = _s3.get_object(
            Bucket=settings.S3_BUCKET_EVIDENCE,
            Key=storage_key,
        )
        return resp["Body"].read()
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            raise FileNotFoundError(f"Storage key not found: {storage_key}")
        raise


def upload_attachment(finding_id: UUID, filename: str, data: bytes, mime_type: str) -> str:
    key = attachment_key(finding_id, filename)
    _s3.put_object(
        Bucket=settings.S3_BUCKET_EVIDENCE,
        Key=key,
        Body=data,
        ContentType=mime_type,
    )
    return key

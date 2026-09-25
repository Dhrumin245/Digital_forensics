"""
Evidence service — US-04, US-05, US-06.

This is the cryptographic core of the entire system.

Rules enforced here:
  - SHA-256 is ALWAYS computed server-side on raw bytes
  - Hash is re-verified on EVERY get/download — not just at intake
  - Tamper detection raises a critical alert + Kafka event
  - Evidence records can never be deleted (DB trigger backs this up)
  - Imported hashes are marked hash_source='imported' with tool name
  - Duplicate hash imports require explicit force flag
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core import audit, events, storage
from core.security import compute_sha256, verify_hash
from models import Evidence
from schemas import (
    AuditActionType,
    EvidenceResponse,
    EvidenceType,
    EvidenceWithIntegrityResponse,
    HashImportResult,
    HashImportRowResult,
    IntegrityCheckDetail,
    IntegrityStatus,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _to_response(ev: Evidence) -> EvidenceResponse:
    return EvidenceResponse(
        id=ev.id,
        case_id=ev.case_id,
        filename=ev.filename,
        file_size_bytes=ev.file_size_bytes,
        mime_type=ev.mime_type,
        evidence_type=EvidenceType(ev.evidence_type),
        sha256_hash=ev.sha256_hash,
        hash_source=ev.hash_source,
        acquisition_tool=ev.acquisition_tool,
        description=ev.description,
        acquisition_notes=ev.acquisition_notes,
        uploaded_by=ev.uploaded_by,
        uploaded_at=ev.uploaded_at,
        current_custodian_id=ev.current_custodian_id,
        integrity_status=IntegrityStatus(ev.integrity_status),
    )


async def _assert_case_access(db: AsyncSession, case_id: UUID, user_id: UUID, role: str) -> None:
    """Verify the user has access to this case."""
    from models import CaseAssignment
    if role in {"Admin", "CaseManager"}:
        return
    result = await db.execute(
        select(CaseAssignment).where(
            CaseAssignment.case_id == case_id,
            CaseAssignment.user_id == user_id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=403, detail="You are not assigned to this case")


# ── US-04: Upload evidence ────────────────────────────────────────────────────

async def upload_evidence(
    db:               AsyncSession,
    case_id:          UUID,
    uploader_id:      UUID,
    uploader_role:    str,
    raw_bytes:        bytes,
    filename:         str,
    mime_type:        str,
    description:      str,
    evidence_type:    EvidenceType,
    acquisition_notes: Optional[str],
    ip_address:       str,
) -> EvidenceResponse:
    await _assert_case_access(db, case_id, uploader_id, uploader_role)

    evidence_id = uuid.uuid4()

    # ── Core cryptographic operation ──────────────────────────────────────────
    # SHA-256 computed SERVER-SIDE on raw bytes. Always. No exceptions.
    sha256 = compute_sha256(raw_bytes)

    # ── Store file in object storage ──────────────────────────────────────────
    storage_key = storage.upload_evidence(
        case_id=case_id,
        evidence_id=evidence_id,
        filename=filename,
        data=raw_bytes,
        mime_type=mime_type,
    )

    # ── Persist evidence record ───────────────────────────────────────────────
    ev = Evidence(
        id=evidence_id,
        case_id=case_id,
        filename=filename,
        file_size_bytes=len(raw_bytes),
        mime_type=mime_type,
        evidence_type=evidence_type.value,
        sha256_hash=sha256,
        storage_key=storage_key,
        hash_source="computed",
        acquisition_tool=None,
        description=description,
        acquisition_notes=acquisition_notes,
        uploaded_by=uploader_id,
        uploaded_at=datetime.now(timezone.utc),
        current_custodian_id=uploader_id,   # Uploader is first custodian
        integrity_status="verified",
    )
    db.add(ev)
    await db.flush()

    # ── Audit log ─────────────────────────────────────────────────────────────
    await audit.log(
        db=db,
        action=AuditActionType.evidence_uploaded,
        resource_type="evidence",
        resource_id=str(evidence_id),
        ip_address=ip_address,
        actor_id=uploader_id,
        actor_role=uploader_role,
        detail={
            "case_id":  str(case_id),
            "filename": filename,
            "sha256":   sha256,
            "size":     len(raw_bytes),
        },
    )

    return _to_response(ev)


# ── US-05: Import hashes from external forensic tools ─────────────────────────

async def import_hashes(
    db:               AsyncSession,
    case_id:          UUID,
    importer_id:      UUID,
    importer_role:    str,
    file_content:     bytes,
    content_type:     str,
    acquisition_tool: Optional[str],
    force_duplicates: bool,
    ip_address:       str,
) -> HashImportResult:
    await _assert_case_access(db, case_id, importer_id, importer_role)

    # ── Parse file ────────────────────────────────────────────────────────────
    rows = _parse_hash_import(file_content, content_type)

    imported = 0
    skipped  = 0
    errors   = 0
    dupes    = 0
    row_results: list[HashImportRowResult] = []

    for i, row in enumerate(rows, start=1):
        sha256   = row.get("sha256", "").strip().lower()
        filename = row.get("filename", "").strip()
        acq_date = row.get("acquisition_date", "")

        # Validate hash format
        if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
            errors += 1
            row_results.append(HashImportRowResult(
                row=i, filename=filename, status="error",
                message=f"Invalid SHA-256 format: '{sha256}'",
            ))
            continue

        if not filename:
            errors += 1
            row_results.append(HashImportRowResult(
                row=i, filename="", status="error", message="Filename is required",
            ))
            continue

        # Check for duplicates
        existing = await db.execute(
            select(Evidence).where(
                Evidence.sha256_hash == sha256,
                Evidence.case_id == case_id,
            )
        )
        if existing.scalar_one_or_none():
            if not force_duplicates:
                dupes += 1
                row_results.append(HashImportRowResult(
                    row=i, filename=filename, status="duplicate",
                    message="Hash already registered on this case. Use force_duplicates=true to import anyway.",
                ))
                continue
            # force_duplicates=True: import as duplicate-linked record

        # ── Create evidence record for imported hash ──────────────────────────
        ev = Evidence(
            id=uuid.uuid4(),
            case_id=case_id,
            filename=filename,
            file_size_bytes=0,              # Not stored — hash only
            mime_type="application/octet-stream",
            evidence_type="file",
            sha256_hash=sha256,
            storage_key="",                 # No file stored — imported hash only
            hash_source="imported",
            acquisition_tool=acquisition_tool,
            description=f"Imported from {acquisition_tool or 'external tool'}",
            acquisition_notes=f"Acquisition date: {acq_date}" if acq_date else None,
            uploaded_by=importer_id,
            uploaded_at=datetime.now(timezone.utc),
            current_custodian_id=importer_id,
            integrity_status="pending",     # Cannot verify without the actual file
        )
        db.add(ev)
        imported += 1
        row_results.append(HashImportRowResult(
            row=i, filename=filename, status="imported", message=None,
        ))

    await db.flush()

    # ── Audit log ─────────────────────────────────────────────────────────────
    await audit.log(
        db=db,
        action=AuditActionType.hash_imported,
        resource_type="evidence_batch",
        resource_id=str(case_id),
        ip_address=ip_address,
        actor_id=importer_id,
        actor_role=importer_role,
        detail={
            "total": len(rows), "imported": imported,
            "errors": errors, "duplicates": dupes,
            "tool": acquisition_tool,
        },
    )

    return HashImportResult(
        total_rows=len(rows),
        imported=imported,
        skipped=skipped,
        errors=errors,
        duplicates=dupes,
        row_results=row_results,
    )


def _parse_hash_import(content: bytes, content_type: str) -> list[dict]:
    """Parse CSV or JSON hash export from Autopsy/FTK."""
    text = content.decode("utf-8", errors="replace")

    if "json" in content_type.lower() or text.strip().startswith("["):
        try:
            data = json.loads(text)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []

    # Default: CSV
    reader = csv.DictReader(io.StringIO(text))
    return [
        {k.strip().lower(): v.strip() for k, v in row.items()}
        for row in reader
    ]


# ── US-06: Get evidence + live integrity check ────────────────────────────────

async def get_evidence_with_integrity(
    db:         AsyncSession,
    case_id:    UUID,
    evidence_id: UUID,
    actor_id:   UUID,
    actor_role: str,
    ip_address: str,
) -> EvidenceWithIntegrityResponse:
    await _assert_case_access(db, case_id, actor_id, actor_role)

    result = await db.execute(
        select(Evidence).where(
            Evidence.id == evidence_id,
            Evidence.case_id == case_id,
        )
    )
    ev = result.scalar_one_or_none()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    checked_at = datetime.now(timezone.utc)

    # Imported hashes (no file stored) skip the re-verification
    if ev.hash_source == "imported" or not ev.storage_key:
        check = IntegrityCheckDetail(
            checked_at=checked_at,
            stored_hash=ev.sha256_hash,
            recomputed_hash="n/a (imported hash — no file stored)",
            match=True,
            alert_raised=False,
        )
    else:
        # ── Re-compute SHA-256 on the live file ───────────────────────────────
        try:
            raw_bytes = storage.download_evidence(ev.storage_key)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Evidence file missing from storage")

        recomputed  = compute_sha256(raw_bytes)
        intact      = verify_hash(raw_bytes, ev.sha256_hash)
        alert_raised = False

        if not intact:
            # ── TAMPER DETECTED ───────────────────────────────────────────────
            ev.integrity_status = "tampered"
            alert_raised = True

            await audit.log(
                db=db,
                action=AuditActionType.tamper_detected,
                resource_type="evidence",
                resource_id=str(evidence_id),
                ip_address=ip_address,
                result="failure",
                actor_id=actor_id,
                actor_role=actor_role,
                detail={
                    "stored_hash":     ev.sha256_hash,
                    "recomputed_hash": recomputed,
                },
            )
            # Publish critical alert to Kafka
            await events.publish_tamper_alert(
                evidence_id=ev.id,
                stored_hash=ev.sha256_hash,
                recomputed_hash=recomputed,
                detected_by=actor_id,
                ip_address=ip_address,
            )
        else:
            ev.integrity_status = "verified"

        await db.flush()

        check = IntegrityCheckDetail(
            checked_at=checked_at,
            stored_hash=ev.sha256_hash,
            recomputed_hash=recomputed,
            match=intact,
            alert_raised=alert_raised,
        )

    # ── Audit access ──────────────────────────────────────────────────────────
    await audit.log(
        db=db,
        action=AuditActionType.evidence_accessed,
        resource_type="evidence",
        resource_id=str(evidence_id),
        ip_address=ip_address,
        actor_id=actor_id,
        actor_role=actor_role,
        detail={"integrity_match": check.match},
    )

    if not check.match:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail={
                "error":   "tamper_detected",
                "message": "Evidence integrity check failed. Access has been restricted pending review.",
                "stored_hash":     check.stored_hash,
                "recomputed_hash": check.recomputed_hash,
            },
        )

    return EvidenceWithIntegrityResponse(
        **_to_response(ev).model_dump(),
        integrity_check=check,
    )


# ── Download evidence (also triggers integrity check) ─────────────────────────

async def download_evidence(
    db:          AsyncSession,
    case_id:     UUID,
    evidence_id: UUID,
    actor_id:    UUID,
    actor_role:  str,
    ip_address:  str,
) -> tuple[bytes, str, str]:
    """
    Returns (raw_bytes, filename, sha256_hash).
    Raises HTTP 423 if tampered.
    """
    # Re-use the integrity-check path — it handles everything
    checked = await get_evidence_with_integrity(
        db, case_id, evidence_id, actor_id, actor_role, ip_address
    )

    raw_bytes = storage.download_evidence(
        (await db.execute(
            select(Evidence).where(Evidence.id == evidence_id)
        )).scalar_one().storage_key
    )

    await audit.log(
        db=db,
        action=AuditActionType.evidence_downloaded,
        resource_type="evidence",
        resource_id=str(evidence_id),
        ip_address=ip_address,
        actor_id=actor_id,
        actor_role=actor_role,
        detail={"filename": checked.filename},
    )

    return raw_bytes, checked.filename, checked.sha256_hash


# ── List evidence ─────────────────────────────────────────────────────────────

async def list_evidence(
    db:               AsyncSession,
    case_id:          UUID,
    actor_id:         UUID,
    actor_role:       str,
    integrity_filter: Optional[str],
) -> list[EvidenceResponse]:
    await _assert_case_access(db, case_id, actor_id, actor_role)

    q = select(Evidence).where(Evidence.case_id == case_id)
    if integrity_filter:
        q = q.where(Evidence.integrity_status == integrity_filter)

    result = await db.execute(q.order_by(Evidence.uploaded_at.desc()))
    return [_to_response(ev) for ev in result.scalars().all()]

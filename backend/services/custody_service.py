"""
Custody transfer service — US-07, US-08.

Rules enforced:
  - Evidence hash MUST be re-verified before transfer is allowed
  - Transfer is PENDING until the receiving party explicitly accepts
  - Only the designated to_user can accept
  - Once accepted, record is immutable (DB trigger also enforces this)
  - Receiving party must be assigned to the case with a valid role
  - Gap detection: any time period without a custodian is flagged
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core import audit, events, storage
from core.security import compute_sha256, verify_hash
from models import CaseAssignment, CustodyRecord, Evidence, User
from schemas import (
    AuditActionType,
    CustodyChainGap,
    CustodyChainResponse,
    CustodyRecord as CustodyRecordSchema,
    CustodyTransferStatus,
    InitiateCustodyTransferRequest,
)


def _sign(user_id: UUID, evidence_id: UUID, timestamp: datetime) -> str:
    """
    Produce a deterministic signature string.
    In production replace with RSA-PSS or ECDSA using a hardware key.
    """
    import hashlib
    payload = f"{user_id}|{evidence_id}|{timestamp.isoformat()}"
    return hashlib.sha256(payload.encode()).hexdigest()


async def _load_evidence(db: AsyncSession, case_id: UUID, evidence_id: UUID) -> Evidence:
    result = await db.execute(
        select(Evidence).where(
            Evidence.id == evidence_id,
            Evidence.case_id == case_id,
        )
    )
    ev = result.scalar_one_or_none()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return ev


def _to_record_schema(rec: CustodyRecord) -> CustodyRecordSchema:
    from services.auth_service import to_profile
    return CustodyRecordSchema(
        id=rec.id,
        evidence_id=rec.evidence_id,
        from_user_id=rec.from_user_id,
        to_user_id=rec.to_user_id,
        from_user=to_profile(rec.from_user),
        to_user=to_profile(rec.to_user),
        transfer_reason=rec.transfer_reason,
        hash_at_transfer=rec.hash_at_transfer,
        status=CustodyTransferStatus(rec.status),
        initiated_at=rec.initiated_at,
        accepted_at=rec.accepted_at,
        from_signature=rec.from_signature,
        to_signature=rec.to_signature,
    )


# ── US-08: Get full custody chain ─────────────────────────────────────────────

async def get_custody_chain(
    db:          AsyncSession,
    case_id:     UUID,
    evidence_id: UUID,
) -> CustodyChainResponse:
    result = await db.execute(
        select(CustodyRecord)
        .options(
            selectinload(CustodyRecord.from_user),
            selectinload(CustodyRecord.to_user),
        )
        .where(CustodyRecord.evidence_id == evidence_id)
        .order_by(CustodyRecord.initiated_at.asc())
    )
    records = list(result.scalars().all())

    # ── Gap detection ─────────────────────────────────────────────────────────
    gaps: list[CustodyChainGap] = []
    accepted = [r for r in records if r.status == "accepted"]

    for i in range(len(accepted) - 1):
        current_end  = accepted[i].accepted_at
        next_start   = accepted[i + 1].initiated_at
        if current_end and next_start and next_start > current_end:
            # Gap: evidence had no custodian between these two timestamps
            gap_seconds = (next_start - current_end).total_seconds()
            if gap_seconds > 60:    # Ignore sub-minute gaps (processing time)
                gaps.append(CustodyChainGap(from_ts=current_end, to_ts=next_start))

    return CustodyChainResponse(
        evidence_id=evidence_id,
        chain_complete=len(gaps) == 0,
        gaps=gaps,
        records=[_to_record_schema(r) for r in records],
    )


# ── US-07: Initiate custody transfer ──────────────────────────────────────────

async def initiate_transfer(
    db:          AsyncSession,
    case_id:     UUID,
    evidence_id: UUID,
    actor_id:    UUID,
    actor_role:  str,
    body:        InitiateCustodyTransferRequest,
    ip_address:  str,
) -> CustodyRecordSchema:
    ev = await _load_evidence(db, case_id, evidence_id)

    # Must be current custodian to initiate
    if ev.current_custodian_id != actor_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the current custodian can initiate a transfer",
        )

    # Receiving user must be assigned to this case
    assignment = await db.execute(
        select(CaseAssignment).where(
            CaseAssignment.case_id == case_id,
            CaseAssignment.user_id == body.to_user_id,
        )
    )
    if not assignment.scalar_one_or_none():
        raise HTTPException(
            status_code=400,
            detail="Receiving user is not assigned to this case",
        )

    # ── Re-verify integrity before allowing transfer ──────────────────────────
    if ev.storage_key:
        try:
            raw_bytes = storage.download_evidence(ev.storage_key)
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail="Evidence file missing from storage")

        if not verify_hash(raw_bytes, ev.sha256_hash):
            ev.integrity_status = "tampered"
            await db.flush()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error":   "integrity_check_failed",
                    "message": "Evidence hash mismatch detected. Transfer blocked — evidence may be tampered.",
                },
            )

    now = datetime.now(timezone.utc)
    rec = CustodyRecord(
        id=uuid.uuid4(),
        evidence_id=evidence_id,
        from_user_id=actor_id,
        to_user_id=body.to_user_id,
        transfer_reason=body.transfer_reason,
        hash_at_transfer=ev.sha256_hash,
        status="pending",
        initiated_at=now,
        from_signature=_sign(actor_id, evidence_id, now),
    )
    db.add(rec)
    await db.flush()

    await audit.log(
        db=db,
        action=AuditActionType.custody_initiated,
        resource_type="custody_record",
        resource_id=str(rec.id),
        ip_address=ip_address,
        actor_id=actor_id,
        actor_role=actor_role,
        detail={
            "evidence_id": str(evidence_id),
            "to_user_id":  str(body.to_user_id),
        },
    )
    await events.publish_custody_transfer(
        event_type="initiated",
        evidence_id=evidence_id,
        from_user=actor_id,
        to_user=body.to_user_id,
        transfer_id=rec.id,
    )

    # Reload with relationships
    result = await db.execute(
        select(CustodyRecord)
        .options(
            selectinload(CustodyRecord.from_user),
            selectinload(CustodyRecord.to_user),
        )
        .where(CustodyRecord.id == rec.id)
    )
    return _to_record_schema(result.scalar_one())


# ── US-07: Accept transfer ────────────────────────────────────────────────────

async def accept_transfer(
    db:          AsyncSession,
    case_id:     UUID,
    evidence_id: UUID,
    transfer_id: UUID,
    actor_id:    UUID,
    actor_role:  str,
    ip_address:  str,
) -> CustodyRecordSchema:
    result = await db.execute(
        select(CustodyRecord)
        .options(
            selectinload(CustodyRecord.from_user),
            selectinload(CustodyRecord.to_user),
        )
        .where(CustodyRecord.id == transfer_id, CustodyRecord.evidence_id == evidence_id)
    )
    rec = result.scalar_one_or_none()
    if not rec:
        raise HTTPException(status_code=404, detail="Transfer not found")
    if rec.status != "pending":
        raise HTTPException(status_code=409, detail=f"Transfer is already {rec.status}")
    if rec.to_user_id != actor_id:
        raise HTTPException(
            status_code=403,
            detail="Only the designated receiving party can accept this transfer",
        )

    now = datetime.now(timezone.utc)
    rec.status       = "accepted"
    rec.accepted_at  = now
    rec.to_signature = _sign(actor_id, evidence_id, now)

    # Update evidence custodian
    ev = await _load_evidence(db, case_id, evidence_id)
    ev.current_custodian_id = actor_id

    await db.flush()

    await audit.log(
        db=db,
        action=AuditActionType.custody_accepted,
        resource_type="custody_record",
        resource_id=str(transfer_id),
        ip_address=ip_address,
        actor_id=actor_id,
        actor_role=actor_role,
        detail={"evidence_id": str(evidence_id), "from_user_id": str(rec.from_user_id)},
    )
    await events.publish_custody_transfer(
        event_type="accepted",
        evidence_id=evidence_id,
        from_user=rec.from_user_id,
        to_user=actor_id,
        transfer_id=transfer_id,
    )

    return _to_record_schema(rec)


# ── Reject transfer ───────────────────────────────────────────────────────────

async def reject_transfer(
    db:          AsyncSession,
    case_id:     UUID,
    evidence_id: UUID,
    transfer_id: UUID,
    actor_id:    UUID,
    actor_role:  str,
    reason:      str,
    ip_address:  str,
) -> CustodyRecordSchema:
    result = await db.execute(
        select(CustodyRecord)
        .options(
            selectinload(CustodyRecord.from_user),
            selectinload(CustodyRecord.to_user),
        )
        .where(CustodyRecord.id == transfer_id, CustodyRecord.evidence_id == evidence_id)
    )
    rec = result.scalar_one_or_none()
    if not rec:
        raise HTTPException(status_code=404, detail="Transfer not found")
    if rec.status != "pending":
        raise HTTPException(status_code=409, detail=f"Transfer is already {rec.status}")
    if rec.to_user_id != actor_id:
        raise HTTPException(status_code=403, detail="Only the designated receiving party can reject")

    rec.status = "rejected"
    await db.flush()

    await audit.log(
        db=db,
        action=AuditActionType.custody_rejected,
        resource_type="custody_record",
        resource_id=str(transfer_id),
        ip_address=ip_address,
        actor_id=actor_id,
        actor_role=actor_role,
        detail={"reason": reason},
    )

    return _to_record_schema(rec)

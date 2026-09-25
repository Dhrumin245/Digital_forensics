"""
Remaining services:
  - task_service    (US-09)
  - finding_service (US-10)
  - report_service  (US-11, US-12, US-14)
  - verify_service  (US-13)
  - user_service    (US-16)
"""

from __future__ import annotations

import difflib
import uuid
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core import audit, storage
from core.security import compute_sha256
from models import (
    Evidence, Finding, FindingAttachment,
    Report, ReportVersion, Task, TaskEvidenceLink, User,
)
from schemas import (
    AuditActionType,
    CreateReportRequest,
    CreateTaskRequest,
    FindingAttachment as FindingAttachmentSchema,
    FindingResponse,
    LockReportRequest,
    ReportDiff,
    ReportResponse,
    ReportStatus,
    ReportSummaryResponse,
    ReportVersionResponse,
    SaveReportVersionRequest,
    TaskResponse,
    TaskStatus,
    UpdateTaskRequest,
    UserProfile,
    UserRole,
)
from services.auth_service import create_user, hash_password, to_profile


# ─────────────────────────────────────────────────────────────────────────────
# TASK SERVICE — US-09
# ─────────────────────────────────────────────────────────────────────────────

def _to_task_response(task: Task) -> TaskResponse:
    return TaskResponse(
        id=task.id,
        case_id=task.case_id,
        title=task.title,
        description=task.description,
        assigned_to=to_profile(task.assigned_to),
        assigned_by=task.assigned_by_user_id,
        status=TaskStatus(task.status),
        evidence_ids=[link.evidence_id for link in (task.evidence_links or [])],
        due_date=task.due_date,
        created_at=task.created_at,
        updated_at=task.updated_at,
    )


async def create_task(
    db:       AsyncSession,
    case_id:  UUID,
    body:     CreateTaskRequest,
    actor_id: UUID,
    actor_role: str,
    ip_address: str,
) -> TaskResponse:
    if not body.evidence_ids:
        raise HTTPException(status_code=400, detail="Task must link to at least one evidence item")

    # Validate all evidence_ids belong to this case
    for eid in body.evidence_ids:
        result = await db.execute(
            select(Evidence).where(Evidence.id == eid, Evidence.case_id == case_id)
        )
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail=f"Evidence {eid} not found in this case")

    task = Task(
        id=uuid.uuid4(),
        case_id=case_id,
        title=body.title,
        description=body.description,
        assigned_to_user_id=body.assigned_to_user_id,
        assigned_by_user_id=actor_id,
        status="assigned",
        due_date=body.due_date,
    )
    db.add(task)
    await db.flush()

    # Create evidence links
    for eid in body.evidence_ids:
        db.add(TaskEvidenceLink(task_id=task.id, evidence_id=eid))
    await db.flush()

    await audit.log(
        db=db, action=AuditActionType.task_created,
        resource_type="task", resource_id=str(task.id),
        ip_address=ip_address, actor_id=actor_id, actor_role=actor_role,
        detail={"case_id": str(case_id), "assigned_to": str(body.assigned_to_user_id)},
    )

    result = await db.execute(
        select(Task)
        .options(selectinload(Task.assigned_to), selectinload(Task.evidence_links))
        .where(Task.id == task.id)
    )
    return _to_task_response(result.scalar_one())


async def list_tasks(
    db:          AsyncSession,
    case_id:     UUID,
    assigned_to: Optional[UUID] = None,
    task_status: Optional[str]  = None,
) -> list[TaskResponse]:
    q = select(Task).options(
        selectinload(Task.assigned_to),
        selectinload(Task.evidence_links),
    ).where(Task.case_id == case_id)
    if assigned_to:
        q = q.where(Task.assigned_to_user_id == assigned_to)
    if task_status:
        q = q.where(Task.status == task_status)
    result = await db.execute(q.order_by(Task.created_at.desc()))
    return [_to_task_response(t) for t in result.scalars().all()]


async def update_task(
    db:         AsyncSession,
    case_id:    UUID,
    task_id:    UUID,
    body:       UpdateTaskRequest,
    actor_id:   UUID,
    actor_role: str,
    ip_address: str,
) -> TaskResponse:
    result = await db.execute(
        select(Task)
        .options(selectinload(Task.assigned_to), selectinload(Task.evidence_links))
        .where(Task.id == task_id, Task.case_id == case_id)
    )
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # Only the assigned examiner can change status to in_progress / completed
    if body.status and body.status.value in ("in_progress", "completed"):
        if task.assigned_to_user_id != actor_id:
            raise HTTPException(
                status_code=403,
                detail="Only the assigned examiner can advance task status",
            )

    if body.status:
        task.status = body.status.value
    if body.title:
        task.title = body.title
    if body.description is not None:
        task.description = body.description
    if body.due_date is not None:
        task.due_date = body.due_date

    await db.flush()
    await audit.log(
        db=db, action=AuditActionType.task_status_changed,
        resource_type="task", resource_id=str(task_id),
        ip_address=ip_address, actor_id=actor_id, actor_role=actor_role,
        detail={"new_status": body.status.value if body.status else None},
    )
    return _to_task_response(task)


# ─────────────────────────────────────────────────────────────────────────────
# FINDING SERVICE — US-10
# ─────────────────────────────────────────────────────────────────────────────

def _to_finding_response(finding: Finding) -> FindingResponse:
    return FindingResponse(
        id=finding.id,
        task_id=finding.task_id,
        evidence_id=finding.evidence_id,
        title=finding.title,
        content=finding.content,
        attachments=[
            FindingAttachmentSchema(
                id=a.id,
                filename=a.filename,
                sha256_hash=a.sha256_hash,
                size_bytes=a.size_bytes,
            )
            for a in (finding.attachments or [])
        ],
        created_by=finding.created_by,
        created_at=finding.created_at,
    )


async def create_finding(
    db:          AsyncSession,
    case_id:     UUID,
    task_id:     UUID,
    evidence_id: UUID,
    title:       str,
    content:     str,
    actor_id:    UUID,
    actor_role:  str,
    ip_address:  str,
    attachments: list[tuple[str, bytes, str]],  # (filename, bytes, mime)
) -> FindingResponse:
    # Verify task exists in this case
    task_result = await db.execute(
        select(Task).where(Task.id == task_id, Task.case_id == case_id)
    )
    if not task_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Task not found")

    finding_id = uuid.uuid4()
    finding = Finding(
        id=finding_id,
        task_id=task_id,
        evidence_id=evidence_id,
        title=title,
        content=content,
        created_by=actor_id,
        created_at=datetime.now(timezone.utc),
    )
    db.add(finding)
    await db.flush()

    # Store attachments
    for filename, raw_bytes, mime_type in attachments:
        sha256      = compute_sha256(raw_bytes)
        storage_key = storage.upload_attachment(finding_id, filename, raw_bytes, mime_type)
        db.add(FindingAttachment(
            id=uuid.uuid4(),
            finding_id=finding_id,
            filename=filename,
            storage_key=storage_key,
            sha256_hash=sha256,
            size_bytes=len(raw_bytes),
        ))
    await db.flush()

    await audit.log(
        db=db, action=AuditActionType.finding_created,
        resource_type="finding", resource_id=str(finding_id),
        ip_address=ip_address, actor_id=actor_id, actor_role=actor_role,
        detail={"task_id": str(task_id), "evidence_id": str(evidence_id)},
    )

    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.attachments))
        .where(Finding.id == finding_id)
    )
    return _to_finding_response(result.scalar_one())


async def list_findings(db: AsyncSession, task_id: UUID) -> list[FindingResponse]:
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.attachments))
        .where(Finding.task_id == task_id)
        .order_by(Finding.created_at.asc())
    )
    return [_to_finding_response(f) for f in result.scalars().all()]


# ─────────────────────────────────────────────────────────────────────────────
# REPORT SERVICE — US-11, US-12, US-14
# ─────────────────────────────────────────────────────────────────────────────

def _to_version_response(v: ReportVersion) -> ReportVersionResponse:
    return ReportVersionResponse(
        report_id=v.report_id,
        version_number=v.version_number,
        content=v.content,
        content_hash=v.content_hash,
        author_id=v.author_id,
        author=to_profile(v.author),
        saved_at=v.saved_at,
        change_summary=v.change_summary,
        is_court_ready=v.is_court_ready,
        locked_by=v.locked_by,
        locked_at=v.locked_at,
        review_notes=v.review_notes,
    )


def _to_summary(r: Report) -> ReportSummaryResponse:
    return ReportSummaryResponse(
        id=r.id,
        case_id=r.case_id,
        title=r.title,
        status=ReportStatus(r.status),
        latest_version=r.latest_version,
        court_ready_version=r.court_ready_version,
        created_by=r.created_by,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


async def create_report(
    db:         AsyncSession,
    case_id:    UUID,
    body:       CreateReportRequest,
    actor_id:   UUID,
    actor_role: str,
    ip_address: str,
) -> ReportSummaryResponse:
    report_id    = uuid.uuid4()
    content_hash = compute_sha256(body.content.encode("utf-8"))
    now          = datetime.now(timezone.utc)

    report = Report(
        id=report_id,
        case_id=case_id,
        title=body.title,
        status="draft",
        latest_version=1,
        created_by=actor_id,
    )
    db.add(report)
    await db.flush()

    v1 = ReportVersion(
        id=uuid.uuid4(),
        report_id=report_id,
        version_number=1,
        content=body.content,
        content_hash=content_hash,
        author_id=actor_id,
        saved_at=now,
        change_summary="Initial version",
        is_court_ready=False,
    )
    db.add(v1)
    await db.flush()

    await audit.log(
        db=db, action=AuditActionType.report_created,
        resource_type="report", resource_id=str(report_id),
        ip_address=ip_address, actor_id=actor_id, actor_role=actor_role,
        detail={"case_id": str(case_id), "title": body.title},
    )
    return _to_summary(report)


async def save_version(
    db:         AsyncSession,
    case_id:    UUID,
    report_id:  UUID,
    body:       SaveReportVersionRequest,
    actor_id:   UUID,
    actor_role: str,
    ip_address: str,
) -> ReportVersionResponse:
    result = await db.execute(
        select(Report)
        .options(selectinload(Report.versions))
        .where(Report.id == report_id, Report.case_id == case_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Block saves on court-locked reports
    court_version = next(
        (v for v in report.versions if v.is_court_ready), None
    )
    if court_version:
        raise HTTPException(
            status_code=403,
            detail=f"Report version {court_version.version_number} is court-ready locked. "
                   "Create a new report to start a new draft cycle.",
        )

    new_version_number = report.latest_version + 1
    content_hash       = compute_sha256(body.content.encode("utf-8"))

    version = ReportVersion(
        id=uuid.uuid4(),
        report_id=report_id,
        version_number=new_version_number,
        content=body.content,
        content_hash=content_hash,
        author_id=actor_id,
        saved_at=datetime.now(timezone.utc),
        change_summary=body.change_summary,
        is_court_ready=False,
    )
    db.add(version)

    report.latest_version = new_version_number
    await db.flush()

    await audit.log(
        db=db, action=AuditActionType.report_version_saved,
        resource_type="report_version", resource_id=str(version.id),
        ip_address=ip_address, actor_id=actor_id, actor_role=actor_role,
        detail={"report_id": str(report_id), "version": new_version_number},
    )

    # Reload with author relationship
    result = await db.execute(
        select(ReportVersion)
        .options(selectinload(ReportVersion.author))
        .where(ReportVersion.id == version.id)
    )
    return _to_version_response(result.scalar_one())


async def lock_report(
    db:         AsyncSession,
    case_id:    UUID,
    report_id:  UUID,
    body:       LockReportRequest,
    actor_id:   UUID,
    actor_role: str,
    ip_address: str,
) -> ReportVersionResponse:
    result = await db.execute(
        select(Report)
        .options(selectinload(Report.versions))
        .where(Report.id == report_id, Report.case_id == case_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    target = next(
        (v for v in report.versions if v.version_number == body.version_number), None
    )
    if not target:
        raise HTTPException(status_code=404, detail=f"Version {body.version_number} not found")
    if target.is_court_ready:
        raise HTTPException(status_code=409, detail="Version is already court-ready locked")

    now                    = datetime.now(timezone.utc)
    target.is_court_ready  = True
    target.locked_by       = actor_id
    target.locked_at       = now
    target.review_notes    = body.review_notes

    report.status               = "court_ready"
    report.court_ready_version  = body.version_number
    await db.flush()

    await audit.log(
        db=db, action=AuditActionType.report_locked,
        resource_type="report_version", resource_id=str(target.id),
        ip_address=ip_address, actor_id=actor_id, actor_role=actor_role,
        detail={
            "report_id": str(report_id),
            "version":   body.version_number,
            "locked_at": now.isoformat(),
        },
    )

    result = await db.execute(
        select(ReportVersion)
        .options(selectinload(ReportVersion.author))
        .where(ReportVersion.id == target.id)
    )
    return _to_version_response(result.scalar_one())


async def diff_versions(
    db:           AsyncSession,
    report_id:    UUID,
    from_version: int,
    to_version:   int,
) -> ReportDiff:
    result = await db.execute(
        select(ReportVersion).where(
            ReportVersion.report_id == report_id,
            ReportVersion.version_number.in_([from_version, to_version]),
        )
    )
    versions = {v.version_number: v for v in result.scalars().all()}
    if from_version not in versions or to_version not in versions:
        raise HTTPException(status_code=404, detail="One or both versions not found")

    diff = "\n".join(difflib.unified_diff(
        versions[from_version].content.splitlines(),
        versions[to_version].content.splitlines(),
        fromfile=f"version {from_version}",
        tofile=f"version {to_version}",
        lineterm="",
    ))
    return ReportDiff(
        report_id=report_id,
        from_version=from_version,
        to_version=to_version,
        unified_diff=diff,
    )


# ─────────────────────────────────────────────────────────────────────────────
# VERIFY SERVICE — US-13 (Public, no auth)
# ─────────────────────────────────────────────────────────────────────────────

async def verify_hash(
    db:         AsyncSession,
    sha256:     str,
    ip_address: str,
) -> dict:
    """
    Public hash verification.
    Unknown hashes and sealed cases both return status='not_found' —
    indistinguishable by design to prevent enumeration (MC-07).
    """
    verified_at = datetime.now(timezone.utc)

    result = await db.execute(
        select(Evidence).where(Evidence.sha256_hash == sha256)
    )
    ev = result.scalar_one_or_none()

    await audit.log(
        db=db,
        action=AuditActionType.verify_hash_queried,
        resource_type="evidence",
        resource_id=sha256,
        ip_address=ip_address,
        actor_id=None,
        actor_role=None,
        detail={"found": ev is not None},
    )

    if not ev:
        return {
            "hash":        sha256,
            "status":      "not_found",
            "verified_at": verified_at,
        }

    # Count custody transfers
    custody_result = await db.execute(
        select(CustodyRecord).where(CustodyRecord.evidence_id == ev.id)
    )

    from models import CustodyRecord, Report, ReportVersion
    custody_count = len(custody_result.scalars().all())

    # Count report versions that reference this evidence
    report_count_result = await db.execute(
        select(ReportVersion).join(Report).where(
            Report.case_id == ev.case_id,
            Report.status == "court_ready",
        )
    )
    version_count = len(report_count_result.scalars().all())

    return {
        "hash":                   sha256,
        "status":                 ev.integrity_status,
        "first_registered_at":    ev.uploaded_at,
        "custody_transfer_count": custody_count,
        "case_number":            None,    # Redacted — never expose case details publicly
        "report_versions_count":  version_count,
        "verified_at":            verified_at,
    }


# ─────────────────────────────────────────────────────────────────────────────
# USER SERVICE — US-16
# ─────────────────────────────────────────────────────────────────────────────

async def list_users(
    db:        AsyncSession,
    role:      Optional[str] = None,
    is_active: Optional[bool] = None,
) -> list[UserProfile]:
    q = select(User)
    if role:
        q = q.where(User.role == role)
    if is_active is not None:
        q = q.where(User.is_active == is_active)
    result = await db.execute(q.order_by(User.created_at.desc()))
    return [to_profile(u) for u in result.scalars().all()]


async def update_user(
    db:         AsyncSession,
    user_id:    UUID,
    role:       Optional[str],
    is_active:  Optional[bool],
    full_name:  Optional[str],
    actor_id:   UUID,
    actor_role: str,
    ip_address: str,
) -> UserProfile:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    old_role = user.role

    if role:
        user.role = role
    if is_active is not None:
        user.is_active = is_active
    if full_name:
        user.full_name = full_name

    await db.flush()

    action = (
        AuditActionType.user_role_changed if role and role != old_role
        else AuditActionType.user_deactivated if is_active is False
        else AuditActionType.user_created
    )
    await audit.log(
        db=db, action=action,
        resource_type="user", resource_id=str(user_id),
        ip_address=ip_address, actor_id=actor_id, actor_role=actor_role,
        detail={"old_role": old_role, "new_role": role, "is_active": is_active},
    )
    return to_profile(user)

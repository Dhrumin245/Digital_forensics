"""
Custody, tasks, findings, reports, verify, users, audit, auth — fully implemented.
"""

from __future__ import annotations
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import Response
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import CurrentUser, UserRole, get_current_user, require_roles
from schemas import (
    AuditActionType, AuditEntry, AuditLogResponse,
    CreateReportRequest, CreateTaskRequest, CreateUserRequest,
    CustodyChainResponse, CustodyRecord,
    FindingResponse, HashImportResult,
    InitiateCustodyTransferRequest, LockReportRequest,
    LoginRequest, ReportDiff, ReportResponse,
    ReportSummaryResponse, ReportVersionResponse,
    SaveReportVersionRequest, TaskResponse,
    TokenResponse, UpdateTaskRequest, UpdateUserRequest,
    UserProfile, VerificationResult,
)
from services import auth_service
from services.custody_service import (
    accept_transfer, get_custody_chain, initiate_transfer, reject_transfer,
)
from services.remaining_services import (
    create_finding, create_report, create_task, diff_versions,
    list_findings, list_tasks, list_users, lock_report,
    save_version, update_task, update_user, verify_hash,
)

AuthUser   = Annotated[CurrentUser, Depends(get_current_user)]
CaseMgr    = Annotated[CurrentUser, Depends(require_roles(UserRole.case_manager))]
LabOrExam  = Annotated[CurrentUser, Depends(require_roles(UserRole.lab_technician, UserRole.examiner))]
ExamOnly   = Annotated[CurrentUser, Depends(require_roles(UserRole.examiner))]
LegalOnly  = Annotated[CurrentUser, Depends(require_roles(UserRole.legal_reviewer))]
AdminOnly  = Annotated[CurrentUser, Depends(require_roles(UserRole.admin))]


# ── AUTH ──────────────────────────────────────────────────────────────────────
router_auth = APIRouter()

@router_auth.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    try:
        return await auth_service.login(db, body.email, body.password)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid email or password")

@router_auth.get("/me", response_model=UserProfile)
async def me(current_user: AuthUser, db: AsyncSession = Depends(get_db)):
    user = await auth_service.get_user_by_id(db, current_user.user_id)
    return auth_service.to_profile(user)


# ── CUSTODY ───────────────────────────────────────────────────────────────────
router_custody = APIRouter()

@router_custody.get("/{case_id}/evidence/{evidence_id}/custody",
                    response_model=CustodyChainResponse,
                    summary="US-08 — Full chain of custody")
async def get_chain(case_id: UUID, evidence_id: UUID, current_user: AuthUser,
                    db: AsyncSession = Depends(get_db)):
    return await get_custody_chain(db, case_id, evidence_id)

@router_custody.post("/{case_id}/evidence/{evidence_id}/custody",
                     response_model=CustodyRecord, status_code=201,
                     summary="US-07 — Initiate custody transfer")
async def initiate(case_id: UUID, evidence_id: UUID, body: InitiateCustodyTransferRequest,
                   req: Request, current_user: LabOrExam, db: AsyncSession = Depends(get_db)):
    return await initiate_transfer(
        db, case_id, evidence_id, current_user.user_id,
        current_user.role.value, body, req.client.host,
    )

@router_custody.post("/{case_id}/evidence/{evidence_id}/custody/{transfer_id}/accept",
                     response_model=CustodyRecord,
                     summary="US-07 — Accept custody transfer")
async def accept(case_id: UUID, evidence_id: UUID, transfer_id: UUID,
                 req: Request, current_user: AuthUser, db: AsyncSession = Depends(get_db)):
    return await accept_transfer(
        db, case_id, evidence_id, transfer_id,
        current_user.user_id, current_user.role.value, req.client.host,
    )

@router_custody.post("/{case_id}/evidence/{evidence_id}/custody/{transfer_id}/reject",
                     response_model=CustodyRecord)
async def reject(case_id: UUID, evidence_id: UUID, transfer_id: UUID,
                 req: Request, current_user: AuthUser,
                 reason: str = Query(...), db: AsyncSession = Depends(get_db)):
    return await reject_transfer(
        db, case_id, evidence_id, transfer_id,
        current_user.user_id, current_user.role.value, reason, req.client.host,
    )


# ── TASKS ─────────────────────────────────────────────────────────────────────
router_tasks = APIRouter()

@router_tasks.get("/{case_id}/tasks", response_model=list[TaskResponse])
async def list_tasks_route(case_id: UUID, current_user: AuthUser,
                           assigned_to: UUID | None = None,
                           task_status: str | None = Query(default=None, alias="status"),
                           db: AsyncSession = Depends(get_db)):
    return await list_tasks(db, case_id, assigned_to, task_status)

@router_tasks.post("/{case_id}/tasks", response_model=TaskResponse, status_code=201,
                   summary="US-09 — Assign task to examiner")
async def create_task_route(case_id: UUID, body: CreateTaskRequest,
                            req: Request, current_user: CaseMgr,
                            db: AsyncSession = Depends(get_db)):
    return await create_task(
        db, case_id, body, current_user.user_id, current_user.role.value, req.client.host,
    )

@router_tasks.patch("/{case_id}/tasks/{task_id}", response_model=TaskResponse)
async def update_task_route(case_id: UUID, task_id: UUID, body: UpdateTaskRequest,
                            req: Request, current_user: AuthUser,
                            db: AsyncSession = Depends(get_db)):
    return await update_task(
        db, case_id, task_id, body,
        current_user.user_id, current_user.role.value, req.client.host,
    )


# ── FINDINGS ──────────────────────────────────────────────────────────────────
router_findings = APIRouter()

@router_findings.get("/{case_id}/tasks/{task_id}/findings", response_model=list[FindingResponse])
async def list_findings_route(case_id: UUID, task_id: UUID, current_user: AuthUser,
                              db: AsyncSession = Depends(get_db)):
    return await list_findings(db, task_id)

@router_findings.post("/{case_id}/tasks/{task_id}/findings",
                      response_model=FindingResponse, status_code=201,
                      summary="US-10 — Record a finding")
async def create_finding_route(
    case_id: UUID, task_id: UUID, req: Request, current_user: ExamOnly,
    db: AsyncSession = Depends(get_db),
    evidence_id: UUID = Form(...),
    title: str = Form(...),
    content: str = Form(...),
    attachments: list[UploadFile] = File(default=[]),
):
    attachment_data = [
        (a.filename or "attachment", await a.read(), a.content_type or "application/octet-stream")
        for a in attachments
    ]
    return await create_finding(
        db, case_id, task_id, evidence_id, title, content,
        current_user.user_id, current_user.role.value, req.client.host, attachment_data,
    )


# ── REPORTS ───────────────────────────────────────────────────────────────────
router_reports = APIRouter()

@router_reports.get("/{case_id}/reports", response_model=list[ReportSummaryResponse])
async def list_reports(case_id: UUID, current_user: AuthUser,
                       db: AsyncSession = Depends(get_db)):
    from models import Report
    result = await db.execute(select(Report).where(Report.case_id == case_id))
    from services.remaining_services import _to_summary
    return [_to_summary(r) for r in result.scalars().all()]

@router_reports.post("/{case_id}/reports", response_model=ReportSummaryResponse,
                     status_code=201, summary="US-11 — Create report (version 1)")
async def create_report_route(case_id: UUID, body: CreateReportRequest,
                              req: Request, current_user: ExamOnly,
                              db: AsyncSession = Depends(get_db)):
    return await create_report(
        db, case_id, body, current_user.user_id, current_user.role.value, req.client.host,
    )

@router_reports.post("/{case_id}/reports/{report_id}/versions",
                     response_model=ReportVersionResponse, status_code=201,
                     summary="US-11 — Save new immutable version")
async def save_version_route(case_id: UUID, report_id: UUID,
                             body: SaveReportVersionRequest,
                             req: Request, current_user: ExamOnly,
                             db: AsyncSession = Depends(get_db)):
    return await save_version(
        db, case_id, report_id, body,
        current_user.user_id, current_user.role.value, req.client.host,
    )

@router_reports.get("/{case_id}/reports/{report_id}/versions",
                    response_model=list[ReportVersionResponse],
                    summary="US-11 — List all versions")
async def list_versions(case_id: UUID, report_id: UUID, current_user: AuthUser,
                        db: AsyncSession = Depends(get_db)):
    from models import ReportVersion
    from sqlalchemy.orm import selectinload
    result = await db.execute(
        select(ReportVersion)
        .options(selectinload(ReportVersion.author))
        .where(ReportVersion.report_id == report_id)
        .order_by(ReportVersion.version_number.asc())
    )
    from services.remaining_services import _to_version_response
    return [_to_version_response(v) for v in result.scalars().all()]

@router_reports.get("/{case_id}/reports/{report_id}/versions/diff", response_model=ReportDiff)
async def diff_route(case_id: UUID, report_id: UUID, current_user: AuthUser,
                     from_version: int = Query(...), to_version: int = Query(...),
                     db: AsyncSession = Depends(get_db)):
    return await diff_versions(db, report_id, from_version, to_version)

@router_reports.post("/{case_id}/reports/{report_id}/lock",
                     response_model=ReportVersionResponse,
                     summary="US-12 — Lock report as court-ready")
async def lock_route(case_id: UUID, report_id: UUID, body: LockReportRequest,
                     req: Request, current_user: LegalOnly,
                     db: AsyncSession = Depends(get_db)):
    return await lock_report(
        db, case_id, report_id, body,
        current_user.user_id, current_user.role.value, req.client.host,
    )

@router_reports.post("/{case_id}/reports/{report_id}/pdf",
                     summary="US-14 — Generate verifiable court PDF")
async def generate_pdf(case_id: UUID, report_id: UUID,
                       req: Request, current_user: LegalOnly,
                       db: AsyncSession = Depends(get_db)):
    from models import Report, ReportVersion
    from sqlalchemy.orm import selectinload
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    import qrcode
    import io

    result = await db.execute(
        select(Report)
        .options(selectinload(Report.versions))
        .where(Report.id == report_id, Report.case_id == case_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    court_version = next((v for v in report.versions if v.is_court_ready), None)
    if not court_version:
        raise HTTPException(status_code=400, detail="No court-ready version exists for this report")

    # Generate PDF in memory
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 60, report.title)
    c.setFont("Helvetica", 11)
    c.drawString(50, height - 90, f"Court-ready version: {court_version.version_number}")
    c.drawString(50, height - 110, f"Locked at: {court_version.locked_at}")
    c.drawString(50, height - 130, f"Report ID: {report_id}")
    c.drawString(50, height - 150, f"Content hash (SHA-256):")
    c.setFont("Courier", 9)
    c.drawString(50, height - 165, court_version.content_hash)

    # QR code linking to verification portal
    verify_url = f"https://forensics.example.com/api/v1/verify/{court_version.content_hash}"
    qr = qrcode.QRCode(box_size=4, border=2)
    qr.add_data(verify_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_buffer = io.BytesIO()
    qr_img.save(qr_buffer, format="PNG")
    qr_buffer.seek(0)
    from reportlab.lib.utils import ImageReader
    c.drawImage(ImageReader(qr_buffer), 400, height - 220, width=120, height=120)

    c.setFont("Helvetica", 10)
    c.drawString(50, height - 210, "Verify authenticity:")
    c.drawString(50, height - 225, verify_url)

    # Report content
    c.setFont("Helvetica", 10)
    y = height - 280
    for line in court_version.content.splitlines():
        if y < 60:
            c.showPage()
            y = height - 60
        c.drawString(50, y, line[:100])
        y -= 14

    c.save()
    pdf_bytes = buffer.getvalue()
    pdf_hash  = auth_service.hash_password.__module__  # reuse hashlib
    from core.security import compute_sha256
    pdf_hash = compute_sha256(pdf_bytes)

    from core.audit import log as audit_log
    await audit_log(
        db=db, action=AuditActionType.report_pdf_generated,
        resource_type="report", resource_id=str(report_id),
        ip_address=req.client.host,
        actor_id=current_user.user_id, actor_role=current_user.role.value,
        detail={"version": court_version.version_number, "pdf_hash": pdf_hash},
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="report-{report_id}-v{court_version.version_number}.pdf"',
            "X-Report-Hash": pdf_hash,
        },
    )


# ── VERIFY (public) ───────────────────────────────────────────────────────────
router_verify = APIRouter()

@router_verify.get("/{hash}", response_model=VerificationResult,
                   summary="US-13 — Public hash verification")
async def verify_route(hash: str, req: Request, db: AsyncSession = Depends(get_db)):
    import re
    if not re.match(r"^[a-f0-9]{64}$", hash):
        raise HTTPException(status_code=400, detail="Hash must be 64 lowercase hex characters")
    result = await verify_hash(db, hash, req.client.host)
    return VerificationResult(**result)


# ── USERS ─────────────────────────────────────────────────────────────────────
router_users = APIRouter()

@router_users.get("", response_model=list[UserProfile])
async def list_users_route(current_user: AdminOnly,
                           role: str | None = None, is_active: bool | None = None,
                           db: AsyncSession = Depends(get_db)):
    return await list_users(db, role, is_active)

@router_users.post("", response_model=UserProfile, status_code=201,
                   summary="US-16 — Create user")
async def create_user_route(body: CreateUserRequest, req: Request,
                            current_user: AdminOnly, db: AsyncSession = Depends(get_db)):
    user = await auth_service.create_user(
        db, body.email, body.full_name, body.role.value, body.password,
    )
    from core.audit import log as audit_log
    await audit_log(
        db=db, action=AuditActionType.user_created,
        resource_type="user", resource_id=str(user.id),
        ip_address=req.client.host, actor_id=current_user.user_id,
        actor_role=current_user.role.value,
        detail={"email": body.email, "role": body.role.value},
    )
    return auth_service.to_profile(user)

@router_users.patch("/{user_id}", response_model=UserProfile,
                    summary="US-16 — Update user role or status")
async def update_user_route(user_id: UUID, body: UpdateUserRequest, req: Request,
                            current_user: AdminOnly, db: AsyncSession = Depends(get_db)):
    return await update_user(
        db, user_id,
        body.role.value if body.role else None,
        body.is_active, body.full_name,
        current_user.user_id, current_user.role.value, req.client.host,
    )


# ── AUDIT ─────────────────────────────────────────────────────────────────────
router_audit = APIRouter()

@router_audit.get("", response_model=AuditLogResponse,
                  summary="US-15 — Query immutable audit log")
async def query_audit(
    current_user: AdminOnly,
    actor_id: UUID | None = None,
    action_type: str | None = None,
    resource_id: str | None = None,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    page: int = 1,
    page_size: int = Query(default=50, le=200),
    db: AsyncSession = Depends(get_db),
):
    filters = ["1=1"]
    params: dict = {}
    if actor_id:
        filters.append("actor_id = :actor_id"); params["actor_id"] = str(actor_id)
    if action_type:
        filters.append("action_type = :action_type"); params["action_type"] = action_type
    if resource_id:
        filters.append("resource_id = :resource_id"); params["resource_id"] = resource_id
    if from_ts:
        filters.append("timestamp >= :from_ts"); params["from_ts"] = from_ts
    if to_ts:
        filters.append("timestamp <= :to_ts"); params["to_ts"] = to_ts

    where = " AND ".join(filters)
    total = (await db.execute(
        text(f"SELECT COUNT(*) FROM forensics_audit.audit_log WHERE {where}"), params
    )).scalar_one()

    rows = (await db.execute(
        text(f"""
            SELECT id, actor_id, actor_role, action_type, resource_type,
                   resource_id, ip_address, result, detail, timestamp
            FROM forensics_audit.audit_log WHERE {where}
            ORDER BY timestamp DESC
            LIMIT :limit OFFSET :offset
        """),
        {**params, "limit": page_size, "offset": (page - 1) * page_size},
    )).mappings().all()

    return AuditLogResponse(
        items=[AuditEntry(**dict(r)) for r in rows],
        total=total, page=page, page_size=page_size,
    )

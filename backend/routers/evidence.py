"""Evidence router — US-04, US-05, US-06"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import CurrentUser, UserRole, get_current_user, require_roles
from schemas import EvidenceResponse, EvidenceType, EvidenceWithIntegrityResponse, HashImportResult, IntegrityStatus
from services import evidence_service

router      = APIRouter()
AuthUser    = Annotated[CurrentUser, Depends(get_current_user)]
LabOnly     = Annotated[CurrentUser, Depends(require_roles(UserRole.lab_technician))]
CanDownload = Annotated[CurrentUser, Depends(
    require_roles(UserRole.lab_technician, UserRole.examiner, UserRole.case_manager)
)]


@router.post("/{case_id}/evidence", response_model=EvidenceResponse,
             status_code=status.HTTP_201_CREATED, summary="US-04 — Upload evidence file")
async def upload_evidence(
    case_id: UUID, req: Request, current_user: LabOnly,
    db: AsyncSession = Depends(get_db),
    file: UploadFile = File(...),
    description: str = Form(...),
    acquisition_notes: str | None = Form(default=None),
    evidence_type: EvidenceType = Form(default=EvidenceType.file),
):
    raw_bytes = await file.read()
    return await evidence_service.upload_evidence(
        db=db, case_id=case_id,
        uploader_id=current_user.user_id, uploader_role=current_user.role.value,
        raw_bytes=raw_bytes, filename=file.filename or "unknown",
        mime_type=file.content_type or "application/octet-stream",
        description=description, evidence_type=evidence_type,
        acquisition_notes=acquisition_notes, ip_address=req.client.host,
    )


@router.post("/{case_id}/evidence/import", response_model=HashImportResult,
             summary="US-05 — Import hashes from Autopsy/FTK")
async def import_hashes(
    case_id: UUID, req: Request, current_user: LabOnly,
    db: AsyncSession = Depends(get_db),
    file: UploadFile = File(...),
    acquisition_tool: str | None = Form(default=None),
    force_duplicates: bool = Query(default=False),
):
    content = await file.read()
    return await evidence_service.import_hashes(
        db=db, case_id=case_id,
        importer_id=current_user.user_id, importer_role=current_user.role.value,
        file_content=content, content_type=file.content_type or "",
        acquisition_tool=acquisition_tool, force_duplicates=force_duplicates,
        ip_address=req.client.host,
    )


@router.get("/{case_id}/evidence", response_model=list[EvidenceResponse])
async def list_evidence(
    case_id: UUID, current_user: AuthUser,
    integrity_status: IntegrityStatus | None = None,
    db: AsyncSession = Depends(get_db),
):
    return await evidence_service.list_evidence(
        db, case_id, current_user.user_id, current_user.role.value,
        integrity_status.value if integrity_status else None,
    )


@router.get("/{case_id}/evidence/{evidence_id}", response_model=EvidenceWithIntegrityResponse,
            summary="US-06 — Get evidence + live integrity check")
async def get_evidence(
    case_id: UUID, evidence_id: UUID, req: Request, current_user: AuthUser,
    db: AsyncSession = Depends(get_db),
):
    return await evidence_service.get_evidence_with_integrity(
        db, case_id, evidence_id, current_user.user_id, current_user.role.value, req.client.host,
    )


@router.get("/{case_id}/evidence/{evidence_id}/download",
            summary="Download evidence — triggers integrity check")
async def download_evidence(
    case_id: UUID, evidence_id: UUID, req: Request, current_user: CanDownload,
    db: AsyncSession = Depends(get_db),
):
    raw_bytes, filename, sha256 = await evidence_service.download_evidence(
        db, case_id, evidence_id, current_user.user_id, current_user.role.value, req.client.host,
    )
    return Response(
        content=raw_bytes,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Evidence-Hash": sha256,
            "X-Integrity-Status": "verified",
        },
    )

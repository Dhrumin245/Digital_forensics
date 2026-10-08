"""
Pydantic v2 schemas — mirrors the OpenAPI spec exactly.
All schemas are used for both request validation and response serialisation.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Optional, TypeAlias
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, StringConstraints, field_validator
import re


# ── Enums ─────────────────────────────────────────────────────────────────────


# ── Required free-text fields ────────────────────────────────────────────────
# Trim surrounding whitespace, then require at least one character, so that
# "" and "   " are both rejected (a blank custody reason or review note would
# defeat the purpose of recording one).
def _required_text(max_len: int):
    return Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=max_len)]

Text200: TypeAlias  = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
Text300: TypeAlias  = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300)]
Text500: TypeAlias  = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]
Text1000: TypeAlias = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]
Text2000: TypeAlias = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]


class UserRole(str, Enum):
    case_manager    = "CaseManager"
    lab_technician  = "LabTechnician"
    examiner        = "Examiner"
    legal_reviewer  = "LegalReviewer"
    admin           = "Admin"
    public_verifier = "PublicVerifier"


class CaseStatus(str, Enum):
    open     = "open"
    active   = "active"
    closed   = "closed"
    archived = "archived"

    @classmethod
    def is_valid_transition(cls, from_status: "CaseStatus", to_status: "CaseStatus") -> bool:
        _VALID = {"open": ["active"], "active": ["closed"], "closed": ["archived"]}
        return to_status.value in _VALID.get(from_status.value, [])


class EvidenceType(str, Enum):
    disk_image      = "disk_image"
    file            = "file"
    memory_dump     = "memory_dump"
    log_file        = "log_file"
    network_capture = "network_capture"
    mobile_backup   = "mobile_backup"
    other           = "other"


class IntegrityStatus(str, Enum):
    verified = "verified"
    tampered = "tampered"
    pending  = "pending"
    unknown  = "unknown"


class TaskStatus(str, Enum):
    assigned    = "assigned"
    in_progress = "in_progress"
    completed   = "completed"
    reviewed    = "reviewed"


class CustodyTransferStatus(str, Enum):
    pending  = "pending"
    accepted = "accepted"
    rejected = "rejected"


class ReportStatus(str, Enum):
    draft         = "draft"
    under_review  = "under_review"
    court_ready   = "court_ready"


class AuditActionType(str, Enum):
    case_created           = "case.created"
    case_updated           = "case.updated"
    case_status_changed    = "case.status_changed"
    user_assigned          = "user.assigned_to_case"
    user_removed           = "user.removed_from_case"
    evidence_uploaded      = "evidence.uploaded"
    evidence_accessed      = "evidence.accessed"
    evidence_downloaded    = "evidence.downloaded"
    tamper_detected        = "evidence.tamper_detected"
    hash_imported          = "hash.imported"
    custody_initiated      = "custody.transfer_initiated"
    custody_accepted       = "custody.transfer_accepted"
    custody_rejected       = "custody.transfer_rejected"
    task_created           = "task.created"
    task_status_changed    = "task.status_changed"
    finding_created        = "finding.created"
    report_created         = "report.created"
    report_version_saved   = "report.version_saved"
    report_locked          = "report.locked"
    report_pdf_generated   = "report.pdf_generated"
    user_created           = "user.created"
    user_role_changed      = "user.role_changed"
    user_deactivated       = "user.deactivated"
    verify_hash_queried    = "verify.hash_queried"


# ── Helpers ───────────────────────────────────────────────────────────────────

SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def validate_sha256(v: str) -> str:
    if not SHA256_PATTERN.match(v):
        raise ValueError("Must be a 64-character lowercase hex SHA-256 string")
    return v


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int = 900


# ── Users ─────────────────────────────────────────────────────────────────────

class UserProfile(BaseModel):
    id:            UUID
    email:         EmailStr
    full_name:     str
    role:          UserRole
    is_active:     bool
    created_at:    datetime
    last_login_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class CreateUserRequest(BaseModel):
    email:     EmailStr
    full_name: Text200
    role:      UserRole
    password:  str = Field(min_length=12)


class UpdateUserRequest(BaseModel):
    role:      Optional[UserRole] = None
    is_active: Optional[bool]    = None
    full_name: Optional[str]     = None


# ── Cases ─────────────────────────────────────────────────────────────────────

class CreateCaseRequest(BaseModel):
    title:            Text300
    description:      Optional[str] = Field(default=None, max_length=2000)
    reference_number: Optional[str] = Field(default=None, max_length=100)


class UpdateCaseRequest(BaseModel):
    title:         Optional[str]        = Field(default=None, max_length=300)
    description:   Optional[str]        = Field(default=None, max_length=2000)
    status:        Optional[CaseStatus] = None
    status_reason: Optional[str]        = Field(default=None, max_length=500)


class CaseResponse(BaseModel):
    id:               UUID
    case_number:      str
    title:            str
    description:      Optional[str]
    status:           CaseStatus
    created_by:       UUID
    created_at:       datetime
    updated_at:       datetime
    evidence_count:   int = 0
    assignment_count: int = 0

    model_config = {"from_attributes": True}


class CaseListResponse(BaseModel):
    items:     list[CaseResponse]
    total:     int
    page:      int
    page_size: int


class AssignUserRequest(BaseModel):
    user_id: UUID


class CaseAssignment(BaseModel):
    id:          UUID
    case_id:     UUID
    user_id:     UUID
    user:        UserProfile
    assigned_by: UUID
    assigned_at: datetime

    model_config = {"from_attributes": True}


# ── Evidence ──────────────────────────────────────────────────────────────────

class EvidenceResponse(BaseModel):
    id:                   UUID
    case_id:              UUID
    filename:             str
    file_size_bytes:      int
    mime_type:            str
    evidence_type:        EvidenceType
    sha256_hash:          str
    hash_source:          str  # "computed" | "imported"
    acquisition_tool:     Optional[str]
    description:          str
    acquisition_notes:    Optional[str]
    uploaded_by:          UUID
    uploaded_at:          datetime
    current_custodian_id: Optional[UUID]
    integrity_status:     IntegrityStatus

    model_config = {"from_attributes": True}


class IntegrityCheckDetail(BaseModel):
    checked_at:      datetime
    stored_hash:     str
    recomputed_hash: str
    match:           bool
    alert_raised:    bool


class EvidenceWithIntegrityResponse(EvidenceResponse):
    integrity_check: IntegrityCheckDetail


class HashImportRowResult(BaseModel):
    row:      int
    filename: str
    status:   str  # "imported" | "duplicate" | "error" | "skipped"
    message:  Optional[str] = None


class HashImportResult(BaseModel):
    total_rows:  int
    imported:    int
    skipped:     int
    errors:      int
    duplicates:  int
    row_results: list[HashImportRowResult]


# ── Custody ───────────────────────────────────────────────────────────────────

class InitiateCustodyTransferRequest(BaseModel):
    to_user_id:      UUID
    transfer_reason: Text1000


class CustodyRecord(BaseModel):
    id:                UUID
    evidence_id:       UUID
    from_user_id:      UUID
    to_user_id:        UUID
    from_user:         UserProfile
    to_user:           UserProfile
    transfer_reason:   str
    hash_at_transfer:  str   # SHA-256 re-verified at moment of transfer
    status:            CustodyTransferStatus
    initiated_at:      datetime
    accepted_at:       Optional[datetime] = None
    from_signature:    str
    to_signature:      Optional[str] = None

    model_config = {"from_attributes": True}


class CustodyChainGap(BaseModel):
    from_ts: datetime
    to_ts:   datetime


class CustodyChainResponse(BaseModel):
    evidence_id:     UUID
    chain_complete:  bool
    gaps:            list[CustodyChainGap]
    records:         list[CustodyRecord]


# ── Tasks ─────────────────────────────────────────────────────────────────────

class CreateTaskRequest(BaseModel):
    title:                 Text300
    description:           Optional[str] = Field(default=None, max_length=2000)
    assigned_to_user_id:   UUID
    evidence_ids:          list[UUID] = Field(min_length=1)
    due_date:              Optional[datetime] = None


class UpdateTaskRequest(BaseModel):
    status:      Optional[TaskStatus] = None
    title:       Optional[str]        = None
    description: Optional[str]        = None
    due_date:    Optional[datetime]   = None


class TaskResponse(BaseModel):
    id:          UUID
    case_id:     UUID
    title:       str
    description: Optional[str]
    assigned_to: UserProfile
    assigned_by: UUID
    status:      TaskStatus
    evidence_ids: list[UUID]
    due_date:    Optional[datetime]
    created_at:  datetime
    updated_at:  datetime

    model_config = {"from_attributes": True}


# ── Findings ──────────────────────────────────────────────────────────────────

class FindingAttachment(BaseModel):
    id:          UUID
    filename:    str
    sha256_hash: str
    size_bytes:  int


class FindingResponse(BaseModel):
    id:          UUID
    task_id:     UUID
    evidence_id: UUID
    title:       str
    content:     str   # Markdown
    attachments: list[FindingAttachment]
    created_by:  UUID
    created_at:  datetime

    model_config = {"from_attributes": True}


# ── Reports ───────────────────────────────────────────────────────────────────

class CreateReportRequest(BaseModel):
    title:   Text300
    content: str   # Markdown for version 1


class SaveReportVersionRequest(BaseModel):
    content:        str
    change_summary: Text500


class ReportVersionResponse(BaseModel):
    report_id:      UUID
    version_number: int
    content:        str
    content_hash:   str   # SHA-256 computed server-side
    author_id:      UUID
    author:         UserProfile
    saved_at:       datetime
    change_summary: str
    is_court_ready: bool
    locked_by:      Optional[UUID]     = None
    locked_at:      Optional[datetime] = None
    review_notes:   Optional[str]      = None

    model_config = {"from_attributes": True}


class ReportSummaryResponse(BaseModel):
    id:                  UUID
    case_id:             UUID
    title:               str
    status:              ReportStatus
    latest_version:      int
    court_ready_version: Optional[int] = None
    created_by:          UUID
    created_at:          datetime
    updated_at:          datetime

    model_config = {"from_attributes": True}


class ReportResponse(ReportSummaryResponse):
    current_version_content: str
    linked_evidence_ids:     list[UUID]
    linked_finding_ids:      list[UUID]


class ReportDiff(BaseModel):
    report_id:    UUID
    from_version: int
    to_version:   int
    unified_diff: str


class LockReportRequest(BaseModel):
    version_number: int
    review_notes:   Text2000


# ── Verify ────────────────────────────────────────────────────────────────────

class VerificationResult(BaseModel):
    hash:                   str
    status:                 str   # "verified" | "tampered" | "not_found"
    first_registered_at:    Optional[datetime] = None
    custody_transfer_count: Optional[int]      = None
    case_number:            Optional[str]      = None
    report_versions_count:  Optional[int]      = None
    verified_at:            datetime


# ── Audit ─────────────────────────────────────────────────────────────────────

class AuditEntry(BaseModel):
    id:            UUID
    actor_id:      Optional[UUID]
    actor_role:    Optional[UserRole]
    action_type:   AuditActionType
    resource_type: str
    resource_id:   str
    ip_address:    str
    result:        str   # "success" | "failure" | "blocked"
    detail:        dict[str, Any]
    timestamp:     datetime

    model_config = {"from_attributes": True}


class AuditLogResponse(BaseModel):
    items:     list[AuditEntry]
    total:     int
    page:      int
    page_size: int


# ── Errors ────────────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    error:   str
    message: str
    detail:  Optional[dict[str, Any]] = None

"""
test_http.py — HTTP-layer integration tests (Phase 6)

Uses FastAPI's TestClient with mocked DB sessions and storage.
Tests the complete request/response cycle for every endpoint group.

These run without a live database — all DB calls are intercepted
by AsyncMock and return controlled fixture data.

Run:
    pytest tests/test_http.py -v --tb=short
"""

from __future__ import annotations

import hashlib
import io
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import sys
sys.path.insert(0, ".")

from core.security import UserRole


# ── Shared fixtures ───────────────────────────────────────────────────────────

ADMIN_ID    = uuid.uuid4()
MANAGER_ID  = uuid.uuid4()
LAB_ID      = uuid.uuid4()
EXAMINER_ID = uuid.uuid4()
LEGAL_ID    = uuid.uuid4()
CASE_ID     = uuid.uuid4()
EVIDENCE_ID = uuid.uuid4()

KNOWN_HASH  = hashlib.sha256(b"test evidence content").hexdigest()

# JWT tokens for each role (real tokens signed by test keys, or mocked)
def make_token(user_id: uuid.UUID, role: str) -> str:
    """Return a minimal Bearer token that the mock auth will accept."""
    return f"test-token-{role.lower()}-{str(user_id)[:8]}"


def auth(role: str, uid: uuid.UUID | None = None) -> dict:
    uid = uid or uuid.uuid4()
    return {"Authorization": f"Bearer {make_token(uid, role)}"}


def mock_current_user(user_id: uuid.UUID, role: str):
    """CurrentUser object injected by require_roles dependency override."""
    from core.security import CurrentUser, UserRole
    return CurrentUser(user_id=user_id, role=UserRole(role), email=f"{role.lower()}@example.com")


from contextlib import contextmanager

@contextmanager
def as_role(role):
    """Temporarily authenticate app_client requests as `role`, restoring
    the fixture's Admin default afterwards (app_client is module-scoped,
    so overrides must not leak between tests)."""
    from main import app
    from core.security import get_current_user
    app.dependency_overrides[get_current_user] = lambda: mock_current_user(uuid.uuid4(), role)
    try:
        yield
    finally:
        app.dependency_overrides[get_current_user] = lambda: mock_current_user(ADMIN_ID, "Admin")


# ── App fixture with dependency overrides ─────────────────────────────────────

@pytest.fixture(scope="module")
def app_client():
    """
    TestClient with all auth and DB dependencies overridden.
    Yields the client and a dict of mocks for per-test customisation.
    """
    from main import app
    from core.database import get_db
    from core.security import get_current_user

    # Shared mock DB session
    mock_db = AsyncMock()

    def override_db():
        yield mock_db

    # Default: authenticated as Admin
    def override_auth():
        return mock_current_user(ADMIN_ID, "Admin")

    app.dependency_overrides[get_db]           = override_db
    app.dependency_overrides[get_current_user] = override_auth

    # main.py's lifespan calls create_tables() directly against the real DB
    # engine at startup — bypass that for tests, the same reason get_db is
    # overridden above doesn't cover it (this call isn't a route dependency).
    with patch("main.create_tables", new_callable=AsyncMock):
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client, mock_db

    app.dependency_overrides.clear()


# ═══════════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════════
class TestHealth:
    def test_health_returns_200(self, app_client):
        client, _ = app_client
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_health_returns_version(self, app_client):
        client, _ = app_client
        r = client.get("/health")
        assert "version" in r.json()


# ═══════════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ═══════════════════════════════════════════════════════════════════
class TestAuthEndpoints:

    def test_login_with_valid_credentials(self, app_client):
        client, mock_db = app_client
        with patch("services.auth_service.login") as mock_login:
            mock_login.return_value = {"access_token": "tok", "refresh_token": "rtok", "token_type": "bearer"}
            r = client.post("/api/v1/auth/login", json={
                "email": "admin@forensicslab.example.com",
                "password": "Admin@123!"
            })
        assert r.status_code == 200
        assert r.json()["access_token"] == "tok"

    def test_login_missing_email_returns_422(self, app_client):
        client, _ = app_client
        r = client.post("/api/v1/auth/login", json={"password": "pass"})
        assert r.status_code == 422

    def test_login_missing_password_returns_422(self, app_client):
        client, _ = app_client
        r = client.post("/api/v1/auth/login", json={"email": "admin@test.com"})
        assert r.status_code == 422

    def test_login_empty_body_returns_422(self, app_client):
        client, _ = app_client
        r = client.post("/api/v1/auth/login", json={})
        assert r.status_code == 422


# ═══════════════════════════════════════════════════════════════════
# CASE ENDPOINTS  (US-01, US-02, US-03)
# ═══════════════════════════════════════════════════════════════════
class TestCaseEndpoints:

    def test_get_cases_returns_200(self, app_client):
        client, mock_db = app_client
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute.return_value = mock_result

        with patch("services.case_service.list_cases") as mock_svc:
            mock_svc.return_value = {"items": [], "total": 0, "page": 1, "page_size": 20}
            r = client.get("/api/v1/cases")
        assert r.status_code == 200
        assert isinstance(r.json()["items"], list)

    def test_create_case_us01_returns_201(self, app_client):
        client, mock_db = app_client
        from schemas import CaseResponse, CaseStatus
        mock_case = MagicMock()
        mock_case.id           = CASE_ID
        mock_case.case_number  = "CASE-2024-00001"
        mock_case.title        = "Test Investigation"
        mock_case.description  = "A test"
        mock_case.status       = CaseStatus.open
        mock_case.created_by   = ADMIN_ID
        mock_case.created_at   = datetime.now(timezone.utc)
        mock_case.updated_at   = datetime.now(timezone.utc)
        mock_case.evidence_count   = 0
        mock_case.assignment_count = 0

        with as_role(UserRole.case_manager):
            with patch("services.case_service.create_case") as mock_svc:
                mock_svc.return_value = mock_case
                r = client.post("/api/v1/cases", json={
                    "title": "Test Investigation",
                    "description": "A test"
                })
        assert r.status_code in (200, 201)

    def test_create_case_missing_title_returns_422(self, app_client):
        client, _ = app_client
        with as_role(UserRole.case_manager):
            r = client.post("/api/v1/cases", json={"description": "No title"})
        assert r.status_code == 422

    def test_get_case_not_found_returns_404(self, app_client):
        client, mock_db = app_client
        with patch("services.case_service.get_case") as mock_svc:
            from fastapi import HTTPException
            mock_svc.side_effect = HTTPException(status_code=404, detail="Not found")
            r = client.get(f"/api/v1/cases/{uuid.uuid4()}")
        assert r.status_code == 404

    def test_update_case_us03_invalid_transition_returns_409(self, app_client):
        client, _ = app_client
        with as_role(UserRole.case_manager):
            with patch("services.case_service.update_case") as mock_svc:
                from fastapi import HTTPException
                mock_svc.side_effect = HTTPException(
                    status_code=409, detail="Invalid transition: open → archived"
                )
                r = client.patch(f"/api/v1/cases/{CASE_ID}", json={"status": "archived"})
        assert r.status_code == 409

    def test_assign_user_us02_returns_201(self, app_client):
        client, _ = app_client
        target_user_id = uuid.uuid4()
        from schemas import CaseAssignment, UserProfile
        mock_assignment = CaseAssignment(
            id=uuid.uuid4(), case_id=CASE_ID, user_id=target_user_id,
            user=UserProfile(id=target_user_id, email="examiner@forensicslab.example.com",
                             full_name="Examiner", role="Examiner", is_active=True,
                             created_at=datetime.now(timezone.utc)),
            assigned_by=uuid.uuid4(), assigned_at=datetime.now(timezone.utc),
        )
        with as_role(UserRole.case_manager):
            with patch("services.case_service.assign_user") as mock_svc:
                mock_svc.return_value = mock_assignment
                r = client.post(
                    f"/api/v1/cases/{CASE_ID}/assignments",
                    json={"user_id": str(target_user_id)}
                )
        assert r.status_code in (200, 201)


# ═══════════════════════════════════════════════════════════════════
# EVIDENCE ENDPOINTS  (US-04, US-05, US-06)
# ═══════════════════════════════════════════════════════════════════
class TestEvidenceEndpoints:

    def test_get_evidence_list_returns_200(self, app_client):
        client, _ = app_client
        with patch("services.evidence_service.list_evidence") as mock_svc:
            mock_svc.return_value = []
            r = client.get(f"/api/v1/cases/{CASE_ID}/evidence")
        assert r.status_code == 200

    def test_upload_evidence_us04_requires_file(self, app_client):
        """US-04 — POST without a file should return 422."""
        client, _ = app_client
        with as_role(UserRole.lab_technician):
            r = client.post(
                f"/api/v1/cases/{CASE_ID}/evidence",
                data={"description": "missing file", "evidence_type": "file"}
            )
        assert r.status_code == 422

    def test_upload_evidence_us04_with_file(self, app_client):
        """US-04 — Upload a file; service computes SHA-256 server-side."""
        client, _ = app_client
        mock_ev = MagicMock()
        mock_ev.id               = EVIDENCE_ID
        mock_ev.filename         = "test.dd"
        mock_ev.sha256_hash      = KNOWN_HASH
        mock_ev.integrity_status = "verified"
        mock_ev.file_size_bytes  = 19
        mock_ev.mime_type        = "application/octet-stream"
        mock_ev.evidence_type    = "file"
        mock_ev.hash_source      = "computed"
        mock_ev.uploaded_at      = datetime.now(timezone.utc)
        mock_ev.description      = "Test file"
        mock_ev.case_id          = CASE_ID
        mock_ev.uploaded_by      = ADMIN_ID
        mock_ev.current_custodian_id = ADMIN_ID
        mock_ev.acquisition_tool = None
        mock_ev.acquisition_notes = None

        with as_role(UserRole.lab_technician):
            with patch("services.evidence_service.upload_evidence") as mock_svc:
                mock_svc.return_value = mock_ev
                r = client.post(
                    f"/api/v1/cases/{CASE_ID}/evidence",
                    files={"file": ("test.dd", b"test evidence content", "application/octet-stream")},
                    data={"description": "Test file", "evidence_type": "file"}
                )
        assert r.status_code in (200, 201)

    def test_get_evidence_us06_tampered_returns_423(self, app_client):
        """US-06 — Accessing tampered evidence must return 423 Locked."""
        client, _ = app_client
        with patch("services.evidence_service.get_evidence_with_integrity") as mock_svc:
            from fastapi import HTTPException
            mock_svc.side_effect = HTTPException(
                status_code=423,
                detail="Evidence integrity check failed — file may have been tampered with"
            )
            r = client.get(f"/api/v1/cases/{CASE_ID}/evidence/{EVIDENCE_ID}")
        assert r.status_code == 423

    def test_get_evidence_us06_valid_returns_200_with_hash(self, app_client):
        """US-06 — Valid evidence access returns evidence with sha256_hash field."""
        client, _ = app_client
        from schemas import EvidenceWithIntegrityResponse, IntegrityCheckDetail
        mock_response = EvidenceWithIntegrityResponse(
            id=EVIDENCE_ID,
            filename="disk.dd",
            sha256_hash=KNOWN_HASH,
            integrity_status="verified",
            file_size_bytes=1024,
            mime_type="application/octet-stream",
            evidence_type="disk_image",
            hash_source="computed",
            uploaded_at=datetime.now(timezone.utc),
            description="Disk image",
            case_id=CASE_ID,
            uploaded_by=LAB_ID,
            current_custodian_id=EXAMINER_ID,
            acquisition_tool="Autopsy",
            acquisition_notes=None,
            integrity_check=IntegrityCheckDetail(
                checked_at=datetime.now(timezone.utc),
                stored_hash=KNOWN_HASH,
                recomputed_hash=KNOWN_HASH,
                match=True,
                alert_raised=False,
            ),
        )

        with as_role(UserRole.examiner):
            with patch("services.evidence_service.get_evidence_with_integrity") as mock_svc:
                mock_svc.return_value = mock_response
                r = client.get(f"/api/v1/cases/{CASE_ID}/evidence/{EVIDENCE_ID}")
        assert r.status_code == 200
        body = r.json()
        assert "sha256_hash" in body
        assert len(body["sha256_hash"]) == 64


# ═══════════════════════════════════════════════════════════════════
# CUSTODY ENDPOINTS  (US-07, US-08)
# ═══════════════════════════════════════════════════════════════════
class TestCustodyEndpoints:

    def test_get_custody_chain_us08_returns_200(self, app_client):
        client, _ = app_client
        with patch("routers.remaining_routers.get_custody_chain") as mock_svc:
            mock_svc.return_value = {
                "evidence_id": str(EVIDENCE_ID),
                "records": [],
                "chain_complete": True,
                "gaps": []
            }
            r = client.get(
                f"/api/v1/cases/{CASE_ID}/evidence/{EVIDENCE_ID}/custody"
            )
        assert r.status_code == 200

    def test_initiate_transfer_us07_missing_body_returns_422(self, app_client):
        client, _ = app_client
        with as_role(UserRole.lab_technician):
            r = client.post(
                f"/api/v1/cases/{CASE_ID}/evidence/{EVIDENCE_ID}/custody",
                json={}
            )
        assert r.status_code == 422

    def test_initiate_transfer_us07_returns_201(self, app_client):
        client, _ = app_client
        from schemas import CustodyRecord, UserProfile
        mock_rec = CustodyRecord(
            id=uuid.uuid4(), evidence_id=EVIDENCE_ID,
            from_user_id=LAB_ID, to_user_id=EXAMINER_ID,
            from_user=UserProfile(id=LAB_ID, email="lab@example.com", full_name="Lab Tech",
                                  role="LabTechnician", is_active=True,
                                  created_at=datetime.now(timezone.utc)),
            to_user=UserProfile(id=EXAMINER_ID, email="examiner@example.com", full_name="Examiner",
                                role="Examiner", is_active=True,
                                created_at=datetime.now(timezone.utc)),
            transfer_reason="Analysis required", hash_at_transfer=KNOWN_HASH,
            status="pending", initiated_at=datetime.now(timezone.utc),
            accepted_at=None, from_signature="sig", to_signature=None,
        )

        with as_role(UserRole.lab_technician):
            with patch("routers.remaining_routers.initiate_transfer") as mock_svc:
                mock_svc.return_value = mock_rec
                r = client.post(
                    f"/api/v1/cases/{CASE_ID}/evidence/{EVIDENCE_ID}/custody",
                    json={
                        "to_user_id": str(EXAMINER_ID),
                        "transfer_reason": "Analysis required"
                    }
                )
        assert r.status_code in (200, 201)

    def test_accept_transfer_us07_returns_200(self, app_client):
        client, _ = app_client
        transfer_id = uuid.uuid4()
        from schemas import CustodyRecord, UserProfile
        accepted_rec = CustodyRecord(
            id=transfer_id, evidence_id=EVIDENCE_ID,
            from_user_id=LAB_ID, to_user_id=EXAMINER_ID,
            from_user=UserProfile(id=LAB_ID, email="lab@example.com", full_name="Lab Tech",
                                  role="LabTechnician", is_active=True,
                                  created_at=datetime.now(timezone.utc)),
            to_user=UserProfile(id=EXAMINER_ID, email="examiner@example.com", full_name="Examiner",
                                role="Examiner", is_active=True,
                                created_at=datetime.now(timezone.utc)),
            transfer_reason="Analysis required", hash_at_transfer=KNOWN_HASH,
            status="accepted", initiated_at=datetime.now(timezone.utc),
            accepted_at=datetime.now(timezone.utc), from_signature="sig", to_signature="sig2",
        )

        with as_role(UserRole.examiner):
            with patch("routers.remaining_routers.accept_transfer") as mock_svc:
                mock_svc.return_value = accepted_rec
                r = client.post(
                    f"/api/v1/cases/{CASE_ID}/evidence/{EVIDENCE_ID}/custody/{transfer_id}/accept"
                )
        assert r.status_code in (200, 201)


# ═══════════════════════════════════════════════════════════════════
# VERIFY ENDPOINT  (US-13)
# ═══════════════════════════════════════════════════════════════════
class TestVerifyEndpoint:
    """US-13 — Public hash verification portal. No auth required."""

    def test_verify_valid_hash_format_returns_200(self, app_client):
        client, _ = app_client
        with patch("routers.remaining_routers.verify_hash") as mock_svc:
            mock_svc.return_value = {
                "hash": KNOWN_HASH,
                "status": "not_found",
                "verified_at": datetime.now(timezone.utc).isoformat()
            }
            r = client.get(f"/api/v1/verify/{KNOWN_HASH}")
        assert r.status_code == 200
        body = r.json()
        assert body["hash"]   == KNOWN_HASH
        assert body["status"] in ("verified", "not_found", "tampered")

    def test_verify_invalid_hash_format_returns_400(self, app_client):
        """Invalid hash format should be rejected before hitting the service."""
        client, _ = app_client
        bad_hashes = [
            "abc",
            "A" * 64,        # uppercase
            "z" * 64,        # invalid hex chars
                "short",
        ]
        for bad in bad_hashes:
            r = client.get(f"/api/v1/verify/{bad}")
            assert r.status_code == 400, f"Expected 400 for hash: {bad!r}"

    def test_verify_requires_no_auth(self, app_client):
        """US-13 — No Authorization header must still return a valid response."""
        client, _ = app_client
        with patch("routers.remaining_routers.verify_hash") as mock_svc:
            mock_svc.return_value = {
                "hash": KNOWN_HASH,
                "status": "not_found",
                "verified_at": datetime.now(timezone.utc).isoformat()
            }
            # No auth header
            r = client.get(
                f"/api/v1/verify/{KNOWN_HASH}",
                headers={}
            )
        assert r.status_code == 200

    def test_verify_unknown_hash_returns_not_found(self, app_client):
        """MC-07 — Unknown hashes must return not_found, not 404."""
        client, _ = app_client
        unknown = "b" * 64
        with patch("routers.remaining_routers.verify_hash") as mock_svc:
            mock_svc.return_value = {
                "hash": unknown,
                "status": "not_found",
                "verified_at": datetime.now(timezone.utc).isoformat()
            }
            r = client.get(f"/api/v1/verify/{unknown}")
        # Must be 200 OK — not 404
        assert r.status_code == 200
        assert r.json()["status"] == "not_found"


# ═══════════════════════════════════════════════════════════════════
# REPORTS  (US-11, US-12)
# ═══════════════════════════════════════════════════════════════════
class TestReportEndpoints:

    def test_list_reports_returns_200(self, app_client):
        client, _ = app_client
        with patch("routers.remaining_routers.list_reports") as mock_svc:
            mock_svc.return_value = []
            r = client.get(f"/api/v1/cases/{CASE_ID}/reports")
        assert r.status_code == 200

    def test_save_version_us11_returns_201(self, app_client):
        client, _ = app_client
        report_id = uuid.uuid4()
        from schemas import ReportVersionResponse, UserProfile
        mock_version = ReportVersionResponse(
            report_id=report_id, version_number=2,
            content="# Report\n\nFindings...", content_hash=KNOWN_HASH,
            author_id=EXAMINER_ID,
            author=UserProfile(id=EXAMINER_ID, email="examiner@forensicslab.example.com",
                               full_name="Examiner", role="Examiner", is_active=True,
                               created_at=datetime.now(timezone.utc)),
            saved_at=datetime.now(timezone.utc), change_summary="Added findings",
            is_court_ready=False,
        )

        with as_role(UserRole.examiner):
            with patch("routers.remaining_routers.save_version") as mock_svc:
                mock_svc.return_value = mock_version
                r = client.post(
                    f"/api/v1/cases/{CASE_ID}/reports/{report_id}/versions",
                    json={"content": "# Report\n\nFindings...", "change_summary": "Added findings"}
                )
        assert r.status_code in (200, 201)

    def test_lock_report_us12_by_non_legal_reviewer_returns_403(self, app_client):
        """US-12 — Only LegalReviewer can lock a report."""
        client, _ = app_client
        report_id = uuid.uuid4()
        with patch("routers.remaining_routers.lock_report") as mock_svc:
            from fastapi import HTTPException
            mock_svc.side_effect = HTTPException(
                status_code=403,
                detail="Only LegalReviewer can lock a report"
            )
            r = client.post(
                f"/api/v1/cases/{CASE_ID}/reports/{report_id}/lock",
                json={"version_number": 3, "review_notes": "Approved"}
            )
        assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════
# AUDIT LOG  (US-15)
# ═══════════════════════════════════════════════════════════════════
class TestAuditEndpoints:

    def test_get_audit_log_us15_returns_200(self, app_client):
        client, _ = app_client
        with patch("routers.remaining_routers.query_audit") as mock_svc:
            mock_svc.return_value = []
            r = client.get("/api/v1/audit")
        assert r.status_code == 200

    def test_audit_log_filters_accepted(self, app_client):
        client, _ = app_client
        with patch("routers.remaining_routers.query_audit") as mock_svc:
            mock_svc.return_value = []
            r = client.get("/api/v1/audit?action_type=evidence.uploaded&limit=10")
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════
# USERS  (US-16)
# ═══════════════════════════════════════════════════════════════════
class TestUserEndpoints:

    def test_list_users_returns_200(self, app_client):
        client, _ = app_client
        with patch("routers.remaining_routers.list_users") as mock_svc:
            mock_svc.return_value = []
            r = client.get("/api/v1/users")
        assert r.status_code == 200

    def test_create_user_returns_201(self, app_client):
        client, _ = app_client
        mock_user = MagicMock()
        mock_user.id         = uuid.uuid4()
        mock_user.email      = "new@forensicslab.example.com"   # .local is a reserved TLD — rejected by email-validator
        mock_user.full_name  = "New User"
        mock_user.role       = "Examiner"
        mock_user.is_active  = True
        mock_user.created_at = datetime.now(timezone.utc)
        mock_user.last_login_at = None

        with patch("services.auth_service.create_user") as mock_svc:
            mock_svc.return_value = mock_user
            r = client.post("/api/v1/users", json={
                "email": "new@forensicslab.example.com",
                "full_name": "New User",
                "role": "Examiner",
                "password": "SecurePass@123!"
            })
        assert r.status_code in (200, 201)

    def test_create_user_missing_required_fields_returns_422(self, app_client):
        client, _ = app_client
        r = client.post("/api/v1/users", json={"email": "only@email.com"})
        assert r.status_code == 422

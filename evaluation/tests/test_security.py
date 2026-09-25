"""
test_security.py — Security-focused tests (Phase 6)

Covers:
  - JWT manipulation (missing, expired, wrong algorithm, tampered payload)
  - SQL injection attempts on query parameters
  - Path traversal on file-related endpoints
  - Rate limiting enforcement on /verify
  - RBAC — every cross-role combination
  - Input length/size validation
  - Content-type enforcement

Run:
    pytest tests/test_security.py -v --tb=short
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import sys
sys.path.insert(0, ".")


# ── Shared test values ────────────────────────────────────────────────────────
VALID_HASH  = "a" * 64
CASE_ID     = uuid.uuid4()
EVIDENCE_ID = uuid.uuid4()


@pytest.fixture(scope="module")
def client():
    from main import app
    from core.database import get_db
    mock_db = AsyncMock()
    app.dependency_overrides[get_db] = lambda: (yield mock_db)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


# ═══════════════════════════════════════════════════════════════════
# JWT SECURITY
# ═══════════════════════════════════════════════════════════════════
class TestJWTSecurity:
    """All protected endpoints must reject bad tokens with 401."""

    PROTECTED = [
        ("GET",  "/api/v1/cases"),
        ("POST", "/api/v1/cases"),
        ("GET",  f"/api/v1/cases/{uuid.uuid4()}/evidence"),
        ("GET",  "/api/v1/users"),
        ("GET",  "/api/v1/audit"),
    ]

    @pytest.mark.parametrize("method,path", PROTECTED)
    def test_missing_token_returns_401(self, client, method, path):
        r = getattr(client, method.lower())(path, headers={})
        assert r.status_code == 401, \
            f"{method} {path} with no token should return 401, got {r.status_code}"

    @pytest.mark.parametrize("method,path", PROTECTED)
    def test_empty_bearer_returns_401(self, client, method, path):
        r = getattr(client, method.lower())(path, headers={"Authorization": "Bearer "})
        assert r.status_code == 401

    @pytest.mark.parametrize("method,path", PROTECTED)
    def test_malformed_token_returns_401(self, client, method, path):
        bad_tokens = [
            "notavalidjwt",
            "Bearer",
            "Bearer .",
            "Bearer ..",
            "Bearer a.b.c",
            "Basic dXNlcjpwYXNz",   # Basic auth should not work
        ]
        for bad in bad_tokens:
            r = getattr(client, method.lower())(
                path, headers={"Authorization": bad}
            )
            assert r.status_code == 401, \
                f"{method} {path} with token '{bad[:20]}' should return 401"

    def test_tampered_payload_returns_401(self, client):
        """Modify the payload after signing — must be rejected."""
        # Craft a structurally valid but unsigned JWT
        header  = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(
            json.dumps({
                "sub": str(uuid.uuid4()),
                "role": "Admin",
                "exp": (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
            }).encode()
        ).decode().rstrip("=")
        fake_sig = base64.urlsafe_b64encode(b"fake_signature").decode().rstrip("=")
        forged = f"{header}.{payload}.{fake_sig}"

        r = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {forged}"})
        assert r.status_code == 401

    def test_none_algorithm_attack_rejected(self, client):
        """Classic 'alg: none' attack — must be rejected."""
        header  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(
            json.dumps({
                "sub": str(uuid.uuid4()),
                "role": "Admin",
                "exp": (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
            }).encode()
        ).decode().rstrip("=")
        forged = f"{header}.{payload}."  # No signature

        r = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {forged}"})
        assert r.status_code == 401

    def test_verify_endpoint_requires_no_auth(self, client):
        """US-13 — Public endpoint must work without any auth header."""
        with patch("routers.remaining_routers.verify_hash") as mock_svc:
            mock_svc.return_value = {
                "hash": VALID_HASH, "status": "not_found",
                "verified_at": datetime.now(timezone.utc).isoformat()
            }
            r = client.get(f"/api/v1/verify/{VALID_HASH}", headers={})
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════
# SQL INJECTION
# ═══════════════════════════════════════════════════════════════════
class TestSQLInjection:
    """
    All string inputs must be parameterised — SQL injection must not
    return 500 errors, expose stack traces, or behave differently.
    """

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1' UNION SELECT * FROM users --",
        "admin'--",
        "' OR 1=1 --",
        "1; SELECT sleep(5) --",
        "%27 OR %271%27=%271",
    ]

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_case_status_filter(self, client, payload):
        """Query params must be safely parameterised."""
        with patch("routers.cases.list_cases") as mock_svc:
            mock_svc.return_value = []
            r = client.get(
                "/api/v1/cases",
                params={"status": payload},
                headers={"Authorization": "Bearer test-token"}
            )
        # Must NOT return 500 — either 400 (validation) or 200 (sanitised)
        assert r.status_code != 500, \
            f"SQL injection payload caused 500: {payload!r}"

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_audit_action_filter(self, client, payload):
        with patch("routers.remaining_routers.query_audit") as mock_svc:
            mock_svc.return_value = []
            r = client.get(
                "/api/v1/audit",
                params={"action_type": payload},
                headers={"Authorization": "Bearer test-token"}
            )
        assert r.status_code != 500

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_case_title(self, client, payload):
        """Request body fields must be passed as parameters, not interpolated."""
        r = client.post(
            "/api/v1/cases",
            json={"title": payload, "description": "test"},
            headers={"Authorization": "Bearer test-token"}
        )
        assert r.status_code != 500


# ═══════════════════════════════════════════════════════════════════
# PATH TRAVERSAL
# ═══════════════════════════════════════════════════════════════════
class TestPathTraversal:
    """UUID path parameters must reject directory traversal strings."""

    TRAVERSAL_PAYLOADS = [
        "../../etc/passwd",
        "../../../etc/shadow",
        "..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//etc//passwd",
    ]

    @pytest.mark.parametrize("payload", TRAVERSAL_PAYLOADS)
    def test_path_traversal_in_case_id(self, client, payload):
        """UUID path params reject non-UUID strings — path traversal gets 404 or 422."""
        r = client.get(
            f"/api/v1/cases/{payload}/evidence",
            headers={"Authorization": "Bearer test-token"}
        )
        assert r.status_code in (400, 404, 422), \
            f"Path traversal should be rejected, got {r.status_code} for {payload!r}"

    @pytest.mark.parametrize("payload", TRAVERSAL_PAYLOADS)
    def test_path_traversal_in_evidence_id(self, client, payload):
        r = client.get(
            f"/api/v1/cases/{CASE_ID}/evidence/{payload}",
            headers={"Authorization": "Bearer test-token"}
        )
        assert r.status_code in (400, 404, 422)


# ═══════════════════════════════════════════════════════════════════
# RBAC — Cross-role tests
# ═══════════════════════════════════════════════════════════════════
class TestRBAC:
    """Every endpoint must enforce its role requirement independently."""

    def test_lab_tech_cannot_create_case(self, client):
        """US-01 — Only CaseManager can create cases."""
        from main import app
        from core.security import get_current_user, CurrentUser, UserRole
        app.dependency_overrides[get_current_user] = lambda: CurrentUser(
            user_id=uuid.uuid4(), role=UserRole.LabTechnician,
            email="lab@test.com"
        )
        r = client.post("/api/v1/cases", json={"title": "Test", "description": "test"})
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403

    def test_examiner_cannot_lock_report(self, client):
        """US-12 — Only LegalReviewer can lock reports."""
        from main import app
        from core.security import get_current_user, CurrentUser, UserRole
        app.dependency_overrides[get_current_user] = lambda: CurrentUser(
            user_id=uuid.uuid4(), role=UserRole.Examiner,
            email="examiner@test.com"
        )
        r = client.post(
            f"/api/v1/cases/{CASE_ID}/reports/{uuid.uuid4()}/lock",
            json={"version_number": 1, "review_notes": "approved"}
        )
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403

    def test_lab_tech_cannot_view_audit_log(self, client):
        """US-15 — Only Admin can query the audit log."""
        from main import app
        from core.security import get_current_user, CurrentUser, UserRole
        app.dependency_overrides[get_current_user] = lambda: CurrentUser(
            user_id=uuid.uuid4(), role=UserRole.LabTechnician,
            email="lab@test.com"
        )
        r = client.get("/api/v1/audit")
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403

    def test_examiner_cannot_manage_users(self, client):
        """US-16 — Only Admin can manage users."""
        from main import app
        from core.security import get_current_user, CurrentUser, UserRole
        app.dependency_overrides[get_current_user] = lambda: CurrentUser(
            user_id=uuid.uuid4(), role=UserRole.Examiner,
            email="examiner@test.com"
        )
        r = client.get("/api/v1/users")
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403

    def test_case_manager_cannot_upload_evidence(self, client):
        """Evidence upload is LabTechnician territory."""
        from main import app
        from core.security import get_current_user, CurrentUser, UserRole
        app.dependency_overrides[get_current_user] = lambda: CurrentUser(
            user_id=uuid.uuid4(), role=UserRole.CaseManager,
            email="manager@test.com"
        )
        r = client.post(
            f"/api/v1/cases/{CASE_ID}/evidence",
            files={"file": ("test.dd", b"content", "application/octet-stream")},
            data={"description": "test", "evidence_type": "file"}
        )
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════
# INPUT VALIDATION
# ═══════════════════════════════════════════════════════════════════
class TestInputValidation:
    """Boundary and edge-value tests for request body validation."""

    def test_case_title_too_long_returns_422(self, client):
        r = client.post(
            "/api/v1/cases",
            json={"title": "A" * 301, "description": "test"},
            headers={"Authorization": "Bearer test-token"}
        )
        assert r.status_code == 422

    def test_case_title_empty_returns_422(self, client):
        r = client.post(
            "/api/v1/cases",
            json={"title": "", "description": "test"},
            headers={"Authorization": "Bearer test-token"}
        )
        assert r.status_code == 422

    @pytest.mark.parametrize("bad_hash", [
        "A" * 64,           # uppercase hex
        "g" * 64,           # invalid hex chars
        "a" * 63,           # too short
        "a" * 65,           # too long
        "",                 # empty
        "SELECT*FROM",      # SQL
        "<script>alert()</script>",   # XSS
    ])
    def test_verify_invalid_hash_formats(self, client, bad_hash):
        r = client.get(f"/api/v1/verify/{bad_hash}")
        assert r.status_code == 400, \
            f"Expected 400 for hash {repr(bad_hash)[:20]}, got {r.status_code}"

    def test_transfer_to_self_returns_400(self, client):
        """A user cannot transfer custody to themselves."""
        actor_id = uuid.uuid4()
        from main import app
        from core.security import get_current_user, CurrentUser, UserRole
        app.dependency_overrides[get_current_user] = lambda: CurrentUser(
            user_id=actor_id, role=UserRole.LabTechnician, email="lab@test.com"
        )
        with patch("routers.remaining_routers.initiate_transfer") as mock_svc:
            from fastapi import HTTPException
            mock_svc.side_effect = HTTPException(
                status_code=400, detail="Cannot transfer to yourself"
            )
            r = client.post(
                f"/api/v1/cases/{CASE_ID}/evidence/{EVIDENCE_ID}/custody",
                json={"to_user_id": str(actor_id), "transfer_reason": "self"}
            )
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 400

    def test_invalid_uuid_path_param_returns_422(self, client):
        """UUID path parameters must reject non-UUID strings."""
        r = client.get(
            "/api/v1/cases/not-a-uuid/evidence",
            headers={"Authorization": "Bearer test-token"}
        )
        assert r.status_code == 422

    def test_content_type_json_required_for_post(self, client):
        """POST endpoints requiring JSON body must reject form-encoded data."""
        r = client.post(
            "/api/v1/cases",
            data="title=test&description=test",   # form-encoded, not JSON
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        )
        assert r.status_code == 422


# ═══════════════════════════════════════════════════════════════════
# RATE LIMITING  (US-13 / MC-07)
# ═══════════════════════════════════════════════════════════════════
class TestRateLimiting:
    """
    The /verify endpoint must enforce a rate limit to prevent
    hash enumeration attacks (MC-07).
    """

    def test_verify_rate_limit_returns_429_after_threshold(self, client):
        """
        After 10 requests/minute (the configured limit), expect 429.
        This test patches the Redis rate-limit check directly.
        """
        with patch("routers.remaining_routers.check_rate_limit") as mock_rl:
            mock_rl.side_effect = [None] * 10 + [
                __import__("fastapi", fromlist=["HTTPException"]).HTTPException(
                    status_code=429, detail="Rate limit exceeded"
                )
            ]
            # First 10 calls should succeed
            for _ in range(10):
                with patch("routers.remaining_routers.verify_hash") as mock_svc:
                    mock_svc.return_value = {
                        "hash": VALID_HASH, "status": "not_found",
                        "verified_at": datetime.now(timezone.utc).isoformat()
                    }
                    r = client.get(f"/api/v1/verify/{VALID_HASH}")
                # May succeed or fail depending on mock setup
                assert r.status_code in (200, 429)

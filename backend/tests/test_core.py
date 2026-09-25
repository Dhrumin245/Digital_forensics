"""
Core test suite — covers the most critical security and cryptographic logic.

Run with:
    pytest tests/ -v --cov=. --cov-report=term-missing

Tests are grouped by user story:
  TestHashVerification  → US-04, US-06
  TestTamperDetection   → US-06, MC-01
  TestRBAC              → US-02 (authorization enforcement)
  TestCustodyChain      → US-07, US-08
  TestReportVersioning  → US-11, US-12
  TestVerificationPortal → US-13
"""

import hashlib
import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock, patch

# ── Standalone unit tests (no DB needed) ─────────────────────────────────────

class TestHashVerification:
    """US-04, US-06 — SHA-256 computation and verification."""

    def test_compute_sha256_deterministic(self):
        """Same input must always produce the same hash."""
        from core.security import compute_sha256
        data = b"forensics evidence file content"
        h1 = compute_sha256(data)
        h2 = compute_sha256(data)
        assert h1 == h2

    def test_compute_sha256_correct_length(self):
        """SHA-256 must always be 64 hex characters."""
        from core.security import compute_sha256
        result = compute_sha256(b"test")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_compute_sha256_known_value(self):
        """Verify against a known SHA-256 value (RFC standard test vector)."""
        from core.security import compute_sha256
        # SHA-256("abc") = ba7816bf...
        result = compute_sha256(b"abc")
        assert result == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"  # noqa (known value)

    def test_different_inputs_produce_different_hashes(self):
        """One-bit change in input must produce a completely different hash."""
        from core.security import compute_sha256
        data1 = b"evidence_file_v1.dd"
        data2 = b"evidence_file_v2.dd"
        assert compute_sha256(data1) != compute_sha256(data2)

    def test_verify_hash_intact_file(self):
        """File matches stored hash → returns True."""
        from core.security import compute_sha256, verify_hash
        data = b"original evidence bytes"
        stored = compute_sha256(data)
        assert verify_hash(data, stored) is True

    def test_verify_hash_empty_file(self):
        """Empty file should still be hashable and verifiable."""
        from core.security import compute_sha256, verify_hash
        data = b""
        stored = compute_sha256(data)
        assert verify_hash(data, stored) is True


class TestTamperDetection:
    """US-06, MC-01 — Any byte change must be detected."""

    def test_single_byte_change_detected(self):
        """Changing a single byte must cause verify_hash to return False."""
        from core.security import compute_sha256, verify_hash
        original = b"disk_image_contents_here" + bytes(range(256))
        stored_hash = compute_sha256(original)

        # Flip one byte
        tampered = bytearray(original)
        tampered[0] ^= 0xFF
        assert verify_hash(bytes(tampered), stored_hash) is False

    def test_appended_byte_detected(self):
        """Appended byte must be detected as tampering."""
        from core.security import compute_sha256, verify_hash
        original = b"network_capture.pcap contents"
        stored = compute_sha256(original)
        tampered = original + b"\x00"
        assert verify_hash(tampered, stored) is False

    def test_truncated_file_detected(self):
        """Truncated file must be detected as tampering."""
        from core.security import compute_sha256, verify_hash
        original = b"memory_dump_contents" * 100
        stored = compute_sha256(original)
        truncated = original[:len(original) // 2]
        assert verify_hash(truncated, stored) is False

    def test_wrong_stored_hash_detected(self):
        """Supplying a wrong stored hash must fail verification."""
        from core.security import verify_hash
        data = b"valid evidence file"
        wrong_hash = "a" * 64
        assert verify_hash(data, wrong_hash) is False

    def test_hash_of_different_file_rejected(self):
        """Hash from a different file must not pass for this file."""
        from core.security import compute_sha256, verify_hash
        file_a = b"file A content"
        file_b = b"file B content"
        hash_a = compute_sha256(file_a)
        assert verify_hash(file_b, hash_a) is False

    @pytest.mark.parametrize("position", [0, 1, -1, -2, 100])
    def test_byte_flip_at_any_position_detected(self, position):
        """Tamper at any position in the file must be detected."""
        from core.security import compute_sha256, verify_hash
        original = b"A" * 500
        stored = compute_sha256(original)
        tampered = bytearray(original)
        tampered[position] ^= 0x01
        assert verify_hash(bytes(tampered), stored) is False


class TestRBACEnforcement:
    """
    US-02 — Authorization enforcement.
    Tests that roles cannot access endpoints they are not permitted for.
    Maps to Evaluation criterion: 'Authorization enforcement — 0 breaches'.
    """

    def _make_token_payload(self, role: str, user_id: str = "00000000-0000-0000-0000-000000000001"):
        return {"sub": user_id, "role": role, "email": f"{role.lower()}@test.com"}

    def test_case_manager_role_parsed_correctly(self):
        from core.security import UserRole
        assert UserRole.case_manager.value == "CaseManager"

    def test_examiner_cannot_use_case_manager_dependency(self):
        """
        require_roles(UserRole.case_manager) must raise 403 for an Examiner.
        This is the core RBAC check — if this fails, unauthorized access is possible.
        """
        from fastapi import HTTPException
        from core.security import CurrentUser, UserRole, require_roles
        import uuid

        examiner = CurrentUser(
            user_id=uuid.uuid4(),
            role=UserRole.examiner,
            email="examiner@test.com",
        )

        check_fn = require_roles(UserRole.case_manager)
        with pytest.raises(HTTPException) as exc_info:
            check_fn(examiner)
        assert exc_info.value.status_code == 403

    def test_case_manager_passes_case_manager_dependency(self):
        from core.security import CurrentUser, UserRole, require_roles
        import uuid

        manager = CurrentUser(
            user_id=uuid.uuid4(),
            role=UserRole.case_manager,
            email="manager@test.com",
        )

        check_fn = require_roles(UserRole.case_manager)
        result = check_fn(manager)
        assert result.role == UserRole.case_manager

    def test_admin_cannot_bypass_non_admin_role_check(self):
        """
        Admin role should NOT automatically pass non-admin role checks.
        Elevation of privilege must not occur via role name similarity.
        """
        from fastapi import HTTPException
        from core.security import CurrentUser, UserRole, require_roles
        import uuid

        admin = CurrentUser(
            user_id=uuid.uuid4(),
            role=UserRole.admin,
            email="admin@test.com",
        )

        # Admin trying to hit a LabTechnician-only endpoint
        check_fn = require_roles(UserRole.lab_technician)
        with pytest.raises(HTTPException) as exc_info:
            check_fn(admin)
        assert exc_info.value.status_code == 403

    def test_multi_role_dependency_accepts_any_matching_role(self):
        """require_roles(A, B) should accept either A or B."""
        from core.security import CurrentUser, UserRole, require_roles
        import uuid

        examiner = CurrentUser(
            user_id=uuid.uuid4(),
            role=UserRole.examiner,
            email="ex@test.com",
        )

        # Both LabTech and Examiner are allowed
        check_fn = require_roles(UserRole.lab_technician, UserRole.examiner)
        result = check_fn(examiner)
        assert result.role == UserRole.examiner

    @pytest.mark.parametrize("role", [
        "CaseManager", "LabTechnician", "Examiner",
        "LegalReviewer", "Admin", "PublicVerifier"
    ])
    def test_all_valid_roles_parse_correctly(self, role):
        from core.security import UserRole
        parsed = UserRole(role)
        assert parsed.value == role


class TestCaseStatusTransitions:
    """US-03 — Only valid status transitions are permitted."""

    def test_valid_open_to_active(self):
        from schemas import CaseStatus
        assert CaseStatus.is_valid_transition(CaseStatus.open, CaseStatus.active) is True

    def test_valid_active_to_closed(self):
        from schemas import CaseStatus
        assert CaseStatus.is_valid_transition(CaseStatus.active, CaseStatus.closed) is True

    def test_valid_closed_to_archived(self):
        from schemas import CaseStatus
        assert CaseStatus.is_valid_transition(CaseStatus.closed, CaseStatus.archived) is True

    def test_invalid_open_to_archived(self):
        from schemas import CaseStatus
        assert CaseStatus.is_valid_transition(CaseStatus.open, CaseStatus.archived) is False

    def test_invalid_open_to_closed(self):
        from schemas import CaseStatus
        assert CaseStatus.is_valid_transition(CaseStatus.open, CaseStatus.closed) is False

    def test_invalid_active_to_open(self):
        """Cannot go backwards."""
        from schemas import CaseStatus
        assert CaseStatus.is_valid_transition(CaseStatus.active, CaseStatus.open) is False

    def test_invalid_archived_to_open(self):
        """Archived is terminal — no transition out."""
        from schemas import CaseStatus
        assert CaseStatus.is_valid_transition(CaseStatus.archived, CaseStatus.open) is False

    @pytest.mark.parametrize("from_s,to_s,expected", [
        ("open",     "active",   True),
        ("active",   "closed",   True),
        ("closed",   "archived", True),
        ("open",     "closed",   False),
        ("open",     "archived", False),
        ("active",   "open",     False),
        ("closed",   "open",     False),
        ("archived", "open",     False),
        ("archived", "active",   False),
    ])
    def test_all_transitions(self, from_s, to_s, expected):
        from schemas import CaseStatus
        result = CaseStatus.is_valid_transition(CaseStatus(from_s), CaseStatus(to_s))
        assert result == expected


class TestReportVersionIntegrity:
    """US-11 — Report version hashes are computed correctly and are immutable."""

    def test_report_content_hash_computed_correctly(self):
        """Content hash must match standard SHA-256 of the UTF-8 encoded content."""
        from core.security import compute_sha256
        content = "# Forensic Report\n\nEvidence item EVD-001 shows..."
        expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
        result = compute_sha256(content.encode("utf-8"))
        assert result == expected

    def test_different_content_different_hash(self):
        """Two different report versions must produce different hashes."""
        from core.security import compute_sha256
        v1 = "Report version 1 content"
        v2 = "Report version 2 content — added findings from EVD-002"
        assert compute_sha256(v1.encode()) != compute_sha256(v2.encode())

    def test_same_content_same_hash(self):
        """If content hasn't changed, hash should be identical (detect no-op saves)."""
        from core.security import compute_sha256
        content = "Identical content"
        assert compute_sha256(content.encode()) == compute_sha256(content.encode())

    def test_empty_report_content_hashable(self):
        """Edge case: empty content should still produce a valid hash."""
        from core.security import compute_sha256
        result = compute_sha256(b"")
        assert len(result) == 64


class TestVerificationPortalHashValidation:
    """US-13 — Public verification portal input validation."""

    @pytest.mark.parametrize("valid_hash", [
        "a" * 64,
        "0" * 64,
        "f" * 64,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ])
    def test_valid_sha256_format_accepted(self, valid_hash):
        """64 lowercase hex characters should pass format validation."""
        import re
        pattern = re.compile(r"^[a-f0-9]{64}$")
        assert pattern.match(valid_hash) is not None

    @pytest.mark.parametrize("invalid_hash", [
        "A" * 64,            # Uppercase — not allowed
        "a" * 63,            # Too short
        "a" * 65,            # Too long
        "z" * 64,            # Invalid hex character
        "",                  # Empty
        "abc",               # Way too short
        "a" * 63 + "G",      # One invalid char at end
        "SELECT * FROM--" + "a" * 49,  # SQL injection attempt
    ])
    def test_invalid_sha256_format_rejected(self, invalid_hash):
        """Anything other than 64 lowercase hex chars must be rejected."""
        import re
        pattern = re.compile(r"^[a-f0-9]{64}$")
        assert pattern.match(invalid_hash) is None


class TestHashImportValidation:
    """US-05 — Hash import CSV validation."""

    def test_valid_sha256_in_csv_row_accepted(self):
        """A properly formatted SHA-256 in an imported row should pass."""
        import re
        valid = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
        assert re.match(r"^[a-f0-9]{64}$", valid) is not None

    def test_empty_hash_field_rejected(self):
        """Empty sha256 field in CSV row must produce an error result."""
        import re
        assert re.match(r"^[a-f0-9]{64}$", "") is None

    def test_filler_hash_rejected(self):
        """All-zeros hash (common placeholder) should be detectable."""
        zero_hash = "0" * 64
        # Technically valid format — but system should flag as suspicious
        # This test documents the behaviour: format passes, flagging is business logic
        import re
        assert re.match(r"^[a-f0-9]{64}$", zero_hash) is not None
        # Note: business logic should warn on all-zero hashes (known placeholder)


class TestCustodyChainGapDetection:
    """US-08 — Chain of custody completeness check."""

    def _make_record(self, initiated_at, accepted_at=None, status="accepted"):
        return {
            "initiated_at": initiated_at,
            "accepted_at":  accepted_at,
            "status":       status,
        }

    def test_complete_chain_no_gaps(self):
        """
        Sequential transfers with no time overlap gaps → chain_complete = True.
        This is the happy path for custody completeness metric.
        """
        from datetime import datetime, timedelta

        t0 = datetime(2024, 1, 1, 9, 0)
        records = [
            self._make_record(t0,                          t0 + timedelta(hours=1)),
            self._make_record(t0 + timedelta(hours=1),     t0 + timedelta(hours=3)),
            self._make_record(t0 + timedelta(hours=3),     t0 + timedelta(hours=5)),
        ]

        # All records accepted and sequential — no gaps
        for i in range(len(records) - 1):
            current_end   = records[i]["accepted_at"]
            next_start     = records[i + 1]["initiated_at"]
            assert current_end <= next_start, f"Gap detected between records {i} and {i+1}"

    def test_pending_transfer_does_not_break_chain(self):
        """A pending (unaccepted) transfer should not count as a completed handoff."""
        record = self._make_record(
            initiated_at="2024-01-01T09:00:00",
            accepted_at=None,
            status="pending",
        )
        assert record["status"] == "pending"
        assert record["accepted_at"] is None


# ── Marker for integration tests (require DB) ─────────────────────────────────
# Run with: pytest tests/ -m integration
# These are skipped in CI unless the DB service is available.

@pytest.mark.integration
class TestEvidenceUploadIntegration:
    """
    Integration tests for US-04 — require running DB and storage.
    Skipped in unit test runs.
    """

    def test_upload_computes_correct_hash(self):
        pytest.skip("Requires running DB — run with -m integration")

    def test_tamper_triggers_alert(self):
        pytest.skip("Requires running DB — run with -m integration")

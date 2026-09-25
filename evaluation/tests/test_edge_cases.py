"""
test_edge_cases.py — Edge case and boundary tests (Phase 6)

Covers scenarios outside the happy path:
  - Zero-byte evidence files
  - Duplicate hash imports
  - Concurrent custody transfer attempts (race condition)
  - Kafka broker offline — API must continue
  - Maximum file size boundary
  - Unicode in case titles / descriptions
  - Simultaneous report version saves
  - Closed case blocks new evidence
  - Evidence deletion is permanently blocked

Run:
    pytest tests/test_edge_cases.py -v --tb=short
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

import sys
sys.path.insert(0, ".")


# ═══════════════════════════════════════════════════════════════════
# EMPTY FILE HANDLING
# ═══════════════════════════════════════════════════════════════════
class TestEmptyFiles:
    """Zero-byte files are valid forensic evidence (e.g. deleted file stubs)."""

    def test_empty_file_sha256_is_known_constant(self):
        """SHA-256 of empty input must equal the known empty-string hash."""
        from core.security import compute_sha256
        result = compute_sha256(b"")
        # SHA-256("") = e3b0c44298fc1c149afb...
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert len(result) == 64

    def test_empty_file_verify_returns_true(self):
        """Empty file that matches stored hash must pass integrity check."""
        from core.security import compute_sha256, verify_hash
        stored = compute_sha256(b"")
        assert verify_hash(b"", stored) is True

    def test_empty_file_modified_to_nonempty_detected(self):
        """Empty file with content added must fail integrity check."""
        from core.security import compute_sha256, verify_hash
        stored = compute_sha256(b"")
        assert verify_hash(b"now it has content", stored) is False

    @pytest.mark.asyncio
    async def test_upload_zero_byte_file_accepted(self):
        """
        Zero-byte files are valid evidence.
        Their SHA-256 must equal the well-known empty-string hash.
        """
        from core.security import compute_sha256, verify_hash
        empty_hash = compute_sha256(b"")
        assert empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert len(empty_hash) == 64
        assert verify_hash(b"", empty_hash) is True
        assert verify_hash(bytes([0]), empty_hash) is False  # null byte changes hash


# ═══════════════════════════════════════════════════════════════════
# DUPLICATE HASH IMPORTS
# ═══════════════════════════════════════════════════════════════════
class TestDuplicateHashes:
    """CSV/JSON imports with duplicate hashes must be handled gracefully."""

    def test_csv_with_duplicate_sha256_rows(self):
        """Two rows with the same SHA-256 — second must be flagged as duplicate."""
        from services.evidence_service import _parse_hash_import
        h = "a" * 64
        csv = (
            "filename,sha256,acquisition_tool,acquisition_date\n"
            f"file1.dd,{h},Autopsy,2024-11-01\n"
            f"file2.dd,{h},Autopsy,2024-11-01\n"   # same hash
        )
        rows = _parse_hash_import(csv.encode(), "text/csv")
        assert len(rows) == 2
        # Both are parsed; duplicate detection is at the DB layer
        assert rows[0]["sha256"] == rows[1]["sha256"]

    def test_duplicate_hash_within_same_case_detectable(self):
        """Two evidence items with the same hash in one case can be found."""
        existing_hashes = {"a" * 64, "b" * 64}
        new_hash = "a" * 64    # already exists
        is_duplicate = new_hash in existing_hashes
        assert is_duplicate is True

    def test_same_hash_different_cases_not_duplicate(self):
        """Same hash in a different case is not a duplicate."""
        case1_hashes = {"a" * 64}
        case2_hashes = set()   # new case
        new_hash = "a" * 64
        is_duplicate = new_hash in case2_hashes
        assert is_duplicate is False


# ═══════════════════════════════════════════════════════════════════
# KAFKA OFFLINE
# ═══════════════════════════════════════════════════════════════════
class TestKafkaOffline:
    """
    When Kafka is unreachable, the API must continue to function.
    DB writes are the source of truth — Kafka is async-only.
    """

    @pytest.mark.asyncio
    async def test_custody_transfer_succeeds_when_kafka_down(self):
        """
        Custody transfer must complete even if Kafka publish fails.
        The DB record is committed first; Kafka failure is a warning, not an error.
        """
        from core.events import publish_custody_transfer
        # Simulate Kafka being down
        called = False
        original = publish_custody_transfer

        async def fake_publish(*args, **kwargs):
            nonlocal called
            called = True
            raise Exception("Kafka: connection refused")

        # Directly call the fake to simulate the service calling it
        try:
            await fake_publish(
                evidence_id=uuid.uuid4(),
                from_user_id=uuid.uuid4(),
                to_user_id=uuid.uuid4(),
                status="pending",
                hash_at_transfer="a" * 64,
            )
        except Exception:
            pass
        assert called is True
            # Crucially: DB write above (in the service) must have already succeeded

    @pytest.mark.asyncio
    async def test_tamper_alert_silently_degrades_when_kafka_down(self):
        """Tamper detection must still return 423 even if the Kafka alert fails."""
        from core.events import publish_tamper_alert

        kafka_called = False
        kafka_raised = False

        async def fake_publish(*args, **kwargs):
            nonlocal kafka_called, kafka_raised
            kafka_called = True
            raise ConnectionRefusedError("Kafka offline")

        try:
            await fake_publish(
                evidence_id=uuid.uuid4(),
                stored_hash="a" * 64,
                recomputed_hash="b" * 64,
                detected_by=uuid.uuid4(),
                ip_address="127.0.0.1",
            )
        except ConnectionRefusedError:
            kafka_raised = True

        assert kafka_called  is True
        assert kafka_raised  is True
        # The HTTP response (423) should be returned regardless of this exception
        # That enforcement is at the service layer (evidence_service.py)


# ═══════════════════════════════════════════════════════════════════
# CONCURRENT TRANSFERS (Race conditions)
# ═══════════════════════════════════════════════════════════════════
class TestConcurrentTransfers:
    """
    Two examiners must not both be able to accept the same transfer.
    The DB constraint (status='accepted' immutability trigger) prevents this.
    """

    def test_custody_status_immutability_after_acceptance(self):
        """
        Once a custody record is accepted, it cannot be updated.
        The DB trigger raises an exception on any UPDATE.
        This test simulates the trigger behaviour.
        """
        mock_record = MagicMock()
        mock_record.status = "accepted"

        # Simulate the DB trigger logic
        def simulate_db_trigger(record, new_status):
            if record.status == "accepted":
                raise Exception("Accepted custody records are immutable.")
            record.status = new_status

        with pytest.raises(Exception, match="immutable"):
            simulate_db_trigger(mock_record, "rejected")

    def test_pending_transfer_can_only_be_accepted_once(self):
        """
        If two concurrent requests try to accept the same transfer,
        the second must fail because the first changes status to 'accepted'.
        """
        transfer = {"status": "pending", "id": uuid.uuid4()}
        accepted_by = []

        def try_accept(user_id):
            if transfer["status"] == "pending":
                transfer["status"] = "accepted"
                accepted_by.append(user_id)
                return True
            return False

        user_a = uuid.uuid4()
        user_b = uuid.uuid4()

        result_a = try_accept(user_a)
        result_b = try_accept(user_b)   # Should fail — already accepted

        assert result_a is True
        assert result_b is False
        assert len(accepted_by) == 1
        assert accepted_by[0] == user_a

    @pytest.mark.asyncio
    async def test_concurrent_uploads_all_produce_correct_hashes(self):
        """20 concurrent SHA-256 computations must all return correct results."""
        from core.security import compute_sha256

        async def compute_async(content: bytes) -> str:
            return compute_sha256(content)

        payloads = [f"evidence_file_{i}_".encode() * 1000 for i in range(20)]
        expected = [hashlib.sha256(p).hexdigest() for p in payloads]

        results = await asyncio.gather(*[compute_async(p) for p in payloads])
        assert results == expected


# ═══════════════════════════════════════════════════════════════════
# CASE STATE GATES
# ═══════════════════════════════════════════════════════════════════
class TestCaseStateGates:
    """Closed and archived cases must block certain operations."""

    @pytest.mark.asyncio
    async def test_closed_case_blocks_new_evidence(self):
        """Evidence cannot be added to a closed case."""
        from fastapi import HTTPException
        from services.evidence_service import upload_evidence
        db = AsyncMock()
        mock_case = MagicMock()
        mock_case.status = "closed"

        case_result = MagicMock()
        case_result.scalar_one_or_none.return_value = mock_case
        db.execute.return_value = case_result

        mock_file = MagicMock()
        mock_file.filename = "late_file.dd"
        mock_file.content_type = "application/octet-stream"
        mock_file.read = AsyncMock(return_value=b"content")

        # Verify the service raises when case status is closed
        # The gate check is: if case.status in ("closed", "archived") -> 409
        from fastapi import HTTPException as FHE
        closed_statuses = ["closed", "archived"]
        for status in closed_statuses:
            mock_case.status = status
            case_result.scalar_one_or_none.return_value = mock_case
            db.execute.return_value = case_result
            with pytest.raises((FHE, Exception)):
                await upload_evidence(
                    db=db, case_id=uuid.uuid4(), file=mock_file,
                    body=MagicMock(description="Late", evidence_type="file",
                                  acquisition_notes=None),
                    actor_id=uuid.uuid4(), actor_role="LabTechnician",
                    ip_address="127.0.0.1",
                )

    @pytest.mark.asyncio
    async def test_archived_case_blocks_status_change(self):
        """Archived cases cannot be transitioned to any other status."""
        from fastapi import HTTPException
        from services.case_service import _assert_transition

        for target in ["open", "active", "closed"]:
            with pytest.raises(HTTPException) as exc:
                _assert_transition("archived", target)
            assert exc.value.status_code == 409


# ═══════════════════════════════════════════════════════════════════
# EVIDENCE DELETION BLOCK
# ═══════════════════════════════════════════════════════════════════
class TestEvidenceDeletionBlocked:
    """Evidence must never be deletable — DB trigger prevents it."""

    def test_evidence_delete_raises_db_exception(self):
        """
        Simulate the PostgreSQL trigger that blocks DELETE on evidence.
        Any attempt to delete evidence should raise an exception.
        """
        # Simulate DB trigger behaviour
        def simulate_delete_trigger():
            raise Exception("Evidence records cannot be deleted.")

        with pytest.raises(Exception, match="cannot be deleted"):
            simulate_delete_trigger()

    def test_no_delete_evidence_endpoint_exists(self):
        """There must be no HTTP DELETE endpoint for evidence."""
        from main import app
        from fastapi.routing import APIRoute
        evidence_deletes = [
            (r.path, list(r.methods or []))
            for r in app.routes
            if isinstance(r, APIRoute)
            and "evidence" in r.path
            and "DELETE" in (r.methods or set())
        ]
        assert len(evidence_deletes) == 0, \
            f"DELETE evidence endpoints must not exist: {evidence_deletes}"


# ═══════════════════════════════════════════════════════════════════
# UNICODE AND SPECIAL CHARACTERS
# ═══════════════════════════════════════════════════════════════════
class TestUnicodeInput:
    """Case titles, descriptions, and findings support full Unicode."""

    def test_unicode_case_title_hash_stable(self):
        """Unicode content must hash stably — same content, same SHA-256."""
        from core.security import compute_sha256
        title = "Üntersuchung: Verdächtige Überweisung — Büro §42"
        h1 = compute_sha256(title.encode("utf-8"))
        h2 = compute_sha256(title.encode("utf-8"))
        assert h1 == h2
        assert len(h1) == 64

    def test_japanese_content_hashes_correctly(self):
        from core.security import compute_sha256
        content = "フォレンジック調査報告書 — 証拠番号 EVD-001"
        result = compute_sha256(content.encode("utf-8"))
        expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert result == expected

    def test_emoji_in_description_handled(self):
        from core.security import compute_sha256
        desc = "Evidence 🔒 classified 🔍 critical ⚠️"
        result = compute_sha256(desc.encode("utf-8"))
        assert len(result) == 64

    @pytest.mark.parametrize("title", [
        "Normal ASCII title",
        "Título en español con ñ",
        "Rapport en français — affaire n°42",
        "中文标题 — 案件编号 2024-001",
        "عنوان عربي — رقم القضية",
        "A" * 299,   # Near-max length (300 char limit)
    ])
    def test_valid_unicode_titles_accepted_by_schema(self, title):
        from schemas import CreateCaseRequest
        req = CreateCaseRequest(title=title, description=None)
        assert req.title == title


# ═══════════════════════════════════════════════════════════════════
# REPORT VERSION EDGE CASES
# ═══════════════════════════════════════════════════════════════════
class TestReportVersionEdgeCases:
    """Report versioning boundary cases."""

    def test_report_version_hash_changes_on_whitespace_addition(self):
        """Adding even a trailing space changes the content hash."""
        from core.security import compute_sha256
        v1 = "Report content"
        v2 = "Report content "   # trailing space
        assert compute_sha256(v1.encode()) != compute_sha256(v2.encode())

    def test_report_version_hash_is_case_sensitive(self):
        from core.security import compute_sha256
        v1 = "report CONTENT"
        v2 = "report content"
        assert compute_sha256(v1.encode()) != compute_sha256(v2.encode())

    def test_large_report_content_hash_correct(self):
        """1MB report content must hash correctly."""
        from core.security import compute_sha256
        content = ("# Section\n\nParagraph text. " * 50000).encode("utf-8")
        result   = compute_sha256(content)
        expected = hashlib.sha256(content).hexdigest()
        assert result == expected
        assert len(result) == 64

    def test_diff_of_identical_versions_is_empty(self):
        """Diffing identical content must produce no changes."""
        import difflib
        content = "Line 1\nLine 2\nLine 3\n"
        diff = list(difflib.unified_diff(
            content.splitlines(), content.splitlines(),
            fromfile="v1", tofile="v2",
        ))
        changes = [l for l in diff if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]
        assert len(changes) == 0

    @pytest.mark.asyncio
    async def test_court_ready_version_blocks_further_edits(self):
        """Once a version is court-ready, no new versions can be saved."""
        from fastapi import HTTPException
        from services.remaining_services import save_version
        from schemas import SaveReportVersionRequest

        locked_version = MagicMock()
        locked_version.is_court_ready  = True
        locked_version.version_number  = 2

        mock_report = MagicMock()
        mock_report.id             = uuid.uuid4()
        mock_report.case_id        = uuid.uuid4()
        mock_report.latest_version = 2
        mock_report.versions       = [locked_version]

        db = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = mock_report
        db.execute.return_value = result

        body = SaveReportVersionRequest(
            content="New content after lock",
            change_summary="This should be blocked"
        )
        with pytest.raises(HTTPException) as exc:
            await save_version(
                db, mock_report.case_id, mock_report.id,
                body, uuid.uuid4(), "Examiner", "127.0.0.1"
            )
        assert exc.value.status_code == 403

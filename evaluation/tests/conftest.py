"""
conftest.py — shared fixtures for the Phase 6 test suite.

All test files import from this when they need shared mocks,
JWT helpers, or seeded data structures.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest


# ── Stable IDs used across test files ─────────────────────────────────────────
ADMIN_ID    = uuid.UUID("00000000-0000-0000-0000-000000000001")
MANAGER_ID  = uuid.UUID("00000000-0000-0000-0000-000000000002")
LAB_ID      = uuid.UUID("00000000-0000-0000-0000-000000000003")
EXAMINER_ID = uuid.UUID("00000000-0000-0000-0000-000000000004")
LEGAL_ID    = uuid.UUID("00000000-0000-0000-0000-000000000005")
CASE_ID     = uuid.UUID("00000000-0000-0000-0000-000000000010")
EVIDENCE_ID = uuid.UUID("00000000-0000-0000-0000-000000000011")


# ── Mock DB session ────────────────────────────────────────────────────────────
@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.add    = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock(side_effect=lambda x: None)
    return db


# ── Mock user objects ──────────────────────────────────────────────────────────
def make_user(user_id, role, email=None):
    u = MagicMock()
    u.id           = user_id
    u.role         = role
    u.email        = email or f"{role.lower()}@forensics.local"
    u.full_name    = f"Test {role}"
    u.is_active    = True
    u.created_at   = datetime(2024, 1, 1, tzinfo=timezone.utc)
    u.last_login_at = None
    return u


@pytest.fixture
def admin_user():    return make_user(ADMIN_ID,    "Admin")

@pytest.fixture
def manager_user():  return make_user(MANAGER_ID,  "CaseManager")

@pytest.fixture
def lab_user():      return make_user(LAB_ID,      "LabTechnician")

@pytest.fixture
def examiner_user(): return make_user(EXAMINER_ID, "Examiner")

@pytest.fixture
def legal_user():    return make_user(LEGAL_ID,    "LegalReviewer")


# ── Mock evidence object ───────────────────────────────────────────────────────
@pytest.fixture
def mock_evidence():
    ev = MagicMock()
    ev.id                   = EVIDENCE_ID
    ev.case_id              = CASE_ID
    ev.filename             = "disk_image.dd"
    ev.sha256_hash          = "a" * 64
    ev.integrity_status     = "verified"
    ev.file_size_bytes      = 1073741824   # 1GB
    ev.evidence_type        = "disk_image"
    ev.hash_source          = "computed"
    ev.description          = "Full disk image"
    ev.uploaded_by          = LAB_ID
    ev.current_custodian_id = LAB_ID
    ev.uploaded_at          = datetime(2024, 11, 1, 10, 0, tzinfo=timezone.utc)
    ev.acquisition_tool     = "Autopsy"
    ev.acquisition_notes    = None
    return ev


# ── Mock case object ───────────────────────────────────────────────────────────
@pytest.fixture
def mock_case():
    c = MagicMock()
    c.id           = CASE_ID
    c.case_number  = "CASE-2024-00001"
    c.title        = "Test Forensic Investigation"
    c.description  = "A test case"
    c.status       = "active"
    c.created_by   = MANAGER_ID
    c.created_at   = datetime(2024, 11, 1, 9, 0, tzinfo=timezone.utc)
    c.updated_at   = datetime(2024, 11, 1, 9, 0, tzinfo=timezone.utc)
    c.evidence     = []
    c.assignments  = []
    return c

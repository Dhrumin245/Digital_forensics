"""
JWT authentication and RBAC enforcement.
All tokens are signed with RS256 (asymmetric).
Role is read from the JWT claim — never trusted from the client body.
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Annotated, Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from jose.exceptions import JOSEError

from core.config import settings

# auto_error=False so a missing Authorization header reaches get_current_user,
# which returns the semantically correct 401 (FastAPI's default is 403).
bearer_scheme = HTTPBearer(auto_error=False)


class UserRole(str, Enum):
    case_manager    = "CaseManager"
    lab_technician  = "LabTechnician"
    examiner        = "Examiner"
    legal_reviewer  = "LegalReviewer"
    admin           = "Admin"
    public_verifier = "PublicVerifier"


class CurrentUser:
    def __init__(self, user_id: UUID, role: UserRole, email: str):
        self.user_id = user_id
        self.role    = role
        self.email   = email


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_PUBLIC_KEY,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
        return payload
    # JOSEError is the base class for every python-jose failure — an expired
    # or badly-signed token (JWTError), a malformed/undecodable key (JWKError),
    # or anything else the library rejects. Any of these means "this token
    # cannot be trusted" and must return 401, never a 500 with a stack trace.
    except JOSEError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(bearer_scheme)],
) -> CurrentUser:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(credentials.credentials)
    return CurrentUser(
        user_id=UUID(payload["sub"]),
        role=UserRole(payload["role"]),
        email=payload["email"],
    )


def require_roles(*roles: UserRole):
    """
    Dependency factory — returns a FastAPI dependency that enforces
    that the current user has one of the specified roles.

    Usage:
        @router.post("/cases", dependencies=[Depends(require_roles(UserRole.case_manager))])
    """
    def _check(current_user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' is not permitted for this action. "
                       f"Required: {[r.value for r in roles]}",
            )
        return current_user
    return _check


# ── Cryptographic helpers ─────────────────────────────────────────────────────

def compute_sha256(data: bytes) -> str:
    """
    Compute SHA-256 of raw bytes. Always called server-side — never trust
    a client-supplied hash for new uploads.
    """
    return hashlib.sha256(data).hexdigest()


def verify_hash(data: bytes, stored_hash: str) -> bool:
    """
    Re-compute SHA-256 and compare to the stored value.
    Returns True if file is intact, False if tampered.
    """
    return compute_sha256(data) == stored_hash

"""
Auth service — login, token creation, user lookup.
JWT signed with RS256 (asymmetric). Passwords hashed with bcrypt.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import bcrypt
from jose import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.security import UserRole
from models import User
from schemas import TokenResponse, UserProfile


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ── Token creation ────────────────────────────────────────────────────────────

def _make_access_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub":   str(user.id),
        "role":  user.role,
        "email": user.email,
        "iat":   now,
        "exp":   now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
        "type":  "access",
    }
    return jwt.encode(payload, settings.JWT_PRIVATE_KEY, algorithm="RS256")


def _make_refresh_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub":  str(user.id),
        "iat":  now,
        "exp":  now + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
        "type": "refresh",
    }
    return jwt.encode(payload, settings.JWT_PRIVATE_KEY, algorithm="RS256")


# ── Service functions ─────────────────────────────────────────────────────────

async def login(db: AsyncSession, email: str, password: str) -> TokenResponse:
    """
    Validate credentials and return access + refresh tokens.
    Raises ValueError on bad credentials (caller converts to HTTP 401).
    """
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise ValueError("Invalid credentials")
    if not verify_password(password, user.password_hash):
        raise ValueError("Invalid credentials")

    # Update last_login_at
    user.last_login_at = datetime.now(timezone.utc)
    await db.flush()

    return TokenResponse(
        access_token=_make_access_token(user),
        refresh_token=_make_refresh_token(user),
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


async def get_user_by_id(db: AsyncSession, user_id: UUID) -> User:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise LookupError(f"User {user_id} not found")
    return user


async def create_user(
    db:        AsyncSession,
    email:     str,
    full_name: str,
    role:      str,
    password:  str,
) -> User:
    user = User(
        email=email,
        full_name=full_name,
        role=role,
        password_hash=hash_password(password),
        is_active=True,
    )
    db.add(user)
    await db.flush()   # Gets the generated UUID without committing
    return user


def to_profile(user: User) -> UserProfile:
    return UserProfile.model_validate(user)

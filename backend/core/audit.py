"""
Audit log service.

Every write operation in the system MUST call audit.log() before returning.
The audit_log table lives in the forensics_audit schema with INSERT-only
privileges — no UPDATE or DELETE possible from the app.

Audit entries are also published to Kafka so they are mirrored to S3
(Object Lock) independently of the database.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from schemas import AuditActionType


async def log(
    db:            AsyncSession,
    action:        AuditActionType,
    resource_type: str,
    resource_id:   str,
    ip_address:    str,
    result:        str = "success",
    actor_id:      Optional[uuid.UUID] = None,
    actor_role:    Optional[str] = None,
    detail:        Optional[dict[str, Any]] = None,
) -> None:
    """
    Write one row to forensics_audit.audit_log.

    Uses raw SQL instead of the ORM model so this works even if the ORM
    session is in a bad state — the audit write must always succeed.

    Parameters
    ----------
    db            : active async session
    action        : AuditActionType enum value
    resource_type : e.g. "evidence", "case", "report_version"
    resource_id   : UUID string of the affected resource
    ip_address    : caller IP (from Request.client.host)
    result        : "success" | "failure" | "blocked"
    actor_id      : UUID of the authenticated user (None for public portal)
    actor_role    : role string from the JWT claim
    detail        : any extra JSON payload relevant to the action
    """
    await db.execute(
        text("""
            INSERT INTO forensics_audit.audit_log
                (id, actor_id, actor_role, action_type,
                 resource_type, resource_id, ip_address,
                 result, detail, timestamp)
            VALUES
                (:id, :actor_id, :actor_role, :action_type,
                 :resource_type, :resource_id, :ip_address,
                 :result, :detail::jsonb, :timestamp)
        """),
        {
            "id":            str(uuid.uuid4()),
            "actor_id":      str(actor_id) if actor_id else None,
            "actor_role":    actor_role,
            "action_type":   action.value,
            "resource_type": resource_type,
            "resource_id":   resource_id,
            "ip_address":    ip_address,
            "result":        result,
            "detail":        __import__("json").dumps(detail or {}),
            "timestamp":     datetime.now(timezone.utc),
        },
    )

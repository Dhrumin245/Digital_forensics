"""Cases router — US-01, US-02, US-03"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from core.audit import log
from core.database import get_db
from core.security import CurrentUser, UserRole, get_current_user, require_roles
from schemas import (
    AuditActionType, AssignUserRequest, CaseAssignment,
    CaseListResponse, CaseResponse, CaseStatus,
    CreateCaseRequest, UpdateCaseRequest,
)
from services import case_service

router   = APIRouter()
AuthUser = Annotated[CurrentUser, Depends(get_current_user)]
CaseMgr  = Annotated[CurrentUser, Depends(require_roles(UserRole.case_manager))]


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED,
             summary="US-01 — Create a new case")
async def create_case(body: CreateCaseRequest, req: Request,
                      current_user: CaseMgr, db: AsyncSession = Depends(get_db)):
    case = await case_service.create_case(db, body, current_user.user_id)
    await log(db, AuditActionType.case_created, "case", str(case.id),
              req.client.host, actor_id=current_user.user_id,
              actor_role=current_user.role.value,
              detail={"title": case.title, "case_number": case.case_number})
    return case


@router.get("", response_model=CaseListResponse)
async def list_cases(req: Request, current_user: AuthUser,
                     status_filter: CaseStatus | None = None,
                     page: int = 1, page_size: int = 20,
                     db: AsyncSession = Depends(get_db)):
    return await case_service.list_cases(
        db, current_user.user_id, current_user.role.value,
        status_filter.value if status_filter else None, page, page_size,
    )


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(case_id: UUID, current_user: AuthUser,
                   db: AsyncSession = Depends(get_db)):
    case = await case_service.get_case(db, case_id, current_user.user_id, current_user.role.value)
    return case_service._to_response(case)


@router.patch("/{case_id}", response_model=CaseResponse,
              summary="US-03 — Update case or transition status")
async def update_case(case_id: UUID, body: UpdateCaseRequest, req: Request,
                      current_user: CaseMgr, db: AsyncSession = Depends(get_db)):
    case = await case_service.update_case(db, case_id, body, current_user.user_id)
    if body.status:
        await log(db, AuditActionType.case_status_changed, "case", str(case_id),
                  req.client.host, actor_id=current_user.user_id,
                  actor_role=current_user.role.value,
                  detail={"new_status": body.status.value, "reason": body.status_reason})
    return case_service._to_response(case)


@router.get("/{case_id}/assignments", response_model=list[CaseAssignment])
async def list_assignments(case_id: UUID, current_user: AuthUser,
                           db: AsyncSession = Depends(get_db)):
    return await case_service.list_assignments(db, case_id)


@router.post("/{case_id}/assignments", response_model=CaseAssignment,
             status_code=status.HTTP_201_CREATED, summary="US-02 — Assign user to case")
async def assign_user(case_id: UUID, body: AssignUserRequest, req: Request,
                      current_user: CaseMgr, db: AsyncSession = Depends(get_db)):
    assignment = await case_service.assign_user(db, case_id, body.user_id, current_user.user_id)
    await log(db, AuditActionType.user_assigned, "case_assignment", str(assignment.id),
              req.client.host, actor_id=current_user.user_id,
              actor_role=current_user.role.value,
              detail={"case_id": str(case_id), "user_id": str(body.user_id)})
    from schemas import CaseAssignment as CaseAssignmentSchema
    from services.auth_service import to_profile
    return CaseAssignmentSchema(
        id=assignment.id, case_id=assignment.case_id,
        user_id=assignment.user_id, user=to_profile(assignment.user),
        assigned_by=assignment.assigned_by, assigned_at=assignment.assigned_at,
    )


@router.delete("/{case_id}/assignments/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_assignment(case_id: UUID, user_id: UUID, req: Request,
                            current_user: CaseMgr, db: AsyncSession = Depends(get_db)):
    await case_service.remove_assignment(db, case_id, user_id, current_user.user_id)
    await log(db, AuditActionType.user_removed, "case_assignment", str(user_id),
              req.client.host, actor_id=current_user.user_id, actor_role=current_user.role.value)

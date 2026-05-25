"""Project management API routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.pydantic_models import ProjectCreate, ProjectResponse, ProjectUpdate
from app.models.schemas import Drawing, Project, ProjectProduct

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.post("", response_model=ProjectResponse)
async def create_project(data: ProjectCreate, db: AsyncSession = Depends(get_db)):
    project = Project(
        name=data.name,
        description=data.description,
        client_name=data.client_name,
        location=data.location,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return ProjectResponse.model_validate(project)


@router.get("", response_model=list[ProjectResponse])
async def list_projects(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).order_by(Project.created_at.desc()))
    projects = result.scalars().all()

    responses = []
    for p in projects:
        drawing_count = await db.scalar(
            select(func.count()).select_from(Drawing).where(Drawing.project_id == p.id)
        )
        product_count = await db.scalar(
            select(func.count()).select_from(ProjectProduct).where(ProjectProduct.project_id == p.id)
        )
        resp = ProjectResponse.model_validate(p)
        resp.drawing_count = drawing_count or 0
        resp.product_count = product_count or 0
        responses.append(resp)

    return responses


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    drawing_count = await db.scalar(
        select(func.count()).select_from(Drawing).where(Drawing.project_id == project_id)
    )
    product_count = await db.scalar(
        select(func.count()).select_from(ProjectProduct).where(ProjectProduct.project_id == project_id)
    )
    resp = ProjectResponse.model_validate(project)
    resp.drawing_count = drawing_count or 0
    resp.product_count = product_count or 0
    return resp


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(project_id: str, data: ProjectUpdate, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(project, key, value)

    await db.commit()
    await db.refresh(project)
    return ProjectResponse.model_validate(project)


@router.delete("/{project_id}")
async def delete_project(project_id: str, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    await db.delete(project)
    await db.commit()
    return {"message": "Project deleted"}

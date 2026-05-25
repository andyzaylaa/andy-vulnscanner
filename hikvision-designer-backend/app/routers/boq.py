"""BOQ (Bill of Quantities) import API routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.pydantic_models import BOQEntryResponse
from app.models.schemas import BOQEntry, Project
from app.services.boq_importer import boq_importer

router = APIRouter(prefix="/api/boq", tags=["boq"])


@router.post("/upload/{project_id}", response_model=list[BOQEntryResponse])
async def upload_boq(
    project_id: str,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    content = await file.read()
    filename = file.filename or "boq.xlsx"

    if filename.endswith((".xlsx", ".xls")):
        entries = await boq_importer.import_excel(content, filename, project_id, db)
    elif filename.endswith(".csv"):
        entries = await boq_importer.import_csv(content, filename, project_id, db)
    else:
        raise HTTPException(status_code=400, detail="Unsupported file type. Use .xlsx, .xls, or .csv")

    entries = await boq_importer.match_boq_to_products(entries, db)
    return [BOQEntryResponse.model_validate(e) for e in entries]


@router.get("/{project_id}", response_model=list[BOQEntryResponse])
async def get_boq_entries(project_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(BOQEntry)
        .where(BOQEntry.project_id == project_id)
        .order_by(BOQEntry.item_number)
    )
    return [BOQEntryResponse.model_validate(e) for e in result.scalars().all()]


@router.delete("/{project_id}/clear")
async def clear_boq(project_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(BOQEntry).where(BOQEntry.project_id == project_id)
    )
    entries = result.scalars().all()
    for entry in entries:
        await db.delete(entry)
    await db.commit()
    return {"message": f"Cleared {len(list(entries))} BOQ entries"}

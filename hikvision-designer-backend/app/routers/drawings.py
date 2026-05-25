"""Drawing upload and analysis API routes."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.pydantic_models import DrawingResponse, SymbolPlacementCreate, SymbolPlacementResponse
from app.models.schemas import Drawing, Project, SymbolPlacement
from app.services.ai_analyzer import ai_analyzer
from app.services.drawing_processor import drawing_processor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/drawings", tags=["drawings"])


@router.post("/upload/{project_id}", response_model=list[DrawingResponse])
async def upload_drawing(
    project_id: str,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 50MB)")

    try:
        pages = await drawing_processor.process_upload(content, file.filename or "drawing.pdf")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    drawings = []
    for page_info in pages:
        drawing = Drawing(
            project_id=project_id,
            filename=page_info["filename"],
            file_path=page_info["file_path"],
            file_type=page_info["file_type"],
            width=page_info["width"],
            height=page_info["height"],
            page_number=page_info["page_number"],
        )
        db.add(drawing)
        drawings.append(drawing)

    await db.commit()
    for d in drawings:
        await db.refresh(d)

    return [DrawingResponse.model_validate(d) for d in drawings]


@router.get("/project/{project_id}", response_model=list[DrawingResponse])
async def list_drawings(project_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Drawing).where(Drawing.project_id == project_id).order_by(Drawing.page_number)
    )
    return [DrawingResponse.model_validate(d) for d in result.scalars().all()]


@router.get("/{drawing_id}/image")
async def get_drawing_image(drawing_id: str, db: AsyncSession = Depends(get_db)):
    drawing = await db.get(Drawing, drawing_id)
    if not drawing:
        raise HTTPException(status_code=404, detail="Drawing not found")

    image_path = drawing_processor.get_image_path(drawing.file_path)
    if not image_path:
        raise HTTPException(status_code=404, detail="Image file not found")

    return FileResponse(image_path, media_type="image/png")


@router.post("/{drawing_id}/analyze", response_model=DrawingResponse)
async def analyze_drawing(drawing_id: str, db: AsyncSession = Depends(get_db)):
    drawing = await db.get(Drawing, drawing_id)
    if not drawing:
        raise HTTPException(status_code=404, detail="Drawing not found")

    image_path = drawing_processor.get_image_path(drawing.file_path)
    if not image_path:
        raise HTTPException(status_code=404, detail="Image file not found")

    analysis = await ai_analyzer.analyze_drawing(image_path, drawing.page_number)
    drawing.analysis_result = analysis
    await db.commit()
    await db.refresh(drawing)

    if "suggested_placements" in analysis:
        existing = await db.execute(
            select(SymbolPlacement).where(SymbolPlacement.drawing_id == drawing_id)
        )
        for old in existing.scalars().all():
            await db.delete(old)
        await db.flush()

        for placement_data in analysis["suggested_placements"]:
            placement = SymbolPlacement(
                drawing_id=drawing_id,
                system_type=placement_data.get("system_type", "cctv"),
                symbol_code=_get_symbol_code(placement_data.get("system_type", "cctv"), placement_data.get("device_type", "")),
                x=placement_data.get("x", 0.5),
                y=placement_data.get("y", 0.5),
                rotation=placement_data.get("rotation", 0),
                label=placement_data.get("model", ""),
                notes=placement_data.get("coverage_note", ""),
            )
            db.add(placement)
        await db.commit()

    return DrawingResponse.model_validate(drawing)


@router.get("/{drawing_id}/placements", response_model=list[SymbolPlacementResponse])
async def get_placements(drawing_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(SymbolPlacement).where(SymbolPlacement.drawing_id == drawing_id)
    )
    return [SymbolPlacementResponse.model_validate(p) for p in result.scalars().all()]


@router.post("/placements", response_model=SymbolPlacementResponse)
async def add_placement(data: SymbolPlacementCreate, db: AsyncSession = Depends(get_db)):
    placement = SymbolPlacement(
        drawing_id=data.drawing_id,
        product_id=data.product_id,
        system_type=data.system_type,
        symbol_code=data.symbol_code,
        x=data.x,
        y=data.y,
        rotation=data.rotation,
        scale=data.scale,
        label=data.label,
        notes=data.notes,
    )
    db.add(placement)
    await db.commit()
    await db.refresh(placement)
    return SymbolPlacementResponse.model_validate(placement)


@router.delete("/placements/{placement_id}")
async def delete_placement(placement_id: str, db: AsyncSession = Depends(get_db)):
    placement = await db.get(SymbolPlacement, placement_id)
    if not placement:
        raise HTTPException(status_code=404, detail="Placement not found")
    await db.delete(placement)
    await db.commit()
    return {"message": "Placement deleted"}


def _get_symbol_code(system_type: str, device_type: str) -> str:
    symbol_map = {
        "cctv": {"Dome Camera": "CAM-DOME", "Bullet Camera": "CAM-BULLET", "PTZ Camera": "CAM-PTZ", "Fisheye Camera": "CAM-FISHEYE", "NVR": "NVR"},
        "access_control": {"Card Reader": "AC-READER", "Access Terminal": "AC-TERMINAL", "Access Controller": "AC-CTRL", "Electric Strike Lock": "AC-LOCK"},
        "gate": {"Barrier Gate": "GATE-BARRIER", "Road Blocker": "GATE-BLOCKER"},
        "video_door_phone": {"Door Station": "VDP-DOOR", "Indoor Station": "VDP-INDOOR"},
        "fire": {"Smoke Detector": "FIRE-SMOKE", "Heat Detector": "FIRE-HEAT", "Manual Call Point": "FIRE-MCP", "Fire Panel": "FIRE-PANEL", "Sounder": "FIRE-SOUNDER"},
        "sound": {"Ceiling Speaker": "SND-CEIL", "Horn Speaker": "SND-HORN", "Amplifier": "SND-AMP"},
    }

    type_symbols = symbol_map.get(system_type, {})
    return type_symbols.get(device_type, f"{system_type[:3].upper()}-DEV")

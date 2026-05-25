"""Report generation and cable/accessory calculation API routes."""
from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.schemas import Drawing, Project, ProjectProduct
from app.services.cable_calculator import cable_calculator
from app.services.report_generator import report_generator

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{project_id}/cables")
async def calculate_cables(project_id: str, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    result = await db.execute(
        select(Drawing).where(Drawing.project_id == project_id)
    )
    drawings = result.scalars().all()

    all_cable_runs = []
    for drawing in drawings:
        analysis = drawing.analysis_result or {}
        cable_runs = analysis.get("cable_runs", [])
        all_cable_runs.extend(cable_runs)

    cables = cable_calculator.calculate_cables(all_cable_runs)
    return {"cables": [asdict(c) for c in cables]}


@router.get("/{project_id}/accessories")
async def calculate_accessories(project_id: str, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    result = await db.execute(
        select(Drawing).where(Drawing.project_id == project_id)
    )
    drawings = result.scalars().all()

    all_products = []
    all_cable_runs = []
    for drawing in drawings:
        analysis = drawing.analysis_result or {}
        products = analysis.get("suggested_products", [])
        cable_runs = analysis.get("cable_runs", [])
        all_products.extend(products)
        all_cable_runs.extend(cable_runs)

    accessories = cable_calculator.calculate_accessories(all_products, all_cable_runs)
    return {"accessories": [asdict(a) for a in accessories]}


@router.get("/{project_id}/excel")
async def generate_excel_report(project_id: str, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    result = await db.execute(
        select(Drawing).where(Drawing.project_id == project_id)
    )
    drawings = result.scalars().all()

    all_cable_runs = []
    all_products = []
    for drawing in drawings:
        analysis = drawing.analysis_result or {}
        all_cable_runs.extend(analysis.get("cable_runs", []))
        all_products.extend(analysis.get("suggested_products", []))

    cables = cable_calculator.calculate_cables(all_cable_runs)
    cable_data = [asdict(c) for c in cables]

    accessories = cable_calculator.calculate_accessories(all_products, all_cable_runs)
    accessory_data = [asdict(a) for a in accessories]

    excel_bytes = await report_generator.generate_project_report(
        project_id, db, cable_data=cable_data, accessory_data=accessory_data
    )

    filename = f"{project.name.replace(' ', '_')}_Report.xlsx"
    return Response(
        content=excel_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{project_id}/summary")
async def get_project_summary(project_id: str, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    result = await db.execute(
        select(ProjectProduct)
        .where(ProjectProduct.project_id == project_id)
        .options(selectinload(ProjectProduct.product))
    )
    project_products = list(result.scalars().all())

    by_system: dict = {}
    total_cost = 0.0
    total_devices = 0

    for pp in project_products:
        st = pp.system_type
        if st not in by_system:
            by_system[st] = {"devices": 0, "cost": 0.0, "products": []}
        by_system[st]["devices"] += pp.quantity
        total_devices += pp.quantity
        if pp.product:
            cost = pp.product.price * pp.quantity
            by_system[st]["cost"] += cost
            total_cost += cost
            by_system[st]["products"].append({
                "model": pp.product.model_number,
                "name": pp.product.name,
                "qty": pp.quantity,
                "cost": cost,
            })

    result = await db.execute(
        select(Drawing).where(Drawing.project_id == project_id)
    )
    drawings = result.scalars().all()

    return {
        "project": {
            "id": project.id,
            "name": project.name,
            "client": project.client_name,
            "location": project.location,
        },
        "total_devices": total_devices,
        "total_cost": total_cost,
        "drawing_count": len(list(drawings)),
        "by_system": by_system,
    }

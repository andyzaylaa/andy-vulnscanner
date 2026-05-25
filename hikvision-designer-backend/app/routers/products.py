"""Product catalog and project product management API routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.pydantic_models import (
    ProductCreate,
    ProductResponse,
    ProductSearchQuery,
    ProjectProductCreate,
    ProjectProductResponse,
)
from app.models.schemas import Product, ProjectProduct
from app.services.product_catalog import product_catalog

router = APIRouter(prefix="/api/products", tags=["products"])


@router.post("/search", response_model=list[ProductResponse])
async def search_products(query: ProductSearchQuery, db: AsyncSession = Depends(get_db)):
    products = await product_catalog.search_products(
        db,
        query=query.query,
        system_type=query.system_type,
        category=query.category,
        source=query.source,
        page=query.page,
        per_page=query.per_page,
    )
    return [ProductResponse.model_validate(p) for p in products]


@router.get("/search-online")
async def search_online(q: str):
    results = await product_catalog.search_hikvision_online(q)
    return {"results": results}


@router.get("/categories")
async def get_categories(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Product.category).distinct())
    categories = [row[0] for row in result.all()]
    return {"categories": sorted(categories)}


@router.get("/system-types")
async def get_system_types():
    return {
        "system_types": [
            {"value": "cctv", "label": "CCTV / Surveillance"},
            {"value": "access_control", "label": "Access Control"},
            {"value": "gate", "label": "Gate / Barrier System"},
            {"value": "video_door_phone", "label": "Video Door Phone / Intercom"},
            {"value": "fire", "label": "Fire Detection & Alarm"},
            {"value": "sound", "label": "Sound / PA System"},
            {"value": "intercom", "label": "Intercom System"},
            {"value": "alarm", "label": "Alarm System"},
        ]
    }


@router.get("/{product_id}", response_model=ProductResponse)
async def get_product(product_id: str, db: AsyncSession = Depends(get_db)):
    product = await product_catalog.get_product_by_id(db, product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return ProductResponse.model_validate(product)


@router.post("", response_model=ProductResponse)
async def create_product(data: ProductCreate, db: AsyncSession = Depends(get_db)):
    product = await product_catalog.import_product(db, data.model_dump())
    return ProductResponse.model_validate(product)


@router.post("/project/{project_id}", response_model=ProjectProductResponse)
async def add_product_to_project(
    project_id: str, data: ProjectProductCreate, db: AsyncSession = Depends(get_db)
):
    pp = ProjectProduct(
        project_id=project_id,
        product_id=data.product_id,
        quantity=data.quantity,
        system_type=data.system_type,
        location_note=data.location_note,
        cable_length_m=data.cable_length_m,
        cable_type=data.cable_type,
        notes=data.notes,
    )
    db.add(pp)
    await db.commit()
    await db.refresh(pp)

    result = await db.execute(
        select(ProjectProduct)
        .where(ProjectProduct.id == pp.id)
        .options(selectinload(ProjectProduct.product))
    )
    pp = result.scalar_one()
    return ProjectProductResponse.model_validate(pp)


@router.get("/project/{project_id}", response_model=list[ProjectProductResponse])
async def get_project_products(project_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ProjectProduct)
        .where(ProjectProduct.project_id == project_id)
        .options(selectinload(ProjectProduct.product))
    )
    return [ProjectProductResponse.model_validate(pp) for pp in result.scalars().all()]


@router.put("/project-product/{pp_id}", response_model=ProjectProductResponse)
async def update_project_product(
    pp_id: str, data: ProjectProductCreate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(ProjectProduct)
        .where(ProjectProduct.id == pp_id)
        .options(selectinload(ProjectProduct.product))
    )
    pp = result.scalar_one_or_none()
    if not pp:
        raise HTTPException(status_code=404, detail="Project product not found")

    pp.product_id = data.product_id
    pp.quantity = data.quantity
    pp.system_type = data.system_type
    pp.location_note = data.location_note
    pp.cable_length_m = data.cable_length_m
    pp.cable_type = data.cable_type
    pp.notes = data.notes

    await db.commit()
    await db.refresh(pp)
    return ProjectProductResponse.model_validate(pp)


@router.delete("/project-product/{pp_id}")
async def remove_product_from_project(pp_id: str, db: AsyncSession = Depends(get_db)):
    pp = await db.get(ProjectProduct, pp_id)
    if not pp:
        raise HTTPException(status_code=404, detail="Project product not found")
    await db.delete(pp)
    await db.commit()
    return {"message": "Product removed from project"}

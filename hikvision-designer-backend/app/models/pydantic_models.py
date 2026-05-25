from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    name: str
    description: str = ""
    client_name: str = ""
    location: str = ""


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    client_name: str | None = None
    location: str | None = None
    status: str | None = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: str
    client_name: str
    location: str
    status: str
    created_at: datetime | None = None
    updated_at: datetime | None = None
    drawing_count: int = 0
    product_count: int = 0

    model_config = {"from_attributes": True}


class DrawingResponse(BaseModel):
    id: str
    project_id: str
    filename: str
    file_path: str
    file_type: str
    width: int
    height: int
    page_number: int
    analysis_result: dict = {}
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class ProductCreate(BaseModel):
    model_number: str
    name: str
    category: str
    system_type: str
    description: str = ""
    specifications: dict = {}
    price: float = 0.0
    currency: str = "USD"
    image_url: str = ""
    datasheet_url: str = ""
    source: str = "local"
    brand: str = "Hikvision"
    accessories: list[dict] = []
    cable_requirements: dict = {}


class ProductResponse(BaseModel):
    id: str
    model_number: str
    name: str
    category: str
    system_type: str
    description: str
    specifications: dict
    price: float
    currency: str
    image_url: str
    datasheet_url: str
    source: str
    brand: str
    accessories: list = []
    cable_requirements: dict = {}
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class ProductSearchQuery(BaseModel):
    query: str
    system_type: str | None = None
    category: str | None = None
    source: str | None = None
    page: int = 1
    per_page: int = 20


class SymbolPlacementCreate(BaseModel):
    drawing_id: str
    product_id: str | None = None
    system_type: str
    symbol_code: str
    x: float
    y: float
    rotation: float = 0.0
    scale: float = 1.0
    label: str = ""
    notes: str = ""


class SymbolPlacementResponse(BaseModel):
    id: str
    drawing_id: str
    product_id: str | None
    system_type: str
    symbol_code: str
    x: float
    y: float
    rotation: float
    scale: float
    label: str
    notes: str

    model_config = {"from_attributes": True}


class ProjectProductCreate(BaseModel):
    product_id: str
    quantity: int = 1
    system_type: str
    location_note: str = ""
    cable_length_m: float = 0.0
    cable_type: str = ""
    notes: str = ""


class ProjectProductResponse(BaseModel):
    id: str
    project_id: str
    product_id: str
    quantity: int
    system_type: str
    location_note: str
    cable_length_m: float
    cable_type: str
    notes: str
    product: ProductResponse | None = None

    model_config = {"from_attributes": True}


class BOQEntryResponse(BaseModel):
    id: str
    project_id: str
    item_number: int
    description: str
    model_number: str
    quantity: int
    unit: str
    unit_price: float
    total_price: float
    system_type: str
    matched_product_id: str | None
    source_file: str

    model_config = {"from_attributes": True}


class DrawingAnalysisResult(BaseModel):
    areas: list[dict] = Field(default_factory=list)
    suggested_systems: list[dict] = Field(default_factory=list)
    suggested_products: list[dict] = Field(default_factory=list)
    suggested_placements: list[dict] = Field(default_factory=list)
    cable_runs: list[dict] = Field(default_factory=list)
    summary: str = ""


class CableCalculation(BaseModel):
    cable_type: str
    total_length_m: float
    quantity_rolls: int
    roll_length_m: float = 305.0
    purpose: str = ""
    system_type: str = ""


class AccessoryItem(BaseModel):
    name: str
    model_number: str = ""
    quantity: int = 1
    purpose: str = ""
    for_product: str = ""


class ProjectReport(BaseModel):
    project: ProjectResponse
    products: list[ProjectProductResponse]
    cables: list[CableCalculation]
    accessories: list[AccessoryItem]
    total_cost: float = 0.0

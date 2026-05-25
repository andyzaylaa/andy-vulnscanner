from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
    func,
)
from sqlalchemy.orm import relationship

from app.database import Base


class SystemType(str, Enum):
    CCTV = "cctv"
    ACCESS_CONTROL = "access_control"
    GATE = "gate"
    VIDEO_DOOR_PHONE = "video_door_phone"
    FIRE = "fire"
    SOUND = "sound"
    INTERCOM = "intercom"
    ALARM = "alarm"


class Project(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    client_name = Column(String(255), default="")
    location = Column(String(255), default="")
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    status = Column(String(50), default="draft")

    drawings = relationship("Drawing", back_populates="project", cascade="all, delete-orphan")
    product_items = relationship("ProjectProduct", back_populates="project", cascade="all, delete-orphan")


class Drawing(Base):
    __tablename__ = "drawings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_type = Column(String(10), default="pdf")
    width = Column(Integer, default=0)
    height = Column(Integer, default=0)
    page_number = Column(Integer, default=0)
    analysis_result = Column(JSON, default=dict)
    created_at = Column(DateTime, default=func.now())

    project = relationship("Project", back_populates="drawings")
    placements = relationship("SymbolPlacement", back_populates="drawing", cascade="all, delete-orphan")


class Product(Base):
    __tablename__ = "products"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    model_number = Column(String(100), nullable=False, unique=True)
    name = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False)
    system_type = Column(String(50), nullable=False)
    description = Column(Text, default="")
    specifications = Column(JSON, default=dict)
    price = Column(Float, default=0.0)
    currency = Column(String(10), default="USD")
    image_url = Column(String(500), default="")
    datasheet_url = Column(String(500), default="")
    source = Column(String(50), default="local")
    brand = Column(String(100), default="Hikvision")
    accessories = Column(JSON, default=list)
    cable_requirements = Column(JSON, default=dict)
    created_at = Column(DateTime, default=func.now())


class ProjectProduct(Base):
    __tablename__ = "project_products"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    product_id = Column(String, ForeignKey("products.id"), nullable=False)
    quantity = Column(Integer, default=1)
    system_type = Column(String(50), nullable=False)
    location_note = Column(String(255), default="")
    cable_length_m = Column(Float, default=0.0)
    cable_type = Column(String(100), default="")
    notes = Column(Text, default="")

    project = relationship("Project", back_populates="product_items")
    product = relationship("Product")


class SymbolPlacement(Base):
    __tablename__ = "symbol_placements"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    drawing_id = Column(String, ForeignKey("drawings.id"), nullable=False)
    product_id = Column(String, ForeignKey("products.id"), nullable=True)
    system_type = Column(String(50), nullable=False)
    symbol_code = Column(String(50), nullable=False)
    x = Column(Float, nullable=False)
    y = Column(Float, nullable=False)
    rotation = Column(Float, default=0.0)
    scale = Column(Float, default=1.0)
    label = Column(String(100), default="")
    notes = Column(Text, default="")

    drawing = relationship("Drawing", back_populates="placements")
    product = relationship("Product")


class BOQEntry(Base):
    __tablename__ = "boq_entries"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    item_number = Column(Integer, default=0)
    description = Column(Text, nullable=False)
    model_number = Column(String(100), default="")
    quantity = Column(Integer, default=1)
    unit = Column(String(20), default="pcs")
    unit_price = Column(Float, default=0.0)
    total_price = Column(Float, default=0.0)
    system_type = Column(String(50), default="")
    matched_product_id = Column(String, ForeignKey("products.id"), nullable=True)
    source_file = Column(String(255), default="")
    created_at = Column(DateTime, default=func.now())

    matched_product = relationship("Product")

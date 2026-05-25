"""Main FastAPI application."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import UPLOAD_PATH, settings
from app.database import init_db, async_session
from app.routers import projects, drawings, products, boq, reports
from app.services.product_catalog import product_catalog

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s...", settings.app_name)
    await init_db()

    async with async_session() as db:
        count = await product_catalog.seed_default_products(db)
        if count > 0:
            logger.info("Seeded %d default products into the database", count)

    yield
    logger.info("Shutting down %s...", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    description="AI-Powered Security & Building Systems Design Tool for Hikvision products",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(projects.router)
app.include_router(drawings.router)
app.include_router(products.router)
app.include_router(boq.router)
app.include_router(reports.router)

app.mount("/uploads", StaticFiles(directory=str(UPLOAD_PATH)), name="uploads")


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "app": settings.app_name, "version": "1.0.0"}


@app.get("/api/symbols")
async def get_symbol_library():
    return {
        "symbols": {
            "cctv": [
                {"code": "CAM-DOME", "name": "Dome Camera", "icon": "⊙", "color": "#2196F3"},
                {"code": "CAM-BULLET", "name": "Bullet Camera", "icon": "▸", "color": "#1976D2"},
                {"code": "CAM-PTZ", "name": "PTZ Camera", "icon": "◎", "color": "#0D47A1"},
                {"code": "CAM-FISHEYE", "name": "Fisheye Camera", "icon": "◉", "color": "#42A5F5"},
                {"code": "NVR", "name": "Network Video Recorder", "icon": "▣", "color": "#1565C0"},
            ],
            "access_control": [
                {"code": "AC-READER", "name": "Card Reader", "icon": "⊡", "color": "#4CAF50"},
                {"code": "AC-TERMINAL", "name": "Access Terminal", "icon": "⊞", "color": "#388E3C"},
                {"code": "AC-CTRL", "name": "Access Controller", "icon": "▦", "color": "#2E7D32"},
                {"code": "AC-LOCK", "name": "Electric Lock", "icon": "⊟", "color": "#66BB6A"},
            ],
            "gate": [
                {"code": "GATE-BARRIER", "name": "Boom Barrier", "icon": "⫿", "color": "#FF9800"},
                {"code": "GATE-BLOCKER", "name": "Road Blocker", "icon": "⊠", "color": "#F57C00"},
            ],
            "video_door_phone": [
                {"code": "VDP-DOOR", "name": "Door Station", "icon": "⊡", "color": "#9C27B0"},
                {"code": "VDP-INDOOR", "name": "Indoor Station", "icon": "▱", "color": "#7B1FA2"},
            ],
            "fire": [
                {"code": "FIRE-SMOKE", "name": "Smoke Detector", "icon": "◯", "color": "#F44336"},
                {"code": "FIRE-HEAT", "name": "Heat Detector", "icon": "◇", "color": "#D32F2F"},
                {"code": "FIRE-MCP", "name": "Manual Call Point", "icon": "☐", "color": "#B71C1C"},
                {"code": "FIRE-PANEL", "name": "Fire Panel", "icon": "▣", "color": "#C62828"},
                {"code": "FIRE-SOUNDER", "name": "Sounder/Strobe", "icon": "◈", "color": "#E53935"},
            ],
            "sound": [
                {"code": "SND-CEIL", "name": "Ceiling Speaker", "icon": "◎", "color": "#607D8B"},
                {"code": "SND-HORN", "name": "Horn Speaker", "icon": "◁", "color": "#455A64"},
                {"code": "SND-AMP", "name": "Amplifier", "icon": "▣", "color": "#37474F"},
            ],
        }
    }

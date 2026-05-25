"""Product catalog service - search from local DB and Hikvision online catalog."""
from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx
from bs4 import BeautifulSoup
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.schemas import Product

logger = logging.getLogger(__name__)

HIKVISION_PRODUCT_DB: list[dict] = [
    # CCTV - IP Cameras
    {"model_number": "DS-2CD2183G2-I", "name": "8 MP AcuSense Fixed Dome Network Camera", "category": "IP Camera", "system_type": "cctv", "description": "8MP, 1/2.8\" CMOS, 2.8/4/6mm fixed lens, up to 30m IR, H.265+, 120dB WDR, IP67, IK10, PoE", "specifications": {"resolution": "8MP (3840x2160)", "lens": "2.8mm", "ir_range": "30m", "wdr": "120dB", "protection": "IP67, IK10", "power": "PoE (802.3af)", "compression": "H.265+"}, "price": 185.0, "brand": "Hikvision", "accessories": [{"name": "Wall Mount Bracket", "model": "DS-1272ZJ-110", "qty": 1}, {"name": "Junction Box", "model": "DS-1280ZJ-S", "qty": 1}], "cable_requirements": {"type": "CAT6 UTP", "max_length_m": 100, "connector": "RJ45", "poe": True}},
    {"model_number": "DS-2CD2143G2-I", "name": "4 MP AcuSense Fixed Dome Network Camera", "category": "IP Camera", "system_type": "cctv", "description": "4MP, 1/3\" CMOS, 2.8mm fixed lens, up to 30m IR, H.265+, 120dB WDR, IP67, IK10, PoE", "specifications": {"resolution": "4MP (2688x1520)", "lens": "2.8mm", "ir_range": "30m", "wdr": "120dB", "protection": "IP67, IK10", "power": "PoE (802.3af)"}, "price": 125.0, "brand": "Hikvision", "accessories": [{"name": "Wall Mount Bracket", "model": "DS-1272ZJ-110", "qty": 1}, {"name": "Junction Box", "model": "DS-1280ZJ-S", "qty": 1}], "cable_requirements": {"type": "CAT6 UTP", "max_length_m": 100, "connector": "RJ45", "poe": True}},
    {"model_number": "DS-2CD2T47G2-L", "name": "4 MP ColorVu Fixed Bullet Network Camera", "category": "IP Camera", "system_type": "cctv", "description": "4MP ColorVu, 1/1.8\" CMOS, 4/6mm fixed lens, up to 60m white light, H.265+, 130dB WDR, IP67", "specifications": {"resolution": "4MP (2688x1520)", "lens": "4mm", "white_light": "60m", "wdr": "130dB", "protection": "IP67", "power": "PoE (802.3af)"}, "price": 165.0, "brand": "Hikvision", "accessories": [{"name": "Wall Mount Bracket", "model": "DS-1292ZJ", "qty": 1}, {"name": "Junction Box", "model": "DS-1280ZJ-S", "qty": 1}], "cable_requirements": {"type": "CAT6 UTP", "max_length_m": 100, "connector": "RJ45", "poe": True}},
    {"model_number": "DS-2DE4425IW-DE", "name": "4 MP 25x IR Network Speed Dome", "category": "PTZ Camera", "system_type": "cctv", "description": "4MP, 25x optical zoom, 100m IR, IP66, PoE+, DarkFighter", "specifications": {"resolution": "4MP", "zoom": "25x optical", "ir_range": "100m", "protection": "IP66", "power": "PoE+ (802.3at)"}, "price": 650.0, "brand": "Hikvision", "accessories": [{"name": "Pendant Mount", "model": "DS-1661ZJ", "qty": 1}, {"name": "Wall Mount Bracket", "model": "DS-1604ZJ", "qty": 1}], "cable_requirements": {"type": "CAT6 UTP", "max_length_m": 100, "connector": "RJ45", "poe_plus": True}},
    {"model_number": "DS-2CD2955FWD-IS", "name": "5 MP Fisheye Fixed Dome Network Camera", "category": "Fisheye Camera", "system_type": "cctv", "description": "5MP fisheye, 1.05mm lens, 360° panoramic view, built-in mic, PoE", "specifications": {"resolution": "5MP", "lens": "1.05mm fisheye", "fov": "360°", "audio": "Built-in mic", "power": "PoE (802.3af)"}, "price": 320.0, "brand": "Hikvision", "accessories": [{"name": "Ceiling Mount", "model": "DS-1259ZJ", "qty": 1}], "cable_requirements": {"type": "CAT6 UTP", "max_length_m": 100, "connector": "RJ45", "poe": True}},
    # NVR
    {"model_number": "DS-7616NI-K2/16P", "name": "16-ch 4K NVR with 16 PoE Ports", "category": "NVR", "system_type": "cctv", "description": "16 channel NVR, 4K resolution, 16 PoE ports, 2 SATA, H.265+", "specifications": {"channels": 16, "resolution": "4K (8MP)", "poe_ports": 16, "sata": 2, "bandwidth": "160Mbps"}, "price": 420.0, "brand": "Hikvision", "accessories": [{"name": "HDD 4TB", "model": "WD Purple 4TB", "qty": 2}, {"name": "Rack Mount Kit", "model": "DS-76xxNI-rack", "qty": 1}], "cable_requirements": {}},
    {"model_number": "DS-7732NI-K4/16P", "name": "32-ch 4K NVR with 16 PoE Ports", "category": "NVR", "system_type": "cctv", "description": "32 channel NVR, 4K resolution, 16 PoE ports, 4 SATA, H.265+", "specifications": {"channels": 32, "resolution": "4K (8MP)", "poe_ports": 16, "sata": 4, "bandwidth": "256Mbps"}, "price": 680.0, "brand": "Hikvision", "accessories": [{"name": "HDD 4TB", "model": "WD Purple 4TB", "qty": 4}, {"name": "Rack Mount Kit", "model": "DS-77xxNI-rack", "qty": 1}], "cable_requirements": {}},
    # Access Control
    {"model_number": "DS-K1T804MF", "name": "Face Recognition Terminal", "category": "Access Terminal", "system_type": "access_control", "description": "Face recognition + fingerprint + card, 4.3\" LCD, 3000 faces, TCP/IP", "specifications": {"verification": "Face/Fingerprint/Card", "display": "4.3 inch LCD", "face_capacity": 3000, "card_capacity": 10000, "interface": "TCP/IP, RS-485"}, "price": 380.0, "brand": "Hikvision", "accessories": [{"name": "Flush Mount Box", "model": "DS-KAB6-FMB", "qty": 1}, {"name": "Electric Lock", "model": "DS-K4H250S", "qty": 1}, {"name": "Exit Button", "model": "DS-K7P03", "qty": 1}, {"name": "Door Magnetic Contact", "model": "DS-PD1-MC-WWS", "qty": 1}], "cable_requirements": {"type": "CAT6 UTP", "max_length_m": 100, "connector": "RJ45", "additional": [{"type": "2C 0.75mm", "purpose": "Electric lock power"}]}},
    {"model_number": "DS-K1T341AMF", "name": "MinMoe Face Recognition Terminal", "category": "Access Terminal", "system_type": "access_control", "description": "MinMoe face recognition, mask detection, temperature screening, fingerprint & card", "specifications": {"verification": "Face/Fingerprint/Card/Temperature", "display": "7 inch LCD", "face_capacity": 6000, "temperature": "Yes"}, "price": 520.0, "brand": "Hikvision", "accessories": [{"name": "Floor Stand", "model": "DS-KAB671-B", "qty": 1}, {"name": "Electric Lock", "model": "DS-K4H250S", "qty": 1}, {"name": "Exit Button", "model": "DS-K7P03", "qty": 1}], "cable_requirements": {"type": "CAT6 UTP", "max_length_m": 100, "connector": "RJ45"}},
    {"model_number": "DS-K2604T", "name": "4-Door Access Controller", "category": "Access Controller", "system_type": "access_control", "description": "4-door network access controller, supports card, fingerprint & face readers", "specifications": {"doors": 4, "card_capacity": 100000, "event_capacity": 300000, "interface": "TCP/IP, RS-485, Wiegand"}, "price": 290.0, "brand": "Hikvision", "accessories": [{"name": "Power Supply 12V 5A", "model": "DS-2FA1225-D4", "qty": 1}, {"name": "Battery Backup", "model": "12V 7Ah", "qty": 1}], "cable_requirements": {"type": "CAT6 UTP", "max_length_m": 100}},
    {"model_number": "DS-K1T671M", "name": "Card Reader Terminal", "category": "Card Reader", "system_type": "access_control", "description": "Mifare card reader, IP65, RS-485/Wiegand output", "specifications": {"card_type": "Mifare", "protection": "IP65", "interface": "RS-485, Wiegand"}, "price": 65.0, "brand": "Hikvision", "accessories": [{"name": "Back Box", "model": "DS-KAB6-QMB", "qty": 1}], "cable_requirements": {"type": "4C 0.5mm shielded", "max_length_m": 100}},
    # Gate / Barrier
    {"model_number": "DS-TMG4B0-RA", "name": "Automatic Boom Barrier (Right Arm)", "category": "Barrier Gate", "system_type": "gate", "description": "Automatic boom barrier, 4m arm, right mount, 3s speed, vehicle detection", "specifications": {"arm_length": "4m", "speed": "3s", "motor": "DC brushless", "ip_rating": "IP54"}, "price": 1200.0, "brand": "Hikvision", "accessories": [{"name": "Loop Detector", "model": "DS-TMG-VD", "qty": 2}, {"name": "Extra Arm 4m", "model": "DS-TMG4-RA", "qty": 1}, {"name": "Photocell Sensor", "model": "DS-TMG-Photocell", "qty": 1}], "cable_requirements": {"type": "5C 2.5mm", "max_length_m": 50, "additional": [{"type": "Loop wire", "purpose": "Vehicle detection loop"}]}},
    {"model_number": "DS-TMG760-TB", "name": "Tire Killer (Road Blocker)", "category": "Road Blocker", "system_type": "gate", "description": "Hydraulic road blocker / tire killer, anti-terrorism rated", "specifications": {"width": "3m", "speed": "3s up, 1.5s emergency", "crash_rating": "K8/M50"}, "price": 8500.0, "brand": "Hikvision", "accessories": [{"name": "Control Unit", "model": "DS-TMG-CU", "qty": 1}], "cable_requirements": {"type": "5C 4mm", "max_length_m": 30}},
    # Video Door Phone / Intercom
    {"model_number": "DS-KV8113-WME1", "name": "IP Video Intercom Door Station", "category": "Door Station", "system_type": "video_door_phone", "description": "2MP HD video, 1 call button, built-in mic & speaker, IP65, IK08, WiFi", "specifications": {"camera": "2MP", "buttons": 1, "protection": "IP65, IK08", "connectivity": "TCP/IP, WiFi"}, "price": 195.0, "brand": "Hikvision", "accessories": [{"name": "Flush Mount Frame", "model": "DS-KD-ACF1", "qty": 1}, {"name": "Surface Mount Box", "model": "DS-KAB8103-IMEX", "qty": 1}], "cable_requirements": {"type": "CAT6 UTP", "max_length_m": 100, "connector": "RJ45"}},
    {"model_number": "DS-KH8350-WTE1", "name": "7\" IP Video Intercom Indoor Station", "category": "Indoor Station", "system_type": "video_door_phone", "description": "7\" touch screen, WiFi, POE, built-in speaker & mic", "specifications": {"display": "7 inch touch", "connectivity": "TCP/IP, WiFi", "power": "PoE", "audio": "Full duplex"}, "price": 175.0, "brand": "Hikvision", "accessories": [{"name": "Desk Stand", "model": "DS-KABH8350-T", "qty": 1}], "cable_requirements": {"type": "CAT6 UTP", "max_length_m": 100}},
    {"model_number": "DS-KD-KP", "name": "Modular Keypad Module", "category": "Intercom Module", "system_type": "video_door_phone", "description": "Keypad module for modular door station, password/card access", "specifications": {"type": "Keypad", "backlight": "Yes", "interface": "RS-485"}, "price": 85.0, "brand": "Hikvision", "accessories": [], "cable_requirements": {}},
    # Fire System
    {"model_number": "DS-PDSMK-S-WE", "name": "Wireless Smoke Detector", "category": "Smoke Detector", "system_type": "fire", "description": "Photoelectric smoke detector, wireless, 868MHz, battery powered", "specifications": {"type": "Photoelectric", "wireless": "868MHz", "battery": "CR123A x1", "coverage": "60 sqm"}, "price": 45.0, "brand": "Hikvision", "accessories": [{"name": "Mounting Base", "model": "DS-PD-Base", "qty": 1}], "cable_requirements": {"type": "No cable (wireless)", "max_length_m": 0}},
    {"model_number": "DS-PDTH-S-WE", "name": "Wireless Heat Detector", "category": "Heat Detector", "system_type": "fire", "description": "Rate of rise & fixed temperature heat detector, wireless", "specifications": {"type": "Rate of Rise + Fixed", "threshold": "57°C", "wireless": "868MHz"}, "price": 42.0, "brand": "Hikvision", "accessories": [{"name": "Mounting Base", "model": "DS-PD-Base", "qty": 1}], "cable_requirements": {"type": "No cable (wireless)", "max_length_m": 0}},
    {"model_number": "DS-PHA20-W2P", "name": "2-Zone Fire Alarm Panel", "category": "Fire Panel", "system_type": "fire", "description": "2-zone conventional fire alarm control panel", "specifications": {"zones": 2, "detectors_per_zone": 30, "type": "Conventional"}, "price": 120.0, "brand": "Hikvision", "accessories": [{"name": "Battery 12V 7Ah", "model": "12V-7AH", "qty": 2}], "cable_requirements": {"type": "Fire rated 2C 1.5mm", "max_length_m": 200}},
    {"model_number": "DS-PMA-S-WE", "name": "Wireless Manual Call Point", "category": "Manual Call Point", "system_type": "fire", "description": "Wireless manual call point, break glass type, 868MHz", "specifications": {"type": "Break glass", "wireless": "868MHz"}, "price": 38.0, "brand": "Hikvision", "accessories": [], "cable_requirements": {"type": "No cable (wireless)", "max_length_m": 0}},
    {"model_number": "DS-PS1-I-WE", "name": "Wireless Indoor Sounder", "category": "Sounder", "system_type": "fire", "description": "Wireless indoor sounder with strobe, 110dB, 868MHz", "specifications": {"output": "110dB", "strobe": "Yes", "wireless": "868MHz"}, "price": 55.0, "brand": "Hikvision", "accessories": [], "cable_requirements": {}},
    # Sound / PA System
    {"model_number": "DS-QAZ0206G", "name": "6W Ceiling Mount Speaker", "category": "Ceiling Speaker", "system_type": "sound", "description": "6W ceiling mount speaker for PA system, 100V line", "specifications": {"power": "6W", "type": "Ceiling mount", "line": "100V", "frequency": "100Hz-16kHz"}, "price": 28.0, "brand": "Hikvision", "accessories": [{"name": "Ceiling Mount Kit", "model": "DS-QAZ-CMK", "qty": 1}], "cable_requirements": {"type": "Speaker cable 2C 1.5mm", "max_length_m": 200}},
    {"model_number": "DS-QAZ0415G", "name": "15W Horn Speaker", "category": "Horn Speaker", "system_type": "sound", "description": "15W outdoor horn speaker, IP66, 100V line", "specifications": {"power": "15W", "type": "Horn", "line": "100V", "protection": "IP66"}, "price": 45.0, "brand": "Hikvision", "accessories": [{"name": "Wall Bracket", "model": "DS-QAZ-WB", "qty": 1}], "cable_requirements": {"type": "Speaker cable 2C 1.5mm", "max_length_m": 200}},
    {"model_number": "DS-KAW150-2N", "name": "150W Network Amplifier", "category": "Amplifier", "system_type": "sound", "description": "150W network audio amplifier, 2 zones, 100V line output", "specifications": {"power": "150W", "zones": 2, "input": "Network + Line", "output": "100V line"}, "price": 350.0, "brand": "Hikvision", "accessories": [{"name": "Rack Mount Kit", "model": "DS-KAW-RMK", "qty": 1}], "cable_requirements": {"type": "CAT6 UTP", "max_length_m": 100}},
    # Accessories
    {"model_number": "DS-1272ZJ-110", "name": "Wall Mount Bracket for Dome Camera", "category": "Bracket", "system_type": "cctv", "description": "Wall mount bracket for dome cameras", "specifications": {"material": "Aluminum alloy", "color": "White", "load": "4.5kg"}, "price": 15.0, "brand": "Hikvision", "accessories": [], "cable_requirements": {}},
    {"model_number": "DS-1280ZJ-S", "name": "Junction Box for Dome/Bullet Camera", "category": "Junction Box", "system_type": "cctv", "description": "Deep base junction box for cable management", "specifications": {"material": "Aluminum alloy", "color": "White", "cable_entry": "Side"}, "price": 12.0, "brand": "Hikvision", "accessories": [], "cable_requirements": {}},
    {"model_number": "DS-1292ZJ", "name": "Wall Mount Bracket for Bullet Camera", "category": "Bracket", "system_type": "cctv", "description": "Wall mount bracket for bullet cameras", "specifications": {"material": "Aluminum alloy", "color": "White"}, "price": 18.0, "brand": "Hikvision", "accessories": [], "cable_requirements": {}},
    {"model_number": "DS-K4H250S", "name": "Electric Strike Lock", "category": "Lock", "system_type": "access_control", "description": "Fail-safe/fail-secure electric strike lock, 12V DC", "specifications": {"type": "Electric Strike", "voltage": "12V DC", "mode": "Fail-safe/Fail-secure"}, "price": 35.0, "brand": "Hikvision", "accessories": [], "cable_requirements": {"type": "2C 0.75mm", "max_length_m": 50}},
    {"model_number": "DS-K7P03", "name": "Exit Button", "category": "Button", "system_type": "access_control", "description": "Plastic exit button with LED indicator", "specifications": {"type": "Push to exit", "led": "Yes"}, "price": 8.0, "brand": "Hikvision", "accessories": [], "cable_requirements": {"type": "2C 0.5mm", "max_length_m": 50}},
    # Monitor
    {"model_number": "DS-D5032QE", "name": "32\" LED Monitor", "category": "Monitor", "system_type": "cctv", "description": "32 inch Full HD LED monitor for CCTV surveillance", "specifications": {"size": "32 inch", "resolution": "1920x1080", "input": "HDMI, VGA"}, "price": 280.0, "brand": "Hikvision", "accessories": [{"name": "Wall Mount", "model": "Monitor-WM", "qty": 1}], "cable_requirements": {"type": "HDMI cable", "max_length_m": 15}},
    # Switches
    {"model_number": "DS-3E0518P-E/M", "name": "16-Port PoE Switch + 2 Uplink", "category": "Network Switch", "system_type": "cctv", "description": "16-port 100Mbps PoE + 2 Gigabit uplink, 230W PoE budget", "specifications": {"ports": "16 PoE + 2 Uplink", "poe_budget": "230W", "speed": "10/100Mbps"}, "price": 195.0, "brand": "Hikvision", "accessories": [{"name": "Rack Mount Kit", "model": "Switch-RMK", "qty": 1}], "cable_requirements": {"type": "CAT6 UTP", "max_length_m": 100}},
    # UPS
    {"model_number": "UPS-1000VA", "name": "1000VA Line Interactive UPS", "category": "UPS", "system_type": "cctv", "description": "1000VA/600W line interactive UPS for CCTV/access control equipment", "specifications": {"capacity": "1000VA/600W", "type": "Line Interactive", "backup_time": "15-30 min"}, "price": 180.0, "brand": "Generic", "accessories": [], "cable_requirements": {"type": "Power cable", "max_length_m": 3}},
]


class ProductCatalogService:
    async def seed_default_products(self, db: AsyncSession) -> int:
        count = 0
        for prod_data in HIKVISION_PRODUCT_DB:
            existing = await db.execute(
                select(Product).where(Product.model_number == prod_data["model_number"])
            )
            if existing.scalar_one_or_none() is None:
                product = Product(
                    model_number=prod_data["model_number"],
                    name=prod_data["name"],
                    category=prod_data["category"],
                    system_type=prod_data["system_type"],
                    description=prod_data["description"],
                    specifications=prod_data.get("specifications", {}),
                    price=prod_data.get("price", 0.0),
                    brand=prod_data.get("brand", "Hikvision"),
                    accessories=prod_data.get("accessories", []),
                    cable_requirements=prod_data.get("cable_requirements", {}),
                    source="built_in",
                )
                db.add(product)
                count += 1
        await db.commit()
        return count

    async def search_products(
        self,
        db: AsyncSession,
        query: str = "",
        system_type: str | None = None,
        category: str | None = None,
        source: str | None = None,
        page: int = 1,
        per_page: int = 20,
    ) -> list[Product]:
        stmt = select(Product)

        if query:
            search = f"%{query}%"
            stmt = stmt.where(
                or_(
                    Product.name.ilike(search),
                    Product.model_number.ilike(search),
                    Product.description.ilike(search),
                    Product.category.ilike(search),
                )
            )

        if system_type:
            stmt = stmt.where(Product.system_type == system_type)
        if category:
            stmt = stmt.where(Product.category.ilike(f"%{category}%"))
        if source:
            stmt = stmt.where(Product.source == source)

        stmt = stmt.offset((page - 1) * per_page).limit(per_page)
        result = await db.execute(stmt)
        return list(result.scalars().all())

    async def get_product_by_id(self, db: AsyncSession, product_id: str) -> Product | None:
        result = await db.execute(select(Product).where(Product.id == product_id))
        return result.scalar_one_or_none()

    async def get_product_by_model(self, db: AsyncSession, model_number: str) -> Product | None:
        result = await db.execute(
            select(Product).where(Product.model_number == model_number)
        )
        return result.scalar_one_or_none()

    async def search_hikvision_online(self, query: str) -> list[dict]:
        """Search Hikvision website for products (best-effort scraping)."""
        results = []
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                url = f"https://www.hikvision.com/en/search/?q={query}"
                response = await client.get(url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, "lxml")
                    product_cards = soup.select(".product-card, .search-result-item, .product-item")
                    for card in product_cards[:10]:
                        title_el = card.select_one("h3, .product-name, .title, a")
                        model_el = card.select_one(".model, .product-model, .sku")
                        desc_el = card.select_one("p, .description, .product-desc")
                        link_el = card.select_one("a[href]")

                        title = title_el.get_text(strip=True) if title_el else ""
                        model = model_el.get_text(strip=True) if model_el else ""
                        desc = desc_el.get_text(strip=True) if desc_el else ""
                        link = link_el.get("href", "") if link_el else ""

                        if title or model:
                            results.append({
                                "name": title,
                                "model_number": model,
                                "description": desc,
                                "url": f"https://www.hikvision.com{link}" if link.startswith("/") else link,
                                "source": "hikvision_online",
                            })
        except Exception as e:
            logger.warning("Hikvision online search failed: %s", e)

        return results

    async def import_product(self, db: AsyncSession, product_data: dict) -> Product:
        existing = await self.get_product_by_model(db, product_data.get("model_number", ""))
        if existing:
            return existing

        product = Product(
            model_number=product_data.get("model_number", "UNKNOWN"),
            name=product_data.get("name", "Unknown Product"),
            category=product_data.get("category", "Other"),
            system_type=product_data.get("system_type", "cctv"),
            description=product_data.get("description", ""),
            specifications=product_data.get("specifications", {}),
            price=product_data.get("price", 0.0),
            brand=product_data.get("brand", "Hikvision"),
            accessories=product_data.get("accessories", []),
            cable_requirements=product_data.get("cable_requirements", {}),
            source=product_data.get("source", "imported"),
        )
        db.add(product)
        await db.commit()
        await db.refresh(product)
        return product


product_catalog = ProductCatalogService()

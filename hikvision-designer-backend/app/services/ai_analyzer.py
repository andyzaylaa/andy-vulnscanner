"""AI-powered drawing analysis service using OpenAI Vision API."""
from __future__ import annotations

import base64
import json
import logging
from pathlib import Path

from openai import AsyncOpenAI

from app.config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert security and building systems designer. 
You analyze architectural floor plans and drawings to recommend placement of:
- CCTV cameras (indoor/outdoor, PTZ, dome, bullet, fisheye)
- Access control systems (card readers, controllers, electric locks, turnstiles)
- Gate barrier systems (boom barriers, bollards, sliding gates)
- Video door phones / intercoms
- Fire detection & alarm systems (smoke detectors, heat detectors, manual call points, sounders, panels)
- Sound / PA systems (ceiling speakers, horn speakers, amplifiers)

When analyzing a drawing, identify:
1. All rooms/areas and their purposes (entrance, corridor, office, parking, etc.)
2. Entry/exit points (doors, gates, windows)
3. Critical areas needing surveillance
4. Areas needing access control
5. Fire zones and evacuation routes
6. Areas suited for sound/PA coverage

For each area, suggest specific Hikvision products with model numbers when possible.
Provide exact coordinates (as percentages of image dimensions) for device placement.
Calculate cable runs and required accessories.

Return your analysis as structured JSON."""

ANALYSIS_PROMPT = """Analyze this architectural/floor plan drawing for a security and building systems integration project.

Provide a comprehensive JSON response with this structure:
{
    "areas": [
        {
            "name": "Area name",
            "type": "office|corridor|entrance|parking|stairwell|elevator|reception|server_room|warehouse|outdoor",
            "bounds": {"x1": 0.0, "y1": 0.0, "x2": 1.0, "y2": 1.0},
            "area_sqm_estimate": 50
        }
    ],
    "suggested_systems": [
        {
            "area": "Area name",
            "system_type": "cctv|access_control|gate|video_door_phone|fire|sound",
            "reason": "Why this system is needed here",
            "priority": "high|medium|low"
        }
    ],
    "suggested_products": [
        {
            "area": "Area name",
            "system_type": "cctv",
            "product_type": "Dome Camera",
            "suggested_model": "DS-2CD2143G2-I",
            "reason": "4MP indoor dome for office coverage",
            "quantity": 2
        }
    ],
    "suggested_placements": [
        {
            "area": "Area name",
            "system_type": "cctv",
            "device_type": "Dome Camera",
            "model": "DS-2CD2143G2-I",
            "x": 0.5,
            "y": 0.3,
            "rotation": 0,
            "coverage_note": "Covers main entrance hallway"
        }
    ],
    "cable_runs": [
        {
            "from_area": "Server Room",
            "to_area": "Main Entrance",
            "cable_type": "CAT6",
            "estimated_length_m": 30,
            "purpose": "IP Camera network connection",
            "system_type": "cctv"
        }
    ],
    "summary": "Overall analysis summary with key recommendations"
}

Be thorough and practical. Use real Hikvision model numbers where possible.
Consider cable pathways, power requirements, and network infrastructure.
For fire systems, follow standard spacing regulations (smoke detectors every 60sqm, etc.).
For CCTV, ensure no blind spots at entry/exit points."""


class AIAnalyzer:
    def __init__(self) -> None:
        self.client: AsyncOpenAI | None = None
        if settings.openai_api_key:
            self.client = AsyncOpenAI(api_key=settings.openai_api_key)

    async def analyze_drawing(self, image_path: str, page_number: int = 0) -> dict:
        if not self.client:
            logger.warning("OpenAI API key not configured, returning mock analysis")
            return self._generate_mock_analysis()

        image_data = self._encode_image(image_path)
        if not image_data:
            return {"error": "Failed to read image file"}

        try:
            response = await self.client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": ANALYSIS_PROMPT},
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{image_data}",
                                    "detail": "high",
                                },
                            },
                        ],
                    },
                ],
                max_tokens=4096,
                temperature=0.2,
            )

            content = response.choices[0].message.content or ""
            json_start = content.find("{")
            json_end = content.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(content[json_start:json_end])
            return {"summary": content, "areas": [], "suggested_systems": [], "suggested_products": [], "suggested_placements": [], "cable_runs": []}

        except Exception as e:
            logger.error("AI analysis failed: %s", e)
            return {"error": str(e)}

    def _encode_image(self, image_path: str) -> str | None:
        path = Path(image_path)
        if not path.exists():
            return None
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")

    def _generate_mock_analysis(self) -> dict:
        return {
            "areas": [
                {"name": "Main Entrance", "type": "entrance", "bounds": {"x1": 0.4, "y1": 0.85, "x2": 0.6, "y2": 1.0}, "area_sqm_estimate": 15},
                {"name": "Reception", "type": "reception", "bounds": {"x1": 0.3, "y1": 0.6, "x2": 0.7, "y2": 0.85}, "area_sqm_estimate": 40},
                {"name": "Main Corridor", "type": "corridor", "bounds": {"x1": 0.1, "y1": 0.4, "x2": 0.9, "y2": 0.6}, "area_sqm_estimate": 60},
                {"name": "Office Area A", "type": "office", "bounds": {"x1": 0.0, "y1": 0.0, "x2": 0.4, "y2": 0.4}, "area_sqm_estimate": 80},
                {"name": "Office Area B", "type": "office", "bounds": {"x1": 0.6, "y1": 0.0, "x2": 1.0, "y2": 0.4}, "area_sqm_estimate": 80},
                {"name": "Server Room", "type": "server_room", "bounds": {"x1": 0.4, "y1": 0.0, "x2": 0.6, "y2": 0.2}, "area_sqm_estimate": 20},
                {"name": "Parking Area", "type": "parking", "bounds": {"x1": 0.0, "y1": 0.85, "x2": 0.3, "y2": 1.0}, "area_sqm_estimate": 200},
            ],
            "suggested_systems": [
                {"area": "Main Entrance", "system_type": "cctv", "reason": "Monitor all visitors entering/exiting", "priority": "high"},
                {"area": "Main Entrance", "system_type": "access_control", "reason": "Control building access", "priority": "high"},
                {"area": "Main Entrance", "system_type": "video_door_phone", "reason": "Visitor verification", "priority": "high"},
                {"area": "Reception", "system_type": "cctv", "reason": "Monitor reception area", "priority": "high"},
                {"area": "Main Corridor", "system_type": "cctv", "reason": "Corridor surveillance", "priority": "medium"},
                {"area": "Main Corridor", "system_type": "fire", "reason": "Fire detection in corridor", "priority": "high"},
                {"area": "Main Corridor", "system_type": "sound", "reason": "PA announcements", "priority": "medium"},
                {"area": "Office Area A", "system_type": "cctv", "reason": "Office monitoring", "priority": "medium"},
                {"area": "Office Area A", "system_type": "fire", "reason": "Smoke detection", "priority": "high"},
                {"area": "Office Area B", "system_type": "cctv", "reason": "Office monitoring", "priority": "medium"},
                {"area": "Office Area B", "system_type": "fire", "reason": "Smoke detection", "priority": "high"},
                {"area": "Server Room", "system_type": "access_control", "reason": "Restricted access", "priority": "high"},
                {"area": "Server Room", "system_type": "cctv", "reason": "24/7 monitoring of critical infrastructure", "priority": "high"},
                {"area": "Server Room", "system_type": "fire", "reason": "Early fire detection for equipment protection", "priority": "high"},
                {"area": "Parking Area", "system_type": "cctv", "reason": "Vehicle and perimeter surveillance", "priority": "high"},
                {"area": "Parking Area", "system_type": "gate", "reason": "Vehicle access control", "priority": "high"},
            ],
            "suggested_products": [
                {"area": "Main Entrance", "system_type": "cctv", "product_type": "Dome Camera", "suggested_model": "DS-2CD2183G2-I", "reason": "8MP dome for entrance coverage", "quantity": 1},
                {"area": "Main Entrance", "system_type": "access_control", "product_type": "Card Reader", "suggested_model": "DS-K1T804MF", "reason": "Fingerprint & card reader", "quantity": 1},
                {"area": "Main Entrance", "system_type": "video_door_phone", "product_type": "Door Station", "suggested_model": "DS-KV8113-WME1", "reason": "IP video intercom door station", "quantity": 1},
                {"area": "Reception", "system_type": "cctv", "product_type": "Dome Camera", "suggested_model": "DS-2CD2143G2-I", "reason": "4MP indoor dome", "quantity": 2},
                {"area": "Main Corridor", "system_type": "cctv", "product_type": "Dome Camera", "suggested_model": "DS-2CD2143G2-I", "reason": "4MP corridor cameras", "quantity": 3},
                {"area": "Main Corridor", "system_type": "fire", "product_type": "Smoke Detector", "suggested_model": "DS-PDSMK-S-WE", "reason": "Wireless smoke detector", "quantity": 4},
                {"area": "Main Corridor", "system_type": "sound", "product_type": "Ceiling Speaker", "suggested_model": "DS-QAZ0206G", "reason": "PA ceiling speaker", "quantity": 3},
                {"area": "Office Area A", "system_type": "cctv", "product_type": "Dome Camera", "suggested_model": "DS-2CD2143G2-I", "reason": "Office surveillance", "quantity": 2},
                {"area": "Office Area A", "system_type": "fire", "product_type": "Smoke Detector", "suggested_model": "DS-PDSMK-S-WE", "reason": "Fire detection", "quantity": 2},
                {"area": "Office Area B", "system_type": "cctv", "product_type": "Dome Camera", "suggested_model": "DS-2CD2143G2-I", "reason": "Office surveillance", "quantity": 2},
                {"area": "Office Area B", "system_type": "fire", "product_type": "Smoke Detector", "suggested_model": "DS-PDSMK-S-WE", "reason": "Fire detection", "quantity": 2},
                {"area": "Server Room", "system_type": "access_control", "product_type": "Card Reader", "suggested_model": "DS-K1T804MF", "reason": "Biometric access for server room", "quantity": 1},
                {"area": "Server Room", "system_type": "cctv", "product_type": "Dome Camera", "suggested_model": "DS-2CD2143G2-I", "reason": "Server room monitoring", "quantity": 1},
                {"area": "Parking Area", "system_type": "cctv", "product_type": "Bullet Camera", "suggested_model": "DS-2CD2T47G2-L", "reason": "Outdoor bullet with ColorVu", "quantity": 4},
                {"area": "Parking Area", "system_type": "gate", "product_type": "Barrier Gate", "suggested_model": "DS-TMG4B0-RA", "reason": "Vehicle barrier gate", "quantity": 1},
            ],
            "suggested_placements": [
                {"area": "Main Entrance", "system_type": "cctv", "device_type": "Dome Camera", "model": "DS-2CD2183G2-I", "x": 0.5, "y": 0.9, "rotation": 0, "coverage_note": "Covers entrance door"},
                {"area": "Main Entrance", "system_type": "access_control", "device_type": "Card Reader", "model": "DS-K1T804MF", "x": 0.45, "y": 0.88, "rotation": 0, "coverage_note": "Next to entrance door"},
                {"area": "Reception", "system_type": "cctv", "device_type": "Dome Camera", "model": "DS-2CD2143G2-I", "x": 0.4, "y": 0.7, "rotation": 0, "coverage_note": "Reception desk area"},
                {"area": "Reception", "system_type": "cctv", "device_type": "Dome Camera", "model": "DS-2CD2143G2-I", "x": 0.6, "y": 0.65, "rotation": 0, "coverage_note": "Reception waiting area"},
                {"area": "Main Corridor", "system_type": "cctv", "device_type": "Dome Camera", "model": "DS-2CD2143G2-I", "x": 0.2, "y": 0.5, "rotation": 0, "coverage_note": "Corridor left section"},
                {"area": "Main Corridor", "system_type": "cctv", "device_type": "Dome Camera", "model": "DS-2CD2143G2-I", "x": 0.5, "y": 0.5, "rotation": 0, "coverage_note": "Corridor center"},
                {"area": "Main Corridor", "system_type": "cctv", "device_type": "Dome Camera", "model": "DS-2CD2143G2-I", "x": 0.8, "y": 0.5, "rotation": 0, "coverage_note": "Corridor right section"},
                {"area": "Parking Area", "system_type": "cctv", "device_type": "Bullet Camera", "model": "DS-2CD2T47G2-L", "x": 0.05, "y": 0.9, "rotation": 45, "coverage_note": "Parking corner 1"},
                {"area": "Parking Area", "system_type": "cctv", "device_type": "Bullet Camera", "model": "DS-2CD2T47G2-L", "x": 0.25, "y": 0.9, "rotation": -45, "coverage_note": "Parking corner 2"},
                {"area": "Parking Area", "system_type": "gate", "device_type": "Barrier Gate", "model": "DS-TMG4B0-RA", "x": 0.15, "y": 0.95, "rotation": 90, "coverage_note": "Parking entrance"},
            ],
            "cable_runs": [
                {"from_area": "Server Room", "to_area": "Main Entrance", "cable_type": "CAT6 UTP", "estimated_length_m": 40, "purpose": "IP Camera + Access Control", "system_type": "cctv"},
                {"from_area": "Server Room", "to_area": "Reception", "cable_type": "CAT6 UTP", "estimated_length_m": 25, "purpose": "IP Cameras", "system_type": "cctv"},
                {"from_area": "Server Room", "to_area": "Main Corridor", "cable_type": "CAT6 UTP", "estimated_length_m": 20, "purpose": "IP Cameras x3", "system_type": "cctv"},
                {"from_area": "Server Room", "to_area": "Office Area A", "cable_type": "CAT6 UTP", "estimated_length_m": 35, "purpose": "IP Cameras x2", "system_type": "cctv"},
                {"from_area": "Server Room", "to_area": "Office Area B", "cable_type": "CAT6 UTP", "estimated_length_m": 35, "purpose": "IP Cameras x2", "system_type": "cctv"},
                {"from_area": "Server Room", "to_area": "Parking Area", "cable_type": "CAT6 FTP Outdoor", "estimated_length_m": 80, "purpose": "Outdoor cameras x4", "system_type": "cctv"},
                {"from_area": "Fire Panel", "to_area": "All Areas", "cable_type": "Fire rated 2C 1.5mm", "estimated_length_m": 200, "purpose": "Smoke detector loop", "system_type": "fire"},
                {"from_area": "Sound Amplifier", "to_area": "Main Corridor", "cable_type": "Speaker cable 2C 1.5mm", "estimated_length_m": 60, "purpose": "PA speakers", "system_type": "sound"},
            ],
            "summary": "Comprehensive security system design covering CCTV surveillance with IP cameras, biometric access control at critical points, parking barrier gate, video intercom at main entrance, fire detection throughout, and PA system in common areas. Total of 15 cameras, 2 access control points, 1 barrier gate, 1 video intercom, 8 smoke detectors, and 3 PA speakers recommended.",
        }


ai_analyzer = AIAnalyzer()

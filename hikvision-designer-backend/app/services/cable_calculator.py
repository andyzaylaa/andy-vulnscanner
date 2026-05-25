"""Cable and accessories calculator for security system installations."""
from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass
class CableRun:
    cable_type: str
    length_m: float
    purpose: str
    system_type: str
    from_location: str = ""
    to_location: str = ""


@dataclass
class CableRequirement:
    cable_type: str
    total_length_m: float
    quantity_rolls: int
    roll_length_m: float
    purpose: str
    system_type: str
    wastage_percent: float = 15.0


@dataclass
class AccessoryRequirement:
    name: str
    model_number: str
    quantity: int
    purpose: str
    for_product: str
    system_type: str


CABLE_TYPES = {
    "CAT6 UTP": {"roll_length": 305, "description": "CAT6 UTP Ethernet Cable", "unit_price": 85.0},
    "CAT6 FTP": {"roll_length": 305, "description": "CAT6 FTP Shielded Ethernet Cable", "unit_price": 120.0},
    "CAT6 FTP Outdoor": {"roll_length": 305, "description": "CAT6 FTP Outdoor Rated Ethernet Cable", "unit_price": 150.0},
    "Fire rated 2C 1.5mm": {"roll_length": 200, "description": "Fire Rated Cable 2 Core 1.5mm²", "unit_price": 95.0},
    "2C 0.75mm": {"roll_length": 200, "description": "Control Cable 2 Core 0.75mm²", "unit_price": 45.0},
    "2C 0.5mm": {"roll_length": 200, "description": "Signal Cable 2 Core 0.5mm²", "unit_price": 35.0},
    "4C 0.5mm shielded": {"roll_length": 200, "description": "Shielded Cable 4 Core 0.5mm²", "unit_price": 65.0},
    "Speaker cable 2C 1.5mm": {"roll_length": 200, "description": "Speaker Cable 2 Core 1.5mm²", "unit_price": 55.0},
    "5C 2.5mm": {"roll_length": 100, "description": "Power Cable 5 Core 2.5mm²", "unit_price": 110.0},
    "5C 4mm": {"roll_length": 100, "description": "Power Cable 5 Core 4mm²", "unit_price": 160.0},
    "HDMI cable": {"roll_length": 1, "description": "HDMI Cable", "unit_price": 15.0},
    "Power cable": {"roll_length": 1, "description": "Power Cable", "unit_price": 10.0},
    "Loop wire": {"roll_length": 100, "description": "Vehicle Detection Loop Wire", "unit_price": 80.0},
}

STANDARD_ACCESSORIES = {
    "cctv": [
        {"name": "Cable Trunking 40x25mm", "model": "CT-4025", "per_10m_cable": 1, "unit_price": 3.0},
        {"name": "RJ45 Connector", "model": "RJ45-CAT6", "per_device": 2, "unit_price": 0.5},
        {"name": "Cable Tie 200mm", "model": "CT-200", "per_device": 10, "unit_price": 0.02},
        {"name": "PVC Conduit 20mm (3m)", "model": "PVC-20", "per_10m_cable": 1, "unit_price": 2.5},
    ],
    "access_control": [
        {"name": "Cable Trunking 40x25mm", "model": "CT-4025", "per_10m_cable": 1, "unit_price": 3.0},
        {"name": "Power Supply 12V 5A", "model": "PS-12V5A", "per_controller": 1, "unit_price": 25.0},
    ],
    "fire": [
        {"name": "Fire Rated Cable Clip", "model": "FC-15", "per_meter": 1, "unit_price": 0.3},
        {"name": "Junction Box (Fire Rated)", "model": "JB-FR", "per_4_devices": 1, "unit_price": 8.0},
    ],
    "sound": [
        {"name": "Cable Trunking 25x16mm", "model": "CT-2516", "per_10m_cable": 1, "unit_price": 2.0},
        {"name": "Speaker Terminal Block", "model": "STB-2", "per_device": 1, "unit_price": 1.5},
    ],
    "gate": [
        {"name": "Flexible Conduit 25mm", "model": "FC-25", "per_device": 3, "unit_price": 4.0},
    ],
}


class CableCalculator:
    def calculate_cables(
        self,
        cable_runs: list[dict],
        wastage_percent: float = 15.0,
    ) -> list[CableRequirement]:
        cable_totals: dict[str, dict] = {}

        for run in cable_runs:
            cable_type = run.get("cable_type", "CAT6 UTP")
            length = run.get("estimated_length_m", 0)
            purpose = run.get("purpose", "")
            system_type = run.get("system_type", "cctv")

            if cable_type not in cable_totals:
                cable_totals[cable_type] = {
                    "total_length": 0,
                    "purposes": [],
                    "system_type": system_type,
                }

            cable_totals[cable_type]["total_length"] += length
            if purpose and purpose not in cable_totals[cable_type]["purposes"]:
                cable_totals[cable_type]["purposes"].append(purpose)

        requirements = []
        for cable_type, data in cable_totals.items():
            total_with_wastage = data["total_length"] * (1 + wastage_percent / 100)
            cable_info = CABLE_TYPES.get(cable_type, {"roll_length": 305})
            roll_length = cable_info["roll_length"]

            if roll_length > 1:
                qty_rolls = math.ceil(total_with_wastage / roll_length)
            else:
                qty_rolls = math.ceil(total_with_wastage)

            requirements.append(CableRequirement(
                cable_type=cable_type,
                total_length_m=round(total_with_wastage, 1),
                quantity_rolls=max(1, qty_rolls),
                roll_length_m=roll_length,
                purpose=", ".join(data["purposes"]),
                system_type=data["system_type"],
                wastage_percent=wastage_percent,
            ))

        return requirements

    def calculate_accessories(
        self,
        products: list[dict],
        cable_runs: list[dict],
    ) -> list[AccessoryRequirement]:
        accessories: list[AccessoryRequirement] = []
        product_accessories_seen: set[str] = set()

        for prod in products:
            prod_accessories = prod.get("accessories", [])
            quantity = prod.get("quantity", 1)
            model = prod.get("model_number", prod.get("suggested_model", ""))
            system_type = prod.get("system_type", "cctv")

            for acc in prod_accessories:
                acc_model = acc.get("model", acc.get("model_number", ""))
                key = f"{acc_model}_{model}"

                if key not in product_accessories_seen:
                    product_accessories_seen.add(key)
                    acc_qty = acc.get("qty", acc.get("quantity", 1))
                    accessories.append(AccessoryRequirement(
                        name=acc.get("name", ""),
                        model_number=acc_model,
                        quantity=acc_qty * quantity,
                        purpose=f"For {model}",
                        for_product=model,
                        system_type=system_type,
                    ))

        cable_by_system: dict[str, float] = {}
        device_count_by_system: dict[str, int] = {}

        for run in cable_runs:
            length = run.get("estimated_length_m", 0)
            system_type = run.get("system_type", "cctv")
            cable_by_system[system_type] = cable_by_system.get(system_type, 0) + length
            device_count_by_system[system_type] = device_count_by_system.get(system_type, 0) + 1

        for system_type, std_accessories in STANDARD_ACCESSORIES.items():
            device_count = device_count_by_system.get(system_type, 0)
            if device_count == 0:
                continue

            for acc in std_accessories:
                qty = 0
                if "per_device" in acc:
                    qty = acc["per_device"] * device_count
                elif "per_10m_cable" in acc:
                    system_cable = cable_by_system.get(system_type, 0)
                    qty = math.ceil(system_cable / 10) * acc["per_10m_cable"]
                elif "per_controller" in acc:
                    qty = max(1, device_count // 4) * acc["per_controller"]
                elif "per_meter" in acc:
                    system_cable = cable_by_system.get(system_type, 0)
                    qty = math.ceil(system_cable)
                elif "per_4_devices" in acc:
                    qty = math.ceil(device_count / 4)

                if qty > 0:
                    accessories.append(AccessoryRequirement(
                        name=acc["name"],
                        model_number=acc["model"],
                        quantity=qty,
                        purpose=f"Standard accessory for {system_type}",
                        for_product="System Infrastructure",
                        system_type=system_type,
                    ))

        return accessories


cable_calculator = CableCalculator()

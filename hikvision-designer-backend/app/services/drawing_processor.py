"""Drawing file processor - handles PDF and image files."""
from __future__ import annotations

import logging
import uuid
from pathlib import Path

import fitz  # PyMuPDF
from PIL import Image

from app.config import UPLOAD_PATH

logger = logging.getLogger(__name__)


class DrawingProcessor:
    SUPPORTED_IMAGE_TYPES = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".tif", ".webp"}
    SUPPORTED_DOC_TYPES = {".pdf"}
    DPI = 200

    async def process_upload(self, file_content: bytes, filename: str) -> list[dict]:
        suffix = Path(filename).suffix.lower()
        file_id = str(uuid.uuid4())

        if suffix in self.SUPPORTED_DOC_TYPES:
            return await self._process_pdf(file_content, file_id, filename)
        elif suffix in self.SUPPORTED_IMAGE_TYPES:
            return await self._process_image(file_content, file_id, filename)
        else:
            raise ValueError(f"Unsupported file type: {suffix}")

    async def _process_pdf(self, content: bytes, file_id: str, filename: str) -> list[dict]:
        pages = []
        pdf_path = UPLOAD_PATH / f"{file_id}.pdf"
        pdf_path.write_bytes(content)

        doc = fitz.open(str(pdf_path))
        for page_num in range(len(doc)):
            page = doc[page_num]
            mat = fitz.Matrix(self.DPI / 72, self.DPI / 72)
            pix = page.get_pixmap(matrix=mat)

            image_filename = f"{file_id}_page_{page_num}.png"
            image_path = UPLOAD_PATH / image_filename
            pix.save(str(image_path))

            pages.append({
                "page_number": page_num,
                "file_path": str(image_path),
                "filename": f"{filename} - Page {page_num + 1}",
                "width": pix.width,
                "height": pix.height,
                "file_type": "pdf",
            })

        doc.close()
        return pages

    async def _process_image(self, content: bytes, file_id: str, filename: str) -> list[dict]:
        suffix = Path(filename).suffix.lower()
        image_filename = f"{file_id}{suffix}"
        image_path = UPLOAD_PATH / image_filename
        image_path.write_bytes(content)

        with Image.open(image_path) as img:
            width, height = img.size

            png_filename = f"{file_id}.png"
            png_path = UPLOAD_PATH / png_filename
            if suffix != ".png":
                img.save(str(png_path), "PNG")
            else:
                png_path = image_path

        return [{
            "page_number": 0,
            "file_path": str(png_path),
            "filename": filename,
            "width": width,
            "height": height,
            "file_type": "image",
        }]

    def get_image_path(self, drawing_file_path: str) -> str | None:
        path = Path(drawing_file_path)
        if path.exists():
            return str(path)
        return None


drawing_processor = DrawingProcessor()

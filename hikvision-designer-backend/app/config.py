from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    app_name: str = "HikVision System Designer"
    database_url: str = "sqlite+aiosqlite:///./data/designer.db"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    upload_dir: str = "./uploads"
    max_upload_size_mb: int = 50
    hikvision_base_url: str = "https://www.hikvision.com"
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()

UPLOAD_PATH = Path(settings.upload_dir)
UPLOAD_PATH.mkdir(parents=True, exist_ok=True)

DATA_PATH = Path("./data")
DATA_PATH.mkdir(parents=True, exist_ok=True)

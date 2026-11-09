import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")


DEFAULT_ALLOWED_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://*.vercel.app",
)


class Settings:
    def __init__(self) -> None:
        self.app_name = os.getenv("APP_NAME", "AI Threat Intelligence")
        self.port = int(os.getenv("PORT", "8000"))

    @property
    def allowed_origins(self) -> list[str]:
        configured_origins = os.getenv("ALLOWED_ORIGINS")
        if configured_origins is None:
            return list(DEFAULT_ALLOWED_ORIGINS)
        return [
            origin.strip().rstrip("/")
            for origin in configured_origins.split(",")
            if origin.strip()
        ]


settings = Settings()

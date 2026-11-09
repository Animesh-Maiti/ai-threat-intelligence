from contextlib import asynccontextmanager
import re
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
from app.core.config import settings
from app.modules.campaign_correlator import ensure_history_directory


@asynccontextmanager
async def lifespan(_: FastAPI):
    ensure_history_directory()
    yield


def _origin_regex(origins: list[str]) -> str | None:
    wildcard_origins = [origin for origin in origins if "*" in origin]
    if not wildcard_origins:
        return None
    patterns = [
        re.escape(origin).replace(r"\*", r"[^/]+")
        for origin in wildcard_origins
    ]
    return rf"^(?:{'|'.join(patterns)})$"

app = FastAPI(
    title="SpecterShield AI API",
    description="Threat intelligence and verifiable security ledger engine",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin for origin in settings.allowed_origins if "*" not in origin],
    allow_origin_regex=_origin_regex(settings.allowed_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Crucial: This mounts your endpoints under /api/v1
app.include_router(router, prefix="/api/v1")

@app.get("/")
@app.get("/health")
def health_check():
    return {"status": "online", "version": "1.0.0"}


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.port,
        workers=2,
    )
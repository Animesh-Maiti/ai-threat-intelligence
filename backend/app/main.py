from fastapi import FastAPI

from app.api.routes import router

app = FastAPI(title="AI Threat Intelligence API")
app.include_router(router, prefix="/api")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

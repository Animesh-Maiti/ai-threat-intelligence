from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router

app = FastAPI(
    title="AI-Powered Web Threat & Digital Trust Intelligence",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Crucial: This mounts your endpoints under /api/v1
app.include_router(router, prefix="/api/v1")

@app.get("/health")
def health_check():
    return {"status": "healthy"}
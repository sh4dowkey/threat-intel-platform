from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.database import engine, Base
from app.core.redis import close_redis
from app.api.ioc import router as ioc_router
from app.api.ml import router as ml_router
from app.api.alerts import router as alerts_router
import app.models.alert  # noqa: F401
import app.models.ioc  # noqa — registers table with SQLAlchemy

#startup and shutdown logic
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await close_redis()
    await engine.dispose()


app = FastAPI(
    title="Threat Intelligence Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:5173",
    "https://threat-intel-platform.vercel.app",
    "https://threat-intel-platform-production.up.railway.app",],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ioc_router)

app.include_router(ml_router)

app.include_router(alerts_router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "threat-intel-platform"}
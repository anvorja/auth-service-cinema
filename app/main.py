# app/main.py
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    import asyncio
    from app.core import redis_client
    from app.kafka.producer import start_producer, stop_producer
    from app.kafka.consumer import start_consumer
    from app.core.database import SessionLocal

    logger.info("Auth Service starting...")

    from app.models.base import Base
    from app.core.database import engine
    Base.metadata.create_all(bind=engine)

    if redis_client.is_healthy():
        logger.info("Redis blacklist: connected")
    else:
        logger.warning("Redis blacklist: unavailable — logout will not invalidate tokens")

    await start_producer()
    consumer_task = asyncio.create_task(start_consumer(SessionLocal))

    yield

    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass
    await stop_producer()
    logger.info("Auth Service shutting down")


app = FastAPI(
    title="Auth Service",
    version="1.0.0",
    description="Authentication and token management service",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health")
async def health():
    from app.core import redis_client
    return {
        "status": "healthy",
        "service": "auth-service",
        "redis_blacklist": redis_client.is_healthy(),
    }

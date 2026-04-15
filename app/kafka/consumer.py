# app/kafka/consumer.py — auth-service
#
# Consume eventos de dominio que afectan la capa de autenticación:
#   • user.deactivated → marcar usuario como inactivo en cinema_auth
#     (publicado por user-service cuando el admin desactiva o el usuario
#     elimina su propia cuenta)
#
import asyncio
import json
import logging
import ssl

from aiokafka import AIOKafkaConsumer
from app.core.config import settings

logger = logging.getLogger(__name__)


async def _handle_user_deactivated(payload: dict, db_factory) -> None:
    from sqlalchemy import text
    user_id = payload.get("user_id")
    if not user_id:
        logger.warning("user.deactivated payload missing user_id: %s", payload)
        return
    with db_factory() as db:
        db.execute(
            text("UPDATE users SET is_active = false WHERE id = :uid"),
            {"uid": user_id},
        )
        db.commit()
    logger.info("User deactivated in cinema_auth | user_id=%s", user_id)


_HANDLERS = {
    "user.deactivated": _handle_user_deactivated,
}


async def start_consumer(db_factory) -> None:
    if not settings.KAFKA_ENABLED:
        logger.info("Kafka disabled — auth consumer not started")
        return

    ssl_context = ssl.create_default_context()
    consumer = AIOKafkaConsumer(
        *_HANDLERS.keys(),
        bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
        security_protocol="SASL_SSL",
        sasl_mechanism="PLAIN",
        sasl_plain_username=settings.KAFKA_API_KEY,
        sasl_plain_password=settings.KAFKA_API_SECRET,
        ssl_context=ssl_context,
        group_id="auth-service-group",
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )

    await consumer.start()
    logger.info("Auth consumer started | topics=%s", list(_HANDLERS.keys()))

    try:
        async for msg in consumer:
            handler = _HANDLERS.get(msg.topic)
            if handler:
                try:
                    await handler(msg.value, db_factory)
                except Exception as e:
                    logger.error("Error handling %s: %s", msg.topic, e)
    except asyncio.CancelledError:
        pass
    finally:
        await consumer.stop()
        logger.info("Auth consumer stopped")

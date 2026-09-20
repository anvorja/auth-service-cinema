# app/core/config.py
from pydantic import field_validator
from pydantic_settings import BaseSettings
from typing import List, Any


class Settings(BaseSettings):
    PROJECT_NAME: str = "Auth Service"
    VERSION: str = "1.0.0"

    DATABASE_URL: str
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 30

    REDIS_URL: str = ""

    # Kafka
    KAFKA_ENABLED: bool = False
    KAFKA_BOOTSTRAP_SERVERS: str = ""
    KAFKA_API_KEY: str = ""
    KAFKA_API_SECRET: str = ""
    # Default = group_id histórico de producción, sin variable nueva en Render.
    # Local lo sobreescribe con sufijo "-local" — dev y prod comparten el
    # mismo cluster de Confluent Cloud, y sin distinguir el group_id ambos
    # entornos terminan en el MISMO grupo de consumidores.
    KAFKA_GROUP_ID: str = "auth-service-group"

    EMAIL_HOST: str = "smtp.gmail.com"
    EMAIL_PORT: int = 465
    EMAIL_USER: str = ""
    EMAIL_APP_PASSWORD: str = ""

    DEBUG: bool = False

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }


settings = Settings()

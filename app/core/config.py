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

    EMAIL_HOST: str = "smtp.gmail.com"
    EMAIL_PORT: int = 465
    EMAIL_USER: str = ""
    EMAIL_APP_PASSWORD: str = ""

    DEBUG: bool = False

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


settings = Settings()

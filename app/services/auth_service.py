# app/services/auth_service.py
import logging
import re
from typing import Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.user import User, UserRole
from app.schemas.auth import UserRegister, UserLogin
from app.core.security import verify_password, get_password_hash, create_access_token, decode_token
from app.core import redis_client

logger = logging.getLogger(__name__)


def _validate_email(email: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))


def _validate_phone(phone: str) -> bool:
    clean = re.sub(r'[\s-]', '', phone)
    return any(
        bool(re.match(p, clean))
        for p in [r'^\+57[39]\d{9}$', r'^57[39]\d{9}$', r'^[39]\d{9}$']
    )


class AuthService:

    @staticmethod
    async def register_user(db: Session, data: UserRegister) -> User:
        if not _validate_email(data.email):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid email format")
        if not _validate_phone(data.phone):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Invalid phone format. Use Colombian format: 3XXXXXXXXX"
            )
        if db.query(User).filter(User.email == data.email).first():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email already registered")

        user = User(
            email=data.email,
            phone=data.phone,
            first_name=data.first_name,
            last_name=data.last_name,
            password_hash=get_password_hash(data.password),
            role=UserRole.CUSTOMER,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info("User registered: %s", user.email)

        # Notificar a user-service para que cree el perfil en cinema_users
        try:
            from app.kafka.producer import publish_event
            await publish_event("user.registered", {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "phone": user.phone,
                "role": user.role.value,
            })
        except Exception as e:
            logger.warning("Could not publish user.registered event: %s", e)

        return user

    @staticmethod
    def login_user(db: Session, data: UserLogin) -> dict:
        user = db.query(User).filter(
            User.email == data.email, User.is_active == True
        ).first()

        if not user or not verify_password(data.password, user.password_hash):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = create_access_token(subject=user.email)
        payload = decode_token(token)
        exp = payload.get("exp", 0) if payload else 0
        redis_client.track_user_token(user.id, token, exp)
        logger.info("User logged in: %s", user.email)
        return {"access_token": token, "token_type": "bearer", "user": user}

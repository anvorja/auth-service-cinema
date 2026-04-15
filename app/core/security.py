# app/core/security.py
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from .config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_REFRESH_TOKEN_EXPIRE_DAYS = 7
_REFRESH_TYPE_CLAIM = "refresh"


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    )
    return jwt.encode(
        {"exp": expire, "sub": subject, "type": "access"},
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token(subject: str) -> str:
    """
    Issue a refresh token with 7-day TTL.
    Claims include type='refresh' so it cannot be used as an access token.
    """
    expire = datetime.now(timezone.utc) + timedelta(days=_REFRESH_TOKEN_EXPIRE_DAYS)
    return jwt.encode(
        {"exp": expire, "sub": subject, "type": _REFRESH_TYPE_CLAIM},
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_token(token: str) -> Optional[dict]:
    """Return full payload or None on invalid/expired token."""
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return None


def decode_refresh_token(token: str) -> Optional[str]:
    """
    Validate a refresh token and return the subject (email).
    Returns None if invalid, expired, or not a refresh token.
    """
    payload = decode_token(token)
    if not payload:
        return None
    if payload.get("type") != _REFRESH_TYPE_CLAIM:
        return None
    return payload.get("sub")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

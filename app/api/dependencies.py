# app/api/dependencies.py
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_token
from app.core import redis_client
from app.models.user import User

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    exc = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = credentials.credentials

    if redis_client.is_blacklisted(token):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Token has been invalidated. Please login again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(token)
    if not payload:
        raise exc

    user_email = payload.get("sub")
    if not user_email:
        raise exc

    user = db.query(User).filter(User.email == user_email, User.is_active == True).first()
    if not user:
        raise exc
    return user


async def get_current_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    return credentials.credentials

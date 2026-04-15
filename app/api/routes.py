# app/api/routes.py
import hashlib
import logging
import re
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_token, create_refresh_token, decode_refresh_token
from app.core import redis_client
from app.services.auth_service import AuthService
from pydantic import BaseModel as _BaseModel, Field
from app.schemas.auth import (
    UserRegister, UserLogin, Token, UserResponse,
    LogoutResponse, VerifyTokenResponse,
)


class RefreshRequest(_BaseModel):
    refresh_token: str
from app.api.dependencies import get_current_user, get_current_token
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister, db: Session = Depends(get_db)):
    user = await AuthService.register_user(db, user_data)
    return UserResponse.from_orm(user)


@router.post("/login", response_model=Token)
async def login(request: Request, login_data: UserLogin, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"

    try:
        result = AuthService.login_user(db, login_data)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            attempts = redis_client.increment_email_attempt(login_data.email)

            if attempts >= redis_client.RESET_TRIGGER_ATTEMPTS:
                # Only trigger reset for real, active accounts (avoids leaking account existence
                # through timing — query happens regardless of whether email exists).
                _user = db.query(User).filter(
                    User.email == login_data.email, User.is_active == True
                ).first()
                if _user and not redis_client.is_reset_email_on_cooldown(login_data.email):
                    _token = secrets.token_urlsafe(32)
                    _token_hash = hashlib.sha256(_token.encode()).hexdigest()
                    redis_client.store_password_reset_token(login_data.email, _token_hash)
                    redis_client.mark_reset_email_sent(login_data.email)
                    try:
                        from app.kafka.producer import publish_event
                        await publish_event("auth.password_reset_requested", {
                            "user_email": _user.email,
                            "customer_name": _user.first_name,
                            "reset_token": _token,
                        })
                    except Exception as _e:
                        logger.warning("Could not publish password reset event: %s", _e)
                exc.detail = (
                    "Credenciales incorrectas. Por seguridad, hemos enviado un correo "
                    "electrónico para restablecer tu contraseña."
                )
            else:
                remaining = redis_client.RESET_TRIGGER_ATTEMPTS - attempts
                exc.detail = (
                    f"Credenciales incorrectas. "
                    f"Tras {remaining} intento(s) más se solicitará el cambio de contraseña."
                )
        raise

    redis_client.reset_login_attempts(client_ip)
    redis_client.reset_email_attempts(login_data.email)
    user = result["user"]
    refresh_token = create_refresh_token(subject=user.email)
    return {
        "access_token": result["access_token"],
        "refresh_token": refresh_token,
        "token_type": result["token_type"],
        "user": {
            "id": user.id,
            "email": user.email,
            "firstName": user.first_name,
            "lastName": user.last_name,
            "role": user.role.value,
            "phone": user.phone,
            "full_name": user.full_name,
            "is_active": user.is_active,
        },
    }


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    token: str = Depends(get_current_token),
    current_user: User = Depends(get_current_user),
):
    payload = decode_token(token)
    exp = payload.get("exp", 0) if payload else 0

    success = redis_client.blacklist_token(token, exp)
    if not success:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Error processing logout. Please try again.",
        )

    return LogoutResponse(
        message="Sesión cerrada exitosamente. Token invalidado inmediatamente.",
        user_id=current_user.id,
    )


@router.post("/logout-all")
async def logout_all(current_user: User = Depends(get_current_user)):
    """
    Invalidate every active session for the current user by blacklisting
    all tracked tokens stored in Redis (Sorted Set user_tokens:<user_id>).
    """
    revoked = redis_client.revoke_all_user_tokens(current_user.id)
    return {
        "message": f"Todas las sesiones cerradas. {revoked} token(s) invalidado(s).",
        "user_id": current_user.id,
        "revoked_count": revoked,
    }


@router.post("/refresh")
async def refresh_access_token(body: RefreshRequest, db: Session = Depends(get_db)):
    """
    Emite un nuevo access token usando un refresh token válido.
    No requiere Authorization header — el refresh token es la credencial.
    """
    credentials_exception = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Refresh token inválido o expirado. Inicia sesión de nuevo.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    user_email = decode_refresh_token(body.refresh_token)
    if not user_email:
        raise credentials_exception

    # Check refresh token not blacklisted (covers logout-all scenario)
    if redis_client.is_blacklisted(body.refresh_token):
        raise credentials_exception

    user = db.query(User).filter(User.email == user_email, User.is_active == True).first()
    if not user:
        raise credentials_exception

    from app.core.security import create_access_token, decode_token
    new_access_token = create_access_token(subject=user.email)
    payload = decode_token(new_access_token)
    exp = payload.get("exp", 0) if payload else 0
    redis_client.track_user_token(user.id, new_access_token, exp)

    return {
        "access_token": new_access_token,
        "token_type": "bearer",
    }


@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(get_current_user)):
    return UserResponse.from_orm(current_user)


class PasswordChangeRequest(_BaseModel):
    current_password: str = Field(..., description="Contraseña actual")
    new_password: str = Field(..., min_length=6, description="Nueva contraseña (mínimo 6 caracteres)")


@router.put("/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    data: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Cambiar contraseña. Requiere la contraseña actual para confirmar la identidad.
    Responsabilidad de auth-service porque es el dueño de las credenciales.
    """
    from app.core.security import verify_password, get_password_hash
    if not verify_password(data.current_password, current_user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Contraseña actual incorrecta")
    current_user.password_hash = get_password_hash(data.new_password)
    db.commit()


@router.get("/verify-token", response_model=VerifyTokenResponse)
async def verify_token(current_user: User = Depends(get_current_user)):
    """
    Internal endpoint used by other services to validate tokens
    (includes blacklist check via Redis).
    """
    return VerifyTokenResponse(
        valid=True,
        user_id=current_user.id,
        email=current_user.email,
        role=current_user.role.value,
    )


# ---------------------------------------------------------------------------
# Password reset (token delivered by email after failed-login trigger)
# ---------------------------------------------------------------------------

_SPECIAL_CHARS_RE = re.compile(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]')


class PasswordResetConfirmRequest(_BaseModel):
    token: str = Field(..., description="Token de restablecimiento recibido por correo")
    new_password: str = Field(
        ...,
        min_length=8,
        description="Nueva contraseña (mín. 8 caracteres, mayúscula, número y carácter especial)",
    )


@router.post("/password-reset/confirm")
async def confirm_password_reset(
    data: PasswordResetConfirmRequest,
    db: Session = Depends(get_db),
):
    """
    Confirm a password reset using the single-use token received by email.
    The token is valid for 30 minutes and is invalidated immediately upon use.

    Password requirements: ≥8 characters, at least one uppercase letter,
    one digit, and one special character.
    """
    # Validate password strength
    pwd = data.new_password
    issues: list[str] = []
    if not re.search(r'[A-Z]', pwd):
        issues.append("al menos una letra mayúscula")
    if not re.search(r'[0-9]', pwd):
        issues.append("al menos un número")
    if not _SPECIAL_CHARS_RE.search(pwd):
        issues.append("al menos un carácter especial (!@#$%^&*...)")
    if issues:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"La contraseña no cumple los requisitos de seguridad: {', '.join(issues)}.",
        )

    token_hash = hashlib.sha256(data.token.encode()).hexdigest()
    email = redis_client.get_password_reset_email(token_hash)
    if not email:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "El enlace de restablecimiento es inválido o ha expirado.",
        )

    user = db.query(User).filter(User.email == email, User.is_active == True).first()
    if not user:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "El enlace de restablecimiento es inválido o ha expirado.",
        )

    from app.core.security import get_password_hash
    user.password_hash = get_password_hash(data.new_password)
    db.commit()

    # One-time use: invalidate the token and clear the attempt counter
    redis_client.delete_password_reset_token(token_hash)
    redis_client.reset_email_attempts(email)

    logger.info("Password reset confirmed for user: %s", email)
    return {"message": "Contraseña restablecida exitosamente. Ya puedes iniciar sesión con tu nueva contraseña."}

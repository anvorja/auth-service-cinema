# app/schemas/auth.py
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, EmailStr


class UserRegister(BaseModel):
    email: EmailStr
    phone: str = Field(..., min_length=10, max_length=20)
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    phone: str
    first_name: str
    last_name: str
    role: str
    is_active: bool
    full_name: str

    @classmethod
    def from_orm(cls, user):
        return cls(
            id=user.id,
            email=user.email,
            phone=user.phone,
            first_name=user.first_name,
            last_name=user.last_name,
            role=user.role.value,
            is_active=user.is_active,
            full_name=user.full_name,
        )


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict


class LogoutResponse(BaseModel):
    message: str
    user_id: int
    logout_time: Optional[datetime] = Field(default_factory=datetime.now)


class VerifyTokenResponse(BaseModel):
    valid: bool
    user_id: int
    email: str
    role: str

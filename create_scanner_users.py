#!/usr/bin/env python3
"""
Crea los usuarios empleados de escaneo de QR en auth-service.
Ejecutar UNA SOLA VEZ desde la raíz de auth-service-cinema:
  python create_scanner_users.py
"""
import sys
import os

# Asegurar que el path incluya app/
sys.path.insert(0, os.path.dirname(__file__))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.user import User, UserRole
from app.core.security import get_password_hash
from app.kafka.producer import publish_event
import asyncio

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise EnvironmentError("La variable de entorno DATABASE_URL no está definida. Configúrala en .env antes de ejecutar este script.")

SCANNER_USERS = [
    {
        "email": "empleadocinema1@gmail.com",
        "password": "scan1qr",
        "first_name": "Empleado",
        "last_name": "Cinema Uno",
        "phone": "3001000001",
    },
    {
        "email": "empleadocinema2@gmail.com",
        "password": "scan2qr",
        "first_name": "Empleado",
        "last_name": "Cinema Dos",
        "phone": "3001000002",
    },
]


async def main():
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    db = Session()

    created = []
    try:
        for u in SCANNER_USERS:
            existing = db.query(User).filter(User.email == u["email"]).first()
            if existing:
                print(f"[SKIP] {u['email']} ya existe (role={existing.role.value})")
                continue

            user = User(
                email=u["email"],
                phone=u["phone"],
                first_name=u["first_name"],
                last_name=u["last_name"],
                password_hash=get_password_hash(u["password"]),
                role=UserRole.SCANNER,
            )
            db.add(user)
            db.flush()   # obtener el id antes del commit
            created.append(user)
            print(f"[OK] Creado: {user.email} (id={user.id}, role=scanner)")

        db.commit()

        # Publicar user.registered para sincronizar con booking-service via Kafka
        for user in created:
            try:
                await publish_event("user.registered", {
                    "id": user.id,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "phone": user.phone,
                    "role": user.role.value,
                })
                print(f"[Kafka] user.registered publicado para {user.email}")
            except Exception as e:
                print(f"[Kafka WARN] No se pudo publicar para {user.email}: {e}")
                print("  → El usuario existe en auth-service. Sincroniza booking-service manualmente si es necesario.")

    finally:
        db.close()
        engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())

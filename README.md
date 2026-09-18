# auth-service-cinema

Autenticación, sesiones y credenciales de usuario para toda la plataforma.

## Responsabilidad

Dueño exclusivo de la tabla `users` en `cinema_auth` (email, teléfono, nombre,
`password_hash`, `role`). Emite y valida JWT, gestiona blacklist de tokens en
Redis (logout inmediato) y el flujo de reseteo de contraseña.

No gestiona perfiles de usuario (eso es `user-service`, sobre `cinema_users`)
ni autorización por rol más allá de exponer `role` en el token — cada
servicio decide qué permite según ese campo. Otros servicios no acceden a
`cinema_auth` directamente: usan `GET /api/v1/auth/verify-token` para validar
credenciales, o confían en el JWT firmado.

## Stack

FastAPI + SQLAlchemy 2.0 sobre PostgreSQL (`cinema_auth`), Redis (blacklist de
tokens y contadores de intentos de login), `python-jose` (JWT), `passlib[bcrypt]`
(hash de contraseña), `aiokafka`. Puerto **8005**.

## API

Prefijo `/api/v1/auth`.

| Método | Ruta | Propósito |
|---|---|---|
| POST | `/register` | Crea un usuario nuevo (`role=customer` por defecto) |
| POST | `/login` | Devuelve access + refresh token. Tras varios intentos fallidos dispara reseteo de contraseña por email (ver Eventos Kafka) |
| POST | `/logout` | Invalida el token actual (blacklist en Redis) |
| POST | `/logout-all` | Invalida todas las sesiones activas del usuario |
| POST | `/refresh` | Emite un nuevo access token a partir de un refresh token válido |
| GET | `/me` | Perfil del usuario autenticado |
| PUT | `/password` | Cambia la contraseña (requiere la actual) |
| GET | `/verify-token` | Uso interno: otros servicios validan un token (incluye chequeo de blacklist) |
| POST | `/password-reset/confirm` | Confirma el reseteo con el token de un solo uso recibido por correo |

## Eventos Kafka

- **Publica** `auth.password_reset_requested` — al detectar varios intentos de
  login fallidos seguidos sobre una cuenta activa (no en un endpoint dedicado
  de "olvidé mi contraseña"). `notification-service` lo consume para enviar
  el correo.
- **Consume** `user.deactivated` — publicado por `user-service` cuando se
  desactiva una cuenta; marca `is_active=false` en `cinema_auth` para
  invalidar sesiones futuras de ese usuario.

Payloads completos y semántica de saga en
`../kafka-schemas-cinema/event_contracts_operativos.md`. Kafka apunta a
Confluent Cloud incluso en desarrollo — no hay broker local (ver
`../IMPLEMENTATION-GUIDE.md` Fase 3).

## Variables de entorno clave

| Variable | Requerida | Uso |
|---|---|---|
| `DATABASE_URL` | Sí | Conexión a `cinema_auth` |
| `JWT_SECRET` | Sí | Firma de access/refresh tokens |
| `JWT_ALGORITHM` | No (`HS256`) | Algoritmo de firma |
| `JWT_EXPIRE_MINUTES` | No (`30`) | Vigencia del access token |
| `REDIS_URL` | No (vacío = blacklist deshabilitada, logout no invalida tokens) | Blacklist de tokens y contadores de intentos |
| `KAFKA_ENABLED` | No (`false`) | Habilita producer y consumer de Kafka |
| `KAFKA_BOOTSTRAP_SERVERS` / `KAFKA_API_KEY` / `KAFKA_API_SECRET` | Si `KAFKA_ENABLED=true` | Credenciales de Confluent Cloud |

Ver `.env.example` para la plantilla completa y `../IMPLEMENTATION-GUIDE.md`
Fase 4 para el procedimiento de setup end-to-end (bases de datos + Kafka).

## Dependencias

Ninguna llamada saliente a otros microservicios. Es un servicio "hoja" desde
el punto de vista HTTP — los demás lo consultan a él (`verify-token`), no al
revés.

## Correr en local

```bash
uvicorn app.main:app --reload --port 8005
```

Requiere `DATABASE_URL` apuntando a un Postgres con la tabla `users` creada
y, opcionalmente, `REDIS_URL`. En la práctica se levanta junto al resto del
stack vía `../infra-cinema/docker-compose.dev.yml` — ver
`../IMPLEMENTATION-GUIDE.md` para el procedimiento completo.

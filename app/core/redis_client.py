# app/core/redis_client.py
"""
Redis-backed token blacklist + per-user token tracking + login rate limiting.

Key schema:
  blacklist:<sha256_of_token>          — TTL = remaining seconds until JWT expiry
  user_tokens:<user_id>                — Sorted Set, score = exp_timestamp, member = sha256(token)
  login_attempts:<ip>                  — Counter with 15-min TTL (legacy, kept for compatibility)
  login_attempts:email:<sha256_email>  — Counter with 15-min TTL per user email
  password_reset:<token_hash>          — email value, TTL 30 min (one-time use)
  password_reset_sent:<sha256_email>   — cooldown flag, TTL 15 min (prevent email spam)
"""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

from .config import settings

logger = logging.getLogger(__name__)

_LOGIN_WINDOW_SECONDS = 900   # 15 minutes
_LOGIN_MAX_ATTEMPTS   = 5

# After this many consecutive failed logins for the same email, a password
# reset email is triggered automatically (login is never blocked).
RESET_TRIGGER_ATTEMPTS = 3
_RESET_TOKEN_TTL       = 1800  # 30 minutes
_RESET_COOLDOWN_TTL    = 900   # 15 minutes — prevent duplicate emails

_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    if not settings.REDIS_URL:
        return None
    try:
        import redis
        c = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_timeout=1,
            socket_connect_timeout=1,
        )
        c.ping()
        _client = c
        logger.info("Redis connected (token blacklist)")
        return _client
    except Exception as exc:
        logger.warning("Redis unavailable — blacklist disabled (%s)", exc)
        return None


def _key(token: str) -> str:
    digest = hashlib.sha256(token.encode()).hexdigest()
    return f"blacklist:{digest}"


def blacklist_token(token: str, exp_timestamp: int) -> bool:
    """
    Add token to blacklist with TTL = remaining seconds until its expiry.

    Args:
        token:         Raw JWT string
        exp_timestamp: Unix timestamp from JWT 'exp' claim

    Returns:
        True if successfully blacklisted, False on Redis failure
    """
    client = _get_client()
    if client is None:
        logger.warning("Redis unavailable — token not blacklisted")
        return False

    remaining = exp_timestamp - int(datetime.now(timezone.utc).timestamp())
    if remaining <= 0:
        return True  # Already expired, no need to blacklist

    try:
        client.setex(_key(token), remaining, "1")
        return True
    except Exception as exc:
        logger.error("Error blacklisting token: %s", exc)
        return False


def is_blacklisted(token: str) -> bool:
    """Return True if token is in the Redis blacklist."""
    client = _get_client()
    if client is None:
        return False
    try:
        return client.exists(_key(token)) == 1
    except Exception as exc:
        logger.error("Error checking blacklist: %s", exc)
        return False


def is_healthy() -> bool:
    client = _get_client()
    if client is None:
        return False
    try:
        return bool(client.ping())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Per-user token tracking (enables real logout-all)
# ---------------------------------------------------------------------------

def _user_tokens_key(user_id: int) -> str:
    return f"user_tokens:{user_id}"


def track_user_token(user_id: int, token: str, exp_timestamp: int) -> None:
    """
    Register a newly issued token in the user's active-token Sorted Set.
    Score = exp_timestamp so expired entries can be pruned in O(log N).
    """
    client = _get_client()
    if client is None:
        return
    try:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        key = _user_tokens_key(user_id)
        now = int(datetime.now(timezone.utc).timestamp())
        # Remove already-expired entries to keep the set small
        client.zremrangebyscore(key, "-inf", now)
        client.zadd(key, {token_hash: exp_timestamp})
        # The set itself expires shortly after the last token in it would
        remaining = exp_timestamp - now
        if remaining > 0:
            client.expire(key, remaining + 60)
    except Exception as exc:
        logger.error("Error tracking user token: %s", exc)


def revoke_all_user_tokens(user_id: int) -> int:
    """
    Blacklist every active token belonging to user_id.
    Returns the number of tokens revoked.
    """
    client = _get_client()
    if client is None:
        logger.warning("Redis unavailable — logout-all skipped")
        return 0
    try:
        now = int(datetime.now(timezone.utc).timestamp())
        key = _user_tokens_key(user_id)
        # Retrieve all non-expired token hashes together with their expiry scores
        entries = client.zrangebyscore(key, now, "+inf", withscores=True)
        if not entries:
            return 0
        pipe = client.pipeline()
        for token_hash, score in entries:
            remaining = int(score) - now
            if remaining > 0:
                pipe.setex(f"blacklist:{token_hash}", remaining, "1")
        pipe.delete(key)
        pipe.execute()
        logger.info("logout-all: revoked %d token(s) for user %d", len(entries), user_id)
        return len(entries)
    except Exception as exc:
        logger.error("Error revoking all user tokens: %s", exc)
        return 0


# ---------------------------------------------------------------------------
# Login rate limiting
# ---------------------------------------------------------------------------

def _rate_limit_key(ip: str) -> str:
    return f"login_attempts:{ip}"


def is_login_allowed(ip: str) -> bool:
    """Return False if the IP has exceeded the allowed failed-login attempts."""
    client = _get_client()
    if client is None:
        return True  # Fail open when Redis is down (availability > security in dev)
    try:
        count = client.get(_rate_limit_key(ip))
        return count is None or int(count) < _LOGIN_MAX_ATTEMPTS
    except Exception as exc:
        logger.error("Error checking rate limit: %s", exc)
        return True


def increment_login_attempt(ip: str) -> int:
    """Increment failed-attempt counter for ip. Sets TTL on first increment."""
    client = _get_client()
    if client is None:
        return 0
    try:
        key = _rate_limit_key(ip)
        count = client.incr(key)
        if count == 1:
            client.expire(key, _LOGIN_WINDOW_SECONDS)
        return count
    except Exception as exc:
        logger.error("Error incrementing login attempt: %s", exc)
        return 0


def reset_login_attempts(ip: str) -> None:
    """Clear failed-attempt counter after a successful login."""
    client = _get_client()
    if client is None:
        return
    try:
        client.delete(_rate_limit_key(ip))
    except Exception as exc:
        logger.error("Error resetting login attempts: %s", exc)


# ---------------------------------------------------------------------------
# Email-based failed-login tracking + password reset tokens
# ---------------------------------------------------------------------------

def _email_attempts_key(email: str) -> str:
    digest = hashlib.sha256(email.lower().encode()).hexdigest()
    return f"login_attempts:email:{digest}"


def _reset_cooldown_key(email: str) -> str:
    digest = hashlib.sha256(email.lower().encode()).hexdigest()
    return f"password_reset_sent:{digest}"


def _reset_token_key(token_hash: str) -> str:
    return f"password_reset:{token_hash}"


def increment_email_attempt(email: str) -> int:
    """
    Increment failed-login counter for *email*. Sets TTL on first increment.
    Returns current count (0 when Redis is unavailable).
    """
    client = _get_client()
    if client is None:
        return 0
    try:
        key = _email_attempts_key(email)
        count = client.incr(key)
        if count == 1:
            client.expire(key, _LOGIN_WINDOW_SECONDS)
        return count
    except Exception as exc:
        logger.error("Error incrementing email attempt: %s", exc)
        return 0


def reset_email_attempts(email: str) -> None:
    """Clear email-based failed-attempt counter (successful login or password reset)."""
    client = _get_client()
    if client is None:
        return
    try:
        client.delete(_email_attempts_key(email))
    except Exception as exc:
        logger.error("Error resetting email attempts: %s", exc)


def is_reset_email_on_cooldown(email: str) -> bool:
    """Return True if a reset email was sent to this address within the last 15 minutes."""
    client = _get_client()
    if client is None:
        return False
    try:
        return client.exists(_reset_cooldown_key(email)) == 1
    except Exception as exc:
        logger.error("Error checking reset cooldown: %s", exc)
        return False


def mark_reset_email_sent(email: str) -> None:
    """Set cooldown flag so the same address is not emailed again for 15 minutes."""
    client = _get_client()
    if client is None:
        return
    try:
        client.setex(_reset_cooldown_key(email), _RESET_COOLDOWN_TTL, "1")
    except Exception as exc:
        logger.error("Error marking reset email sent: %s", exc)


def store_password_reset_token(email: str, token_hash: str) -> None:
    """
    Persist email → token_hash with a 30-minute TTL.
    The token_hash is the SHA-256 digest of the raw token so the plain token
    is never stored at rest.
    """
    client = _get_client()
    if client is None:
        logger.warning("Redis unavailable — password reset token not stored")
        return
    try:
        client.setex(_reset_token_key(token_hash), _RESET_TOKEN_TTL, email)
    except Exception as exc:
        logger.error("Error storing reset token: %s", exc)


def get_password_reset_email(token_hash: str) -> Optional[str]:
    """Return the email associated with *token_hash*, or None if missing/expired."""
    client = _get_client()
    if client is None:
        return None
    try:
        return client.get(_reset_token_key(token_hash))
    except Exception as exc:
        logger.error("Error retrieving reset token: %s", exc)
        return None


def delete_password_reset_token(token_hash: str) -> None:
    """Consume (invalidate) the token after a successful password reset."""
    client = _get_client()
    if client is None:
        return
    try:
        client.delete(_reset_token_key(token_hash))
    except Exception as exc:
        logger.error("Error deleting reset token: %s", exc)

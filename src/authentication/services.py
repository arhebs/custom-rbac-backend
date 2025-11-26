"""Token service for JWT creation, decoding, and blocklist checks."""

import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Tuple

import jwt
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed

from core.redis_client import get_redis_client


class BlocklistUnavailable(Exception):
    """Raised when Redis blocklist cannot be checked (fail-closed)."""


class TokenService:
    """Handle JWT issuance, decoding, and blocklist operations."""

    ACCESS_TTL = timedelta(minutes=15)
    REFRESH_TTL = timedelta(hours=24)
    ALGORITHM = "HS256"
    BLOCKLIST_PREFIX = "blocklist:token:"

    @classmethod
    def generate_tokens(cls, user) -> Tuple[str, str]:
        """Generate signed access and refresh tokens for the given user."""

        now = datetime.now(timezone.utc)
        access_payload = cls._build_payload(user, "access", now, cls.ACCESS_TTL)
        refresh_payload = cls._build_payload(user, "refresh", now, cls.REFRESH_TTL)

        access_token = jwt.encode(access_payload, settings.SECRET_KEY, algorithm=cls.ALGORITHM)
        refresh_token = jwt.encode(refresh_payload, settings.SECRET_KEY, algorithm=cls.ALGORITHM)
        return access_token, refresh_token

    @classmethod
    def _build_payload(cls, user, token_type: str, issued_at: datetime, ttl: timedelta) -> dict[str, Any]:
        exp = issued_at + ttl
        return {
            "sub": str(user.id),
            "jti": str(uuid.uuid4()),
            "exp": int(exp.timestamp()),
            "iat": int(issued_at.timestamp()),
            # Access the role name via getattr chaining so static analysis
            # does not require ``role`` to exist on AbstractBaseUser.
            "role": getattr(getattr(user, "role", None), "name", None),
            "type": token_type,
        }

    @classmethod
    def decode_token(cls, token: str, expected_type: str | None = None) -> dict[str, Any]:
        """Decode and validate a JWT; optionally enforce token type."""

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[cls.ALGORITHM])
        except jwt.ExpiredSignatureError as exc:  # pragma: no cover - simple mapping
            raise AuthenticationFailed("Token has expired") from exc
        except jwt.InvalidTokenError as exc:  # pragma: no cover - simple mapping
            raise AuthenticationFailed("Invalid token") from exc

        if expected_type and payload.get("type") != expected_type:
            raise AuthenticationFailed("Invalid token type")

        return payload

    @classmethod
    def block_token(cls, jti: str, exp: int) -> None:
        """Add token jti to blocklist until its expiration timestamp."""

        client = get_redis_client()
        ttl_seconds = max(0, exp - int(time.time()))
        try:
            client.setex(f"{cls.BLOCKLIST_PREFIX}{jti}", ttl_seconds, "1")
        except Exception as exc:  # pragma: no cover - network failure
            raise BlocklistUnavailable("Redis unavailable while blocklisting") from exc

    @classmethod
    def is_token_blocked(cls, jti: str) -> bool:
        """Check if a token jti is present in the blocklist."""

        client = get_redis_client()
        try:
            return client.get(f"{cls.BLOCKLIST_PREFIX}{jti}") is not None
        except Exception as exc:  # pragma: no cover - network failure
            raise BlocklistUnavailable("Redis unavailable while checking blocklist") from exc


__all__ = ["TokenService", "BlocklistUnavailable"]

"""Middleware to authenticate requests via JWT and Redis blocklist."""

from typing import Optional

from django.contrib.auth.models import AnonymousUser
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed

from authentication.models import User
from authentication.services import TokenService, BlocklistUnavailable


class JWTAuthMiddleware(MiddlewareMixin):
    """Decode access JWT, check blocklist, and attach request.user."""

    def process_request(self, request):  # type: ignore[override]
        """Authenticate request using Bearer access token if present."""
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth_header or not auth_header.startswith("Bearer "):
            request.user = AnonymousUser()
            return None

        token = auth_header.split(" ", 1)[1]

        try:
            payload = TokenService.decode_token(token, expected_type="access")
            jti = payload.get("jti")
            if not jti:
                return _unauthorized()

            if TokenService.is_token_blocked(jti):
                return _unauthorized()

            user = self._get_user(payload.get("sub"))
            if not user or not user.is_active:
                return _unauthorized()

            request.user = user
            return None

        except AuthenticationFailed:
            return _unauthorized()
        except BlocklistUnavailable:
            return _service_unavailable()

    @staticmethod
    def _get_user(user_id: Optional[str]) -> Optional[User]:
        if not user_id:
            return None
        try:
            return User.objects.select_related("role").get(id=user_id)
        except User.DoesNotExist:
            return None


def _unauthorized() -> JsonResponse:
    return JsonResponse(
        {
            "data": None,
            "errors": [
                "Authentication credentials were not provided or are invalid, token revoked, or user is inactive."
            ],
        },
        status=status.HTTP_401_UNAUTHORIZED,
    )


def _service_unavailable() -> JsonResponse:
    return JsonResponse(
        {"data": None, "errors": ["Authentication service unavailable (blocklist)."]},
        status=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


__all__ = ["JWTAuthMiddleware"]

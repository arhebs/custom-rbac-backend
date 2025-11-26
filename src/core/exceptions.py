"""Custom exception handling to enforce the API error envelope."""

from typing import Any

from django.conf import settings
from django.db import DatabaseError
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler

from authentication.services import BlocklistUnavailable


def _normalize_errors(payload: Any) -> list[Any]:
    """Convert DRF's response.data into a list for the envelope."""

    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and "detail" in payload:
        # Common DRF pattern: {"detail": "..."}
        return [payload["detail"]]
    return [payload]


def custom_exception_handler(exc: Exception, context: dict[str, Any]) -> Response | None:
    """Wrap DRF errors in `{ "data": null, "errors": [...] }` shape.

    - Uses DRF's default handler to produce the base response.
    - Normalizes common auth/permission messages per the spec.
    - Optionally exposes more detailed auth errors when DEBUG_AUTH_ERRORS is enabled.
    """

    # Handle blocklist connectivity errors that do not go through DRF's
    # built-in exception mapping (e.g., during logout/soft delete). These are
    # security-critical and must fail-closed with 503.
    if isinstance(exc, BlocklistUnavailable):
        return Response(
            {"data": None, "errors": ["Authentication service unavailable (blocklist)."]},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    # Treat database errors as a temporary service outage and still respect the
    # global envelope format instead of returning Django's HTML 500 page.
    if isinstance(exc, DatabaseError):
        return Response(
            {"data": None, "errors": ["Service temporarily unavailable."]},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    response = drf_exception_handler(exc, context)

    if response is None:
        return response

    # Normalize auth-related status codes to 401, regardless of DRF's default
    # mapping, so that AuthenticationFailed/NotAuthenticated consistently
    # produce 401 responses per the project spec.
    if isinstance(exc, (AuthenticationFailed, NotAuthenticated)):
        response.status_code = status.HTTP_401_UNAUTHORIZED

    # Successful responses are untouched here; BaseAPIView/BaseViewSet handle them.
    if response.status_code >= 400:
        base_errors = response.data

        # Normalize key messages
        if response.status_code == status.HTTP_401_UNAUTHORIZED:
            if getattr(settings, "DEBUG_AUTH_ERRORS", False):
                # When DEBUG_AUTH_ERRORS is enabled, surface the more specific
                # underlying message (e.g. "Token has expired", "Invalid token type").
                errors = _normalize_errors(base_errors)
            else:
                errors = [
                    "Authentication credentials were not provided or are invalid, "
                    "token revoked, or user is inactive."
                ]
        elif response.status_code == status.HTTP_403_FORBIDDEN:
            errors = [
                "You do not have permission to perform this action on this resource."
            ]
        else:
            errors = _normalize_errors(base_errors)

        response.data = {"data": None, "errors": errors}

    return response

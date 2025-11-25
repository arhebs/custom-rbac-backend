"""Custom exception handling to enforce the API error envelope."""

from typing import Any

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler


def custom_exception_handler(exc: Exception, context: dict[str, Any]) -> Response | None:
    """Wrap DRF errors in `{ "data": null, "errors": [...] }` shape.

    - Uses DRF's default handler to produce the base response.
    - Normalizes common auth/permission messages per the spec.
    """

    response = drf_exception_handler(exc, context)

    if response is None:
        return response

    # Successful responses are untouched here; BaseAPIView/BaseViewSet handle them.
    if response.status_code >= 400:
        errors = response.data

        # Normalize key messages
        if response.status_code == status.HTTP_401_UNAUTHORIZED:
            errors = [
                "Authentication credentials were not provided or are invalid, "
                "token revoked, or user is inactive."
            ]
        elif response.status_code == status.HTTP_403_FORBIDDEN:
            errors = [
                "You do not have permission to perform this action on this resource."
            ]

        response.data = {"data": None, "errors": errors if isinstance(errors, list) else [errors]}

    return response

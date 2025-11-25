"""Response helpers and base classes for consistent API envelopes."""

from typing import Any

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet


def api_response(data: Any, status: int = 200) -> Response:
    """Return data wrapped in the standard envelope.

    All successful JSON responses should use this helper to ensure the
    `{ "data": ..., "errors": [] }` shape.
    """

    return Response({"data": data, "errors": []}, status=status)


def _is_enveloped(payload: Any) -> bool:
    return isinstance(payload, dict) and "data" in payload and "errors" in payload


class EnvelopeMixin:
    """Mixin to wrap successful responses in the standard envelope."""

    def finalize_response(self, request, response, *args, **kwargs):  # type: ignore[override]
        """Ensure non-error responses include the `{data, errors}` envelope."""
        if hasattr(response, "data") and response.status_code and response.status_code < 400:
            if response.status_code != 204 and not _is_enveloped(response.data):
                response.data = {"data": response.data, "errors": []}
        # DRF's APIView/ModelViewSet provide finalize_response; mixin alone doesn't.
        return super().finalize_response(request, response, *args, **kwargs)  # type: ignore[attr-defined]


class BaseAPIView(EnvelopeMixin, APIView):
    """APIView that ensures successful responses use the standard envelope."""


class BaseViewSet(EnvelopeMixin, ModelViewSet):
    """ModelViewSet variant that wraps successful responses in the envelope."""

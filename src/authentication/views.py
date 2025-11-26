"""Authentication endpoints: register, login, refresh, logout, and profile."""

from typing import Any

from django.contrib.auth import get_user_model
from django.http import JsonResponse
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.views import APIView

from core.response import BaseAPIView, api_response
from .serializers import (
    LoginSerializer,
    ProfileUpdateSerializer,
    RegisterSerializer,
    UserDetailSerializer,
)
from .services import TokenService

User = get_user_model()


class RegisterView(BaseAPIView):
    permission_classes: list[Any] = []

    # noinspection PyMethodMayBeStatic
    def post(self, request):
        """Register a new user and return their profile."""
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return api_response(UserDetailSerializer(user).data, status=status.HTTP_201_CREATED)


class LoginView(BaseAPIView):
    permission_classes: list[Any] = []

    # noinspection PyMethodMayBeStatic
    def post(self, request):
        """Authenticate and issue access + refresh tokens."""
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        access, refresh = TokenService.generate_tokens(user)
        return api_response({"access": access, "refresh": refresh})


class RefreshView(BaseAPIView):
    permission_classes: list[Any] = []

    # noinspection PyMethodMayBeStatic
    def post(self, request):
        """Exchange a valid refresh token for new access/refresh tokens."""
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            raise AuthenticationFailed("Refresh token required")

        payload = TokenService.decode_token(refresh_token, expected_type="refresh")
        user = _get_active_user(payload.get("sub"))
        if not user:
            raise AuthenticationFailed("User not found or inactive")

        # Ensure the refresh token was issued for the current token_version of
        # the user. If the user has called logout-all since this token was
        # minted, the version will not match and the token should be rejected.
        token_ver = payload.get("ver")
        if token_ver is None or token_ver != getattr(user, "token_version", 1):
            raise AuthenticationFailed("Invalid or revoked refresh token")

        access, new_refresh = TokenService.generate_tokens(user)
        return api_response({"access": access, "refresh": new_refresh})


class LogoutView(APIView):
    """Invalidate the current access token by blocklisting its jti."""

    # noinspection PyMethodMayBeStatic
    def post(self, request):
        """Blocklist the bearer access token and return 204 No Content."""
        token = _get_bearer_token(request)
        if not token:
            return JsonResponse({"data": None, "errors": ["Missing token."]}, status=401)

        payload = TokenService.decode_token(token, expected_type="access")
        TokenService.block_token(payload["jti"], payload["exp"])
        # 204 responses must not include a body.
        return Response(status=status.HTTP_204_NO_CONTENT)


class LogoutAllView(APIView):
    """Invalidate all existing tokens for the current user across devices."""

    # noinspection PyMethodMayBeStatic
    def post(self, request):
        """Increment token_version and blocklist the current access token."""
        if not request.user.is_authenticated:
            raise AuthenticationFailed("Authentication required")

        # Bump the per-user token version so that all tokens (access and refresh)
        # issued before this point become invalid.
        user = request.user
        current_version = getattr(user, "token_version", 1) or 1
        user.token_version = current_version + 1
        user.save(update_fields=["token_version"])

        # Optionally blocklist the current access token so it is unusable even
        # if an attacker captures it after this call.
        token = _get_bearer_token(request)
        if token:
            payload = TokenService.decode_token(token, expected_type="access")
            TokenService.block_token(payload["jti"], payload["exp"])

        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(BaseAPIView):
    permission_classes: list[Any] = []

    # noinspection PyMethodMayBeStatic
    def get(self, request):
        """Return the current user's profile."""
        if not request.user.is_authenticated:
            raise AuthenticationFailed("Authentication required")
        return api_response(UserDetailSerializer(request.user).data)

    # noinspection PyMethodMayBeStatic
    def patch(self, request):
        """Update profile fields for the current user."""
        if not request.user.is_authenticated:
            raise AuthenticationFailed("Authentication required")
        serializer = ProfileUpdateSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return api_response(UserDetailSerializer(request.user).data)

    # noinspection PyMethodMayBeStatic
    def delete(self, request):
        """Soft-delete the current user and blocklist the current access token."""
        if not request.user.is_authenticated:
            raise AuthenticationFailed("Authentication required")
        token = _get_bearer_token(request)
        if token:
            payload = TokenService.decode_token(token, expected_type="access")
            TokenService.block_token(payload["jti"], payload["exp"])
        request.user.is_active = False
        request.user.save(update_fields=["is_active"])
        # 204 responses must not include a body.
        return Response(status=status.HTTP_204_NO_CONTENT)


def _get_active_user(user_id) -> User | None:
    """Retrieve an active user by id, or None if missing/inactive."""
    if not user_id:
        return None
    try:
        user = User.objects.select_related("role").get(id=user_id)
    except User.DoesNotExist:
        return None
    if not user.is_active:
        return None
    return user


def _get_bearer_token(request) -> str | None:
    """Extract the Bearer token from Authorization header if present."""
    auth_header = request.META.get("HTTP_AUTHORIZATION", "")
    if auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1]
    return None

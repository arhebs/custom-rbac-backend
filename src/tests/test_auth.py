"""Matrix tests for authentication flows (register, login, refresh, logout, soft delete)."""

from __future__ import annotations

import time
from unittest import mock

import jwt
from django.conf import settings
from django.db import DatabaseError
from django.test import TestCase
from rest_framework.test import APIClient

from authentication.services import BlocklistUnavailable, TokenService
from tests.utils import FakeRedis, create_user, seed_rbac_basics


class AuthFlowTests(TestCase):
    """End-to-end tests covering auth endpoints and soft delete behavior."""

    @classmethod
    def setUpClass(cls):
        """Patch Redis clients to use in-memory fake for all tests."""
        super().setUpClass()
        cls.fake_redis = FakeRedis()
        cls.patchers = [
            mock.patch("core.redis_client.get_redis_client", return_value=cls.fake_redis),
            mock.patch("authentication.services.get_redis_client", return_value=cls.fake_redis),
        ]
        for patcher in cls.patchers:
            patcher.start()

    @classmethod
    def tearDownClass(cls):
        """Stop Redis patches after all tests complete."""
        for patcher in cls.patchers:
            patcher.stop()
        super().tearDownClass()

    @classmethod
    def setUpTestData(cls):
        """Seed base roles and a default active user for test cases."""
        cls.roles, _ = seed_rbac_basics()
        cls.password = "StrongPass123"
        cls.user = create_user("user@example.com", cls.password, cls.roles["User"])

    def setUp(self):
        """Fresh DRF APIClient per test."""
        self.api_client: APIClient = APIClient()

    def _login_two_devices(self):
        """Helper to perform two logins for the same user."""
        login_a = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        ).json()["data"]
        login_b = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        ).json()["data"]

        return login_a, login_b

    def _create_two_device_clients(self):
        """Helper to create two APIClients authenticated as the same user."""
        login_a, login_b = self._login_two_devices()
        client_a = APIClient()
        client_b = APIClient()
        client_a.credentials(HTTP_AUTHORIZATION=f"Bearer {login_a['access']}")
        client_b.credentials(HTTP_AUTHORIZATION=f"Bearer {login_b['access']}")
        return client_a, client_b

    def test_register_success(self):
        """Successful registration returns profile and envelope."""
        payload = {
            "email": "new@example.com",
            "password": "NewPass123!",
            "repeat_password": "NewPass123!",
            "first_name": "New",
        }
        response = self.api_client.post("/auth/register/", payload, format="json")
        body = response.json()

        self.assertEqual(response.status_code, 201)
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["data"]["email"], payload["email"])

    def test_register_password_mismatch(self):
        """Mismatched passwords yield 400 with errors populated."""
        payload = {
            "email": "new2@example.com",
            "password": "Password123",
            "repeat_password": "Mismatch123",
        }
        response = self.api_client.post("/auth/register/", payload, format="json")
        body = response.json()

        self.assertEqual(response.status_code, 400)
        self.assertIsNone(body["data"])
        self.assertTrue(body["errors"])

    def test_login_success_returns_tokens(self):
        """Valid credentials return access and refresh tokens."""
        response = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        )
        body = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertIn("access", body["data"])
        self.assertIn("refresh", body["data"])
        self.assertEqual(body["errors"], [])

    def test_login_invalid_credentials_401(self):
        """Bad password returns 401 with null data."""
        response = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": "wrongpass"},
            format="json",
        )
        body = response.json()

        self.assertEqual(response.status_code, 401)
        self.assertIsNone(body["data"])
        self.assertTrue(body["errors"])

    def test_login_inactive_user_401(self):
        """Inactive user cannot log in and receives 401."""
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        response = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        )
        body = response.json()

        self.assertEqual(response.status_code, 401)
        self.assertIsNone(body["data"])
        self.assertTrue(body["errors"])

    def test_refresh_with_valid_refresh_token(self):
        """Refresh endpoint issues new access/refresh tokens."""
        login = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        ).json()
        old_access = login["data"]["access"]
        refresh_token = login["data"]["refresh"]

        response = self.api_client.post("/auth/refresh/", {"refresh": refresh_token}, format="json")
        body = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertIn("access", body["data"])
        self.assertIn("refresh", body["data"])
        self.assertNotEqual(body["data"]["access"], old_access)

    def test_refresh_with_access_token_rejected(self):
        """Providing an access token to refresh endpoint returns 401."""
        tokens = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        ).json()["data"]

        response = self.api_client.post("/auth/refresh/", {"refresh": tokens["access"]}, format="json")
        body = response.json()

        self.assertEqual(response.status_code, 401)
        self.assertIsNone(body["data"])
        self.assertTrue(body["errors"])

    def test_logout_blocklists_token(self):
        """Logout blocklists current access token causing subsequent 401."""
        tokens = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        ).json()["data"]
        self.api_client.credentials(**{"HTTP_AUTHORIZATION": f"Bearer {tokens['access']}"})

        logout_response = self.api_client.post("/auth/logout/")
        self.assertEqual(logout_response.status_code, 204)

        # Reusing the same token should now fail because it was blocklisted.
        me_response = self.api_client.get("/auth/me/")
        self.assertEqual(me_response.status_code, 401)

    def test_soft_delete_blocks_token_and_future_login(self):
        """Soft delete blocklists active token and prevents future logins."""
        tokens = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        ).json()["data"]
        self.api_client.credentials(**{"HTTP_AUTHORIZATION": f"Bearer {tokens['access']}"})

        delete_response = self.api_client.delete("/auth/me/")
        self.assertEqual(delete_response.status_code, 204)

        # Existing token is blocklisted.
        me_response = self.api_client.get("/auth/me/")
        self.assertEqual(me_response.status_code, 401)

        # User is inactive and cannot log in again.
        relogin = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        )
        self.assertEqual(relogin.status_code, 401)

    def test_logout_all_revokes_access_and_refresh_tokens_across_devices(self):
        """logout-all invalidates all existing tokens (access and refresh)."""
        # Simulate two devices by performing two separate logins.
        login_a, login_b = self._login_two_devices()

        # Device A calls logout-all with its access token.
        client_a = APIClient()
        client_a.credentials(HTTP_AUTHORIZATION=f"Bearer {login_a['access']}")
        logout_all_response = client_a.post("/auth/logout-all/")
        self.assertEqual(logout_all_response.status_code, 204)

        # Device B's access token should now be invalid due to token_version bump.
        client_b = APIClient()
        client_b.credentials(HTTP_AUTHORIZATION=f"Bearer {login_b['access']}")
        me_response = client_b.get("/auth/me/")
        self.assertEqual(me_response.status_code, 401)

        # Refresh tokens from both devices should also be rejected.
        refresh_response_a = self.api_client.post(
            "/auth/refresh/",
            {"refresh": login_a["refresh"]},
            format="json",
        )
        self.assertEqual(refresh_response_a.status_code, 401)

        refresh_response_b = self.api_client.post(
            "/auth/refresh/",
            {"refresh": login_b["refresh"]},
            format="json",
        )
        self.assertEqual(refresh_response_b.status_code, 401)

    def test_refresh_after_soft_delete_returns_401(self):
        """Refresh tokens issued before soft delete must not work afterwards."""
        # Login and obtain access/refresh tokens.
        login = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        ).json()["data"]
        access = login["access"]
        refresh = login["refresh"]

        # Soft delete the user using the access token.
        self.api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        delete_response = self.api_client.delete("/auth/me/")
        self.assertEqual(delete_response.status_code, 204)

        # Attempt to use the old refresh token after soft delete.
        refresh_response = self.api_client.post(
            "/auth/refresh/",
            {"refresh": refresh},
            format="json",
        )
        body = refresh_response.json()

        self.assertEqual(refresh_response.status_code, 401)
        self.assertIsNone(body["data"])
        self.assertTrue(body["errors"])

    def test_logout_redis_down_returns_503(self):
        """If Redis is unavailable during logout, the API should fail-closed."""
        login = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        ).json()["data"]
        access = login["access"]

        self.api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

        # Simulate Redis failure when block_token is invoked.
        with mock.patch.object(
                TokenService,
                "block_token",
                side_effect=BlocklistUnavailable("Redis unavailable while blocklisting"),
        ):
            response = self.api_client.post("/auth/logout/")

        body = response.json()
        self.assertEqual(response.status_code, 503)
        self.assertIsNone(body["data"])
        self.assertTrue(body["errors"])

    def test_expired_refresh_token_returns_401(self):
        """Expired refresh tokens should be rejected with 401 Unauthorized."""
        # Ensure user is active and has a role for token payload.
        user = self.user
        now = int(time.time())
        payload = {
            "sub": str(user.id),
            "jti": "expired-jti",
            "exp": now - 60,  # expired 1 minute ago
            "iat": now - 120,
            "role": user.role.name,
            "type": "refresh",
            "ver": user.token_version,
        }
        expired_refresh = jwt.encode(payload, settings.SECRET_KEY, algorithm=TokenService.ALGORITHM)

        response = self.api_client.post(
            "/auth/refresh/",
            {"refresh": expired_refresh},
            format="json",
        )
        body = response.json()

        self.assertEqual(response.status_code, 401)
        self.assertIsNone(body["data"])
        self.assertTrue(body["errors"])

    def test_concurrent_logout_from_multiple_devices(self):
        """Multiple access tokens for the same user can be logged out independently."""
        # Login from two "devices".
        client_a, client_b = self._create_two_device_clients()

        # Both devices log out with their respective tokens.
        resp_a = client_a.post("/auth/logout/")
        resp_b = client_b.post("/auth/logout/")
        self.assertEqual(resp_a.status_code, 204)
        self.assertEqual(resp_b.status_code, 204)

        # Both tokens are now unusable.
        self.assertEqual(client_a.get("/auth/me/").status_code, 401)
        self.assertEqual(client_b.get("/auth/me/").status_code, 401)

        # A fresh login should still work.
        new_login = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        )
        self.assertEqual(new_login.status_code, 200)

    def test_concurrent_soft_delete_is_idempotent_and_safe(self):
        """Repeated DELETE /auth/me/ calls do not corrupt state."""
        # Simulate two "devices" each with their own access token.
        client_a, client_b = self._create_two_device_clients()

        # First device performs soft delete and should get 204.
        delete_a = client_a.delete("/auth/me/")
        self.assertEqual(delete_a.status_code, 204)

        # Second device attempts soft delete after the user is already inactive.
        # Middleware will reject the token because the user is inactive, yielding 401.
        delete_b = client_b.delete("/auth/me/")
        self.assertEqual(delete_b.status_code, 401)

        # The user must be inactive in the database.
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)

        # Both tokens should now be unusable for authenticated endpoints.
        self.assertEqual(client_a.get("/auth/me/").status_code, 401)
        self.assertEqual(client_b.get("/auth/me/").status_code, 401)

    def test_patch_me_cannot_change_email(self):
        """PATCH /auth/me/ must not allow changing email."""
        login = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        ).json()["data"]
        access = login["access"]

        self.api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

        response = self.api_client.patch(
            "/auth/me/",
            {"email": "new@example.com"},
            format="json",
        )
        body = response.json()

        # We choose the explicit behavior: reject attempts to change email.
        self.assertEqual(response.status_code, 400)
        self.assertIsNone(body["data"])
        self.assertTrue(body["errors"])

    def test_refresh_when_database_unavailable_returns_503_with_envelope(self):
        """Database errors during refresh should surface as 503 with JSON envelope."""
        # Obtain a valid refresh token first.
        login = self.api_client.post(
            "/auth/login/",
            {"email": self.user.email, "password": self.password},
            format="json",
        ).json()["data"]
        refresh_token = login["refresh"]

        # Simulate a database outage when looking up the user during refresh.
        with mock.patch(
                "authentication.views._get_active_user",
                side_effect=DatabaseError("DB down"),
        ):
            response = self.api_client.post(
                "/auth/refresh/",
                {"refresh": refresh_token},
                format="json",
            )

        body = response.json()
        self.assertEqual(response.status_code, 503)
        self.assertIsNone(body["data"])
        self.assertTrue(body["errors"])

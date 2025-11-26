"""Matrix tests for authentication flows (register, login, refresh, logout, soft delete)."""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from rest_framework.test import APIClient

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

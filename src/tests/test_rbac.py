"""RBAC matrix tests for article endpoints."""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from rest_framework.test import APIClient

from articles.models import Article
from authentication.services import TokenService
from tests.utils import FakeRedis, create_user, seed_rbac_basics


class RBACArticleTests(TestCase):
    """Validate own/all permission flags across Admin/User/Guest roles."""

    @classmethod
    def setUpClass(cls):
        """Patch Redis clients to use the in-memory fake for RBAC tests."""
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
        """Stop Redis patches after the suite finishes."""
        for patcher in cls.patchers:
            patcher.stop()
        super().tearDownClass()

    @classmethod
    def setUpTestData(cls):
        """Seed roles, users, and baseline articles for RBAC scenarios."""
        cls.roles, _ = seed_rbac_basics()

        cls.admin_password = "AdminPass123"
        cls.user_password = "UserPass123"
        cls.guest_password = "GuestPass123"

        cls.admin = create_user(
            "admin@test.com",
            cls.admin_password,
            cls.roles["Admin"],
            first_name="Admin",
            is_superuser=True,
            is_staff=True,
        )
        cls.standard_user = create_user("user@test.com", cls.user_password, cls.roles["User"], first_name="User")
        cls.guest_user = create_user("guest@test.com", cls.guest_password, cls.roles["Guest"], first_name="Guest")

        # Seed sample articles
        cls.admin_articles = [
            Article.objects.create(title="Admin Article 1", content="A1", owner=cls.admin),
            Article.objects.create(title="Admin Article 2", content="A2", owner=cls.admin),
        ]
        cls.user_articles = [
            Article.objects.create(title="User Article 1", content="U1", owner=cls.standard_user),
            Article.objects.create(title="User Article 2", content="U2", owner=cls.standard_user),
        ]

    @staticmethod
    def auth_client(user):
        """Return an APIClient authenticated with a fresh access token."""
        token, _ = TokenService.generate_tokens(user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        return client

    def test_admin_can_crud_all_articles(self):
        """Admin role can list, create, update, and delete any article."""
        client = self.auth_client(self.admin)

        list_response = client.get("/articles/")
        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(len(list_response.json()["data"]), 4)

        create_response = client.post("/articles/", {"title": "New Admin", "content": "Body"}, format="json")
        self.assertEqual(create_response.status_code, 201)
        created_id = create_response.json()["data"]["id"]

        target_id = self.user_articles[0].pk
        update_response = client.put(
            f"/articles/{target_id}/", {"title": "Admin Updated", "content": "Updated"}, format="json"
        )
        self.assertEqual(update_response.status_code, 200)

        delete_response = client.delete(f"/articles/{target_id}/")
        self.assertEqual(delete_response.status_code, 204)

        # Cleanup created article to keep DB tidy within the test transaction.
        client.delete(f"/articles/{created_id}/")

    def test_user_owns_only_their_articles(self):
        """Standard user is limited to own articles; foreign access denied."""
        client = self.auth_client(self.standard_user)

        list_response = client.get("/articles/")
        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(len(list_response.json()["data"]), 2)

        # Cannot access admin-owned article detail.
        detail_response = client.get(f"/articles/{self.admin_articles[0].pk}/")
        self.assertIn(detail_response.status_code, (403, 404))

        # Can create and update own article.
        create_response = client.post("/articles/", {"title": "User Created", "content": "Body"}, format="json")
        self.assertEqual(create_response.status_code, 201)
        new_id = create_response.json()["data"]["id"]

        update_own = client.patch(f"/articles/{new_id}/", {"title": "User Updated"}, format="json")
        self.assertEqual(update_own.status_code, 200)

        # Cannot modify admin-owned article.
        update_foreign = client.patch(
            f"/articles/{self.admin_articles[0].pk}/", {"title": "Hack"}, format="json"
        )
        self.assertIn(update_foreign.status_code, (403, 404))

        # Own delete allowed; foreign delete denied.
        delete_own = client.delete(f"/articles/{new_id}/")
        self.assertEqual(delete_own.status_code, 204)

        delete_foreign = client.delete(f"/articles/{self.admin_articles[1].pk}/")
        self.assertIn(delete_foreign.status_code, (403, 404))

    def test_guest_is_read_only(self):
        """Guest role can only read; writes are forbidden."""
        client = self.auth_client(self.guest_user)

        list_response = client.get("/articles/")
        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(len(list_response.json()["data"]), 4)

        create_response = client.post("/articles/", {"title": "Guest Try", "content": "X"}, format="json")
        self.assertEqual(create_response.status_code, 403)

        update_response = client.patch(
            f"/articles/{self.user_articles[0].pk}/", {"title": "Nope"}, format="json"
        )
        self.assertEqual(update_response.status_code, 403)

        delete_response = client.delete(f"/articles/{self.user_articles[0].pk}/")
        self.assertEqual(delete_response.status_code, 403)

    def test_missing_rule_results_in_403(self):
        """Absence of AccessRule for role/element yields 403."""
        from access_control.models import Role

        no_rule_role = Role.objects.create(name="NoRule")
        user_without_rule = create_user("norule@test.com", "NoRulePass123", no_rule_role)
        client = self.auth_client(user_without_rule)

        response = client.get("/articles/")
        self.assertEqual(response.status_code, 403)

    def test_inactive_user_gets_401(self):
        """Inactive users receive 401 on protected endpoints."""
        inactive_user = create_user("inactive@test.com", "Inactive123", self.roles["User"])
        token, _ = TokenService.generate_tokens(inactive_user)
        inactive_user.is_active = False
        inactive_user.save(update_fields=["is_active"])

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = client.get("/articles/")
        self.assertEqual(response.status_code, 401)


class AccessRuleApiTests(TestCase):
    """Tests for AccessRule admin API behavior."""

    @classmethod
    def setUpClass(cls):
        """Patch Redis clients to use in-memory fake for access rule tests."""
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
        """Stop Redis patches after access rule tests complete."""
        for patcher in cls.patchers:
            patcher.stop()
        super().tearDownClass()

    @classmethod
    def setUpTestData(cls):
        """Seed base RBAC infra and an admin user for API tests."""
        cls.roles, cls.elements = seed_rbac_basics()
        cls.admin_password = "AdminPass123"
        cls.admin = create_user(
            "admin_access_rule@test.com",
            cls.admin_password,
            cls.roles["Admin"],
            first_name="Admin",
            is_superuser=True,
            is_staff=True,
        )

    def setUp(self):
        """Authenticate as admin for each test."""
        self.api_client: APIClient = APIClient()
        login = self.api_client.post(
            "/auth/login/",
            {"email": self.admin.email, "password": self.admin_password},
            format="json",
        ).json()
        access = login["data"]["access"]
        self.api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

    def test_duplicate_role_element_access_rule_is_rejected(self):
        """Creating an AccessRule with duplicate (role, element) via API returns 400."""
        # The seed_rbac_basics helper already created a rule for (User, article).
        # Attempting to create it again via the API must be rejected.
        payload = {
            "role": "User",
            "element": "article",
            "can_read_own": True,
            "can_read_all": False,
            "can_create": True,
            "can_update_own": True,
            "can_update_all": False,
            "can_delete_own": True,
            "can_delete_all": False,
        }
        response = self.api_client.post("/access-rules/", payload, format="json")
        body = response.json()

        self.assertEqual(response.status_code, 400)
        self.assertIsNone(body["data"])
        self.assertTrue(body["errors"])

    def test_missing_authorization_header_returns_401(self):
        """Requests without Authorization header on protected endpoints yield 401.

        This matches the requirement that if the logged-in user cannot be
        determined from the incoming request, the API must return 401 rather
        than 403.
        """
        client = APIClient()
        response = client.get("/articles/")
        self.assertEqual(response.status_code, 401)

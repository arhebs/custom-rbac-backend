"""Shared helpers for tests (RBAC seeding, user creation, fake Redis)."""

from __future__ import annotations

from typing import Dict, Tuple

from django.contrib.auth import get_user_model

from access_control.models import Role
from authentication.managers import UserManager
from scripts.management.commands.seed_rbac import (
    create_seed_elements,
    create_seed_roles,
    create_seed_rules,
)

User = get_user_model()


class FakeRedis:
    """Minimal Redis stub supporting the commands used by TokenService."""

    def __init__(self):
        self._store: Dict[str, str] = {}

    def setex(self, key: str, ttl_seconds: int, value: str) -> None:
        """Mimic Redis SETEX; TTL is ignored in tests, value stored in-memory."""
        self._store[key] = value

    def get(self, key: str):
        """Return stored value for key or None, matching Redis GET semantics."""
        return self._store.get(key)


def seed_rbac_basics() -> Tuple[dict, dict]:
    """Create base roles, business elements, and access rules for tests.

    Delegates to the same helpers used by the ``seed_rbac`` management command
    to keep RBAC setup logic in a single place.
    """

    roles = create_seed_roles()
    elements = create_seed_elements()
    create_seed_rules(roles, elements)
    return roles, elements


def create_user(email: str, password: str, role: Role, **extra):
    """Create a user with a bcrypt-hashed password for tests."""

    return User.objects.create(
        email=email,
        password_hash=UserManager.hash_password(password),
        role=role,
        **extra,
    )

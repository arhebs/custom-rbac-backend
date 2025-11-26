"""App configuration for the access_control Django application.

This module wires up the application config and ensures that RBAC-related
system checks are registered when Django starts.
"""

from django.apps import AppConfig


class AccessControlConfig(AppConfig):
    """Application configuration for the access_control app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "access_control"

    def ready(self) -> None:
        """Register system checks when the app is loaded."""
        # Import system checks so they are registered with Django.
        from . import checks  # noqa: F401

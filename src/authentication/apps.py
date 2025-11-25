"""App configuration for authentication components."""

from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
    """Authentication app holds the custom User model and auth utilities."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "authentication"

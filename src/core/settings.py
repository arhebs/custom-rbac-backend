"""Django settings for the Custom RBAC project.

Environment-driven configuration for Postgres, Redis, and security defaults.
"""
import os
from pathlib import Path
from urllib.parse import urlparse

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def _get_env(name: str, default: str | None = None) -> str | None:
    """Read an environment variable with an optional fallback."""
    return os.environ.get(name, default)


def _parse_database_url(url: str) -> dict:
    """Parse a PostgreSQL-style DATABASE_URL into a Django DATABASES entry."""
    parsed = urlparse(url)
    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": parsed.path.lstrip("/"),
        "USER": parsed.username,
        "PASSWORD": parsed.password,
        "HOST": parsed.hostname,
        "PORT": parsed.port or "5432",
    }


SECRET_KEY = _get_env("SECRET_KEY", "dev-secret-key-change-me")
DEBUG = _get_env("DEBUG", "True") == "True"
if not DEBUG and SECRET_KEY in ("change-me", "dev-secret-key-change-me"):
    raise ImproperlyConfigured("SECRET_KEY must be set in production")
ALLOWED_HOSTS = [
    h.strip()
    for h in _get_env("ALLOWED_HOSTS", "localhost,127.0.0.1,0.0.0.0").split(",")
    if h.strip()
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "drf_spectacular",
    "core",
    "authentication",
    "access_control",
    "articles",
    "scripts",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # JWTAuthMiddleware will be added below to run after common middlewares
    "core.middleware.JWTAuthMiddleware",
]

ROOT_URLCONF = "core.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "core.wsgi.application"
ASGI_APPLICATION = "core.asgi.application"

DATABASE_URL = _get_env("DATABASE_URL")
if DATABASE_URL:
    DATABASES = {"default": _parse_database_url(DATABASE_URL)}
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": _get_env("POSTGRES_DB", "custom_rbac"),
            "USER": _get_env("POSTGRES_USER", "custom_rbac"),
            "PASSWORD": _get_env("POSTGRES_PASSWORD", "custom_rbac"),
            "HOST": _get_env("POSTGRES_HOST", "localhost"),
            "PORT": _get_env("POSTGRES_PORT", "5433"),
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 8},
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_USER_MODEL = "authentication.User"

ALLOW_SUPERUSER_BYPASS = _get_env("ALLOW_SUPERUSER_BYPASS", "False") == "True"
DEBUG_AUTH_ERRORS = _get_env("DEBUG_AUTH_ERRORS", "False") == "True"
REDIS_URL = _get_env("REDIS_URL", "redis://localhost:6380/0")

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["core.authentication.MiddlewareUserAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": [],
    "EXCEPTION_HANDLER": "core.exceptions.custom_exception_handler",
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Custom RBAC API",
    "DESCRIPTION": (
        "OpenAPI schema for the Custom Authentication & Authorization backend "
        "with JWT + refresh tokens, Redis blocklist, and database-backed RBAC."
    ),
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "SERVE_PUBLIC": True,
    "APPEND_COMPONENTS": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
        }
    },
    # Apply JWT bearer auth by default to operations unless overridden.
    "SECURITY": [{"bearerAuth": []}],
}

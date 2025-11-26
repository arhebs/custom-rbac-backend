"""Authentication helpers that bridge JWT middleware into DRF.

DRF's ``Request.user`` normally relies on its own authentication classes.
Since this project performs JWT verification in ``JWTAuthMiddleware``, this
module provides a lightweight authenticator that simply surfaces the user
already attached to the underlying Django request.
"""

from typing import Any, Optional, Tuple

from django.contrib.auth.models import AnonymousUser
from rest_framework.authentication import BaseAuthentication


class MiddlewareUserAuthentication(BaseAuthentication):
    """Expose ``request._request.user`` (set by middleware) to DRF.

    This authenticator does *not* perform any credential parsing or token
    decoding. It assumes that ``JWTAuthMiddleware`` has already validated the
    bearer token (if present) and attached a proper user object to the Django
    request. If the user is anonymous or missing, authentication is skipped.
    """

    def authenticate(self, request) -> Optional[Tuple[Any, None]]:
        # DRF's Request wraps the original Django HttpRequest as ``. _request``.
        django_request = getattr(request, "_request", None)
        if django_request is None:
            return None

        user = getattr(django_request, "user", None)
        if user is None or isinstance(user, AnonymousUser):
            return None

        if not getattr(user, "is_authenticated", False):
            return None

        return user, None


__all__ = ["MiddlewareUserAuthentication"]


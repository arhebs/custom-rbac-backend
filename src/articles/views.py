"""Article ViewSet protected by RBACPermission."""

from rest_framework import viewsets

from access_control.permissions import RBACPermission
from core.response import BaseViewSet
from .models import Article
from .serializers import ArticleSerializer


class ArticleViewSet(BaseViewSet, viewsets.ModelViewSet):
    serializer_class = ArticleSerializer
    permission_classes = [RBACPermission]
    business_element = "article"

    def get_queryset(self):
        user = self.request.user
        if not getattr(user, "is_authenticated", False):
            return Article.objects.none()
        # Fetch the rule once via the permission helper to scope queryset
        role = getattr(user, "role", None)
        rule = self._get_rule(role)
        if not rule:
            return Article.objects.none()

        if rule.can_read_all:
            return Article.objects.all()
        if rule.can_read_own:
            return Article.objects.filter(owner=user)
        return Article.objects.none()

    def perform_create(self, serializer):
        """Attach the current user as owner on create."""
        serializer.save(owner=self.request.user)

    def _get_rule(self, role):
        """Reuse AccessRule lookup to scope queryset decisions."""
        from access_control.models import AccessRule

        try:
            if role is None:
                return None
            return AccessRule.objects.get(role=role, element__key=self.business_element)
        except AccessRule.DoesNotExist:
            return None


__all__ = ["ArticleViewSet"]

"""System checks for RBAC configuration."""

from django.core.checks import Error, register

from access_control.permissions import RBACPermission


@register()
def rbac_views_have_business_element(app_configs, **kwargs):
    """Ensure RBAC-protected views declare a business_element attribute.

    This check is intentionally conservative and only inspects known viewsets
    in this project. If new RBAC-protected views are introduced, they should
    either be added here or share a common base class that this check can
    introspect.
    """
    errors: list[Error] = []

    # Import here to avoid circular imports at module load time.
    from articles.views import ArticleViewSet
    from access_control.views import AccessRuleViewSet

    rbac_views = [ArticleViewSet, AccessRuleViewSet]

    for view_cls in rbac_views:
        permission_classes = getattr(view_cls, "permission_classes", [])
        if RBACPermission in permission_classes:
            element = getattr(view_cls, "business_element", None)
            if not element:
                errors.append(
                    Error(
                        f"{view_cls.__name__} uses RBACPermission but does not "
                        f"define business_element.",
                        obj=view_cls,
                        id="access_control.E001",
                    )
                )

    return errors


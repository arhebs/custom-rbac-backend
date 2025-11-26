"""Seed roles, business elements, access rules, and sample data."""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

from access_control.models import AccessRule, BusinessElement, Role
from articles.models import Article
from authentication.managers import UserManager


class Command(BaseCommand):
    """Management command to seed roles, rules, and sample data."""

    help = (
        "Seed RBAC roles, business elements, rules, and sample users/articles. "
        "Use --reset to clear previously seeded data first."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help=(
                "Clear seeded RBAC roles/elements/rules and demo users/articles "
                "before running the seeder."
            ),
        )

    def handle(self, *args, **options):
        """Entrypoint for the management command."""
        if options.get("reset"):
            self._reset_seeded_data()

        self.stdout.write("Seeding RBAC data...")
        roles = self._create_roles()
        elements = self._create_elements()
        self._create_rules(roles, elements)
        self._create_sample_users_and_articles(roles)
        self.stdout.write(self.style.SUCCESS("RBAC seed completed."))

    def _reset_seeded_data(self) -> None:
        """Remove previously seeded RBAC infra and demo data.

        This is intentionally conservative: it only removes the three base roles
        (Admin/User/Guest), the three base business elements (article/access_rule/user),
        their associated AccessRule rows, and the demo users/articles created by
        this command.
        """
        self.stdout.write("Resetting previously seeded RBAC data...")

        User = get_user_model()

        # Delete demo users (their articles will be cascaded via FK).
        demo_emails = ["admin@example.com", "user@example.com", "guest@example.com"]
        User.objects.filter(email__in=demo_emails).delete()

        # Clear access rules for the base roles/elements.
        AccessRule.objects.filter(role__name__in=["Admin", "User", "Guest"]).delete()
        AccessRule.objects.filter(element__key__in=["article", "access_rule", "user"]).delete()

        # Remove the base roles and business elements themselves.
        Role.objects.filter(name__in=["Admin", "User", "Guest"]).delete()
        BusinessElement.objects.filter(key__in=["article", "access_rule", "user"]).delete()

        self.stdout.write(self.style.WARNING("Seeded RBAC data cleared."))

    @staticmethod
    def _create_roles():
        """Create base roles if missing and return a name->Role map."""
        roles = {}
        for name in ["Admin", "User", "Guest"]:
            role, _ = Role.objects.get_or_create(name=name)
            roles[name] = role
        return roles

    @staticmethod
    def _create_elements():
        """Create business elements used by RBAC."""
        elements = {}
        for key in ["article", "access_rule", "user"]:
            elem, _ = BusinessElement.objects.get_or_create(key=key)
            elements[key] = elem
        return elements

    @staticmethod
    def _create_rules(roles, elements):
        """Create or update access rules for Admin/User/Guest roles."""
        # Admin full access
        AccessRule.objects.update_or_create(
            role=roles["Admin"],
            element=elements["article"],
            defaults={
                "can_read_own": True,
                "can_read_all": True,
                "can_create": True,
                "can_update_own": True,
                "can_update_all": True,
                "can_delete_own": True,
                "can_delete_all": True,
            },
        )
        AccessRule.objects.update_or_create(
            role=roles["Admin"],
            element=elements["access_rule"],
            defaults={
                "can_read_own": True,
                "can_read_all": True,
                "can_create": True,
                "can_update_own": True,
                "can_update_all": True,
                "can_delete_own": True,
                "can_delete_all": True,
            },
        )
        # User own-only on articles
        AccessRule.objects.update_or_create(
            role=roles["User"],
            element=elements["article"],
            defaults={
                "can_read_own": True,
                "can_read_all": False,
                "can_create": True,
                "can_update_own": True,
                "can_update_all": False,
                "can_delete_own": True,
                "can_delete_all": False,
            },
        )
        # Guest read-only on articles
        AccessRule.objects.update_or_create(
            role=roles["Guest"],
            element=elements["article"],
            defaults={
                "can_read_own": False,
                "can_read_all": True,
                "can_create": False,
                "can_update_own": False,
                "can_update_all": False,
                "can_delete_own": False,
                "can_delete_all": False,
            },
        )

    @staticmethod
    def _create_sample_users_and_articles(roles):
        """Create sample users and articles for quick testing."""
        User = get_user_model()

        admin, _ = User.objects.get_or_create(
            email="admin@example.com",
            defaults={
                "role": roles["Admin"],
                "first_name": "Admin",
                "password_hash": UserManager.hash_password("adminpass"),
                "is_staff": True,
                "is_superuser": True,
            },
        )

        user, _ = User.objects.get_or_create(
            email="user@example.com",
            defaults={
                "role": roles["User"],
                "first_name": "User",
                "password_hash": UserManager.hash_password("userpass"),
            },
        )

        guest, _ = User.objects.get_or_create(
            email="guest@example.com",
            defaults={
                "role": roles["Guest"],
                "first_name": "Guest",
                "password_hash": UserManager.hash_password("guestpass"),
            },
        )

        Article.objects.get_or_create(
            title="Admin Article 1",
            owner=admin,
            defaults={"content": "Content by admin."},
        )
        Article.objects.get_or_create(
            title="Admin Article 2",
            owner=admin,
            defaults={"content": "Another admin article."},
        )
        Article.objects.get_or_create(
            title="User Article 1",
            owner=user,
            defaults={"content": "User owned article."},
        )
        Article.objects.get_or_create(
            title="User Article 2",
            owner=user,
            defaults={"content": "Another user article."},
        )

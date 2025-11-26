"""Root URL configuration for the Custom RBAC API."""
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("auth/", include("authentication.urls")),
    path("", include("access_control.urls")),
    path("", include("articles.urls")),
]

"""Root URL configuration for the Custom RBAC API."""
from django.contrib import admin
from django.urls import path

urlpatterns = [
    path("admin/", admin.site.urls),
    # App URLs will be included in later steps
]

"""
Top-level URL map.

Every API route lives under /api/v1/ so the contract can change later
without breaking old clients. Each app adds its own urls.py here.
"""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("api/v1/", include("core.urls")),
    # Week 2+: path("api/v1/auth/", include("accounts.urls")),
    # Week 3+: path("api/v1/nodes/", include("nodes.urls")),
    path("django-admin/", admin.site.urls),  # developer view of the data, superusers only
]

# JSON errors for requests that never reach a DRF view (e.g. an unknown URL).
handler400 = "core.views.error_400"
handler403 = "core.views.error_403"
handler404 = "core.views.error_404"
handler500 = "core.views.error_500"

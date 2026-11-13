"""
Top-level URL map.

Every API route lives under /api/v1/ so the contract can change later
without breaking old clients. Each app adds its own urls.py here.
"""

from django.conf import settings
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("api/v1/", include("core.urls")),
    path("api/v1/auth/", include("accounts.urls")),
    path("api/v1/users/", include("accounts.users_urls")),
    path("api/v1/audit/", include("audit.urls")),
    path("api/v1/", include("nodes.urls")),
    path("api/v1/tasks/", include("tasks.urls")),
    path("api/v1/node-api/tasks/", include("tasks.node_urls")),
    path("api/v1/", include("trust.urls")),
    path("api/v1/", include("heartbeats.urls")),
]

# The Django admin has its own login page without our rate limits or audit events,
# so it is only available on a developer's machine (DEBUG=True), never in the demo build.
if settings.DEBUG:
    urlpatterns.append(path("django-admin/", admin.site.urls))

# JSON errors for requests that never reach a DRF view (e.g. an unknown URL).
handler400 = "core.views.error_400"
handler403 = "core.views.error_403"
handler404 = "core.views.error_404"
handler500 = "core.views.error_500"
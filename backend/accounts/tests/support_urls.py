"""Test-only endpoints, one per access level. Loaded only by test_permissions.py."""

from django.urls import include, path
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import require


def guarded(capability):
    class View(APIView):
        permission_classes = [require(capability)]

        def get(self, request):
            return Response({"ok": True})

        def post(self, request):
            return Response({"ok": True})

    View.__name__ = f"Guarded_{capability.replace('.', '_')}"
    return View.as_view()


urlpatterns = [
    path("t/view/", guarded("nodes.view")),
    path("t/operate/", guarded("tasks.submit")),
    path("t/admin/", guarded("nodes.revoke")),
    path("api/v1/", include("core.urls")),
]

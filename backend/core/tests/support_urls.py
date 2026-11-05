"""
Test-only endpoints that trigger each kind of failure, so the error
handler can be tested before the real endpoints exist. Never routed in
production: only loaded via override_settings(ROOT_URLCONF=...).
"""

from django.urls import include, path
from rest_framework.permissions import AllowAny, BasePermission
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView

from core.errors import APIError, ErrorCode


class EchoView(APIView):
    """Authenticated POST that parses the JSON body."""

    def post(self, request):
        return Response({"received_keys": sorted(request.data.keys())})


class PublicEchoView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        return Response({"received_keys": sorted(request.data.keys())})


class NeverAllowed(BasePermission):
    def has_permission(self, request, view):
        return False


class ForbiddenView(APIView):
    permission_classes = [NeverAllowed]

    def get(self, request):
        return Response({"secret": "should never be returned"})


class CrashView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        raise RuntimeError("db password=hunter2 at C:\\Users\\dev\\secret.py line 42")


class DomainErrorView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        raise APIError(ErrorCode.NODE_REVOKED)


class TwoPerMinute(SimpleRateThrottle):
    rate = "2/min"

    def get_cache_key(self, request, view):
        return "test-throttle"


class ThrottledView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [TwoPerMinute]

    def get(self, request):
        return Response({"ok": True})


urlpatterns = [
    path("t/echo/", EchoView.as_view()),
    path("t/public-echo/", PublicEchoView.as_view()),
    path("t/forbidden/", ForbiddenView.as_view()),
    path("t/crash/", CrashView.as_view()),
    path("t/domain-error/", DomainErrorView.as_view()),
    path("t/throttled/", ThrottledView.as_view()),
    path("api/v1/", include("core.urls")),
]

handler404 = "core.views.error_404"
handler500 = "core.views.error_500"

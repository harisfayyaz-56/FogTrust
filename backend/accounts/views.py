"""
Authentication endpoints (docs/api-contract.md, section 5.2).

    GET  /api/v1/auth/csrf/     set the CSRF cookie (call once when the dashboard loads)
    POST /api/v1/auth/login/    start a session
    POST /api/v1/auth/logout/   end it
    GET  /api/v1/auth/me/       who am I, and what may I do
"""

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.middleware.csrf import get_token
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from audit.services import log_event
from core.errors import APIError, ErrorCode

from .models import User
from .permissions import capabilities_for
from .serializers import LoginSerializer
from .throttles import LoginUsernameThrottle


def _user_summary(user) -> dict:
    return {"username": user.get_username(), "role": user.role}


class CsrfTokenView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        # get_token() also tells the CSRF middleware to set the csrftoken cookie.
        return Response({"csrf_token": get_token(request._request)})


class LoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []  # an existing session is irrelevant here; login replaces it
    throttle_classes = [ScopedRateThrottle, LoginUsernameThrottle]
    throttle_scope = "login"

    def post(self, request):
        # DRF only checks CSRF for users who are already signed in. Checking it here too
        # stops a malicious site from silently logging the victim into an attacker's account.
        SessionAuthentication().enforce_csrf(request)

        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data["username"]
        password = serializer.validated_data["password"]

        # Django runs the password hasher even for unknown usernames, so response time
        # does not reveal whether an account exists.
        user = authenticate(request._request, username=username, password=password)
        if user is None:
            reason = self._failure_reason(username)
            log_event(
                "auth.login",
                "failure",
                request=request,
                target_type="user",
                target_id=username,
                reason_code=reason,
                details={"username_known": User.objects.filter(username=username).exists()},
            )
            # Same code and message for every failure, so attackers cannot probe accounts.
            raise APIError(ErrorCode.AUTH_INVALID_CREDENTIALS)

        django_login(request._request, user)  # new session key (no fixation) and new CSRF token
        log_event("auth.login", "success", request=request, actor=user, target_type="user", target_id=username)
        return Response({"user": _user_summary(user), "session_expires_in": settings.SESSION_COOKIE_AGE})

    @staticmethod
    def _failure_reason(username: str) -> str:
        """Precise reason for the audit log only. The client always sees AUTH_INVALID_CREDENTIALS."""
        if User.objects.filter(username=username, is_active=False).exists():
            return ErrorCode.AUTH_ACCOUNT_DISABLED
        return ErrorCode.AUTH_INVALID_CREDENTIALS


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        log_event("auth.logout", "success", request=request, actor=user, target_type="user", target_id=user.username)
        django_logout(request._request)  # deletes the server-side session
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response(
            {
                **_user_summary(user),
                "permissions": capabilities_for(user.role),
                "session_idle_timeout": settings.SESSION_COOKIE_AGE,
            }
        )

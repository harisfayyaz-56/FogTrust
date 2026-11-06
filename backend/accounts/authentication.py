"""
Session authentication with two expiry rules.

  Idle timeout      SESSION_COOKIE_AGE + SESSION_SAVE_EVERY_REQUEST (settings.py):
                    the session ends after 30 minutes without a request.
  Absolute timeout  SESSION_ABSOLUTE_TIMEOUT_SECONDS: the session ends 8 hours after
                    login even if it is used constantly, so a stolen cookie
                    cannot be kept alive for ever.

CSRF is enforced for every authenticated unsafe request (DRF behaviour).
"""

import time

from django.conf import settings
from django.contrib.auth import logout as django_logout
from rest_framework.authentication import SessionAuthentication

from audit.services import log_event
from core.errors import APIError, ErrorCode

LOGIN_AT_SESSION_KEY = "_fogtrust_login_at"


class FogTrustSessionAuthentication(SessionAuthentication):
    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            return None

        user, auth = result
        login_at = request.session.get(LOGIN_AT_SESSION_KEY)
        limit = settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS
        if not isinstance(login_at, (int, float)) or time.time() - login_at > limit:
            log_event(
                "auth.session_expired",
                "failure",
                request=request,
                actor=user,
                target_type="user",
                target_id=user.get_username(),
                reason_code=ErrorCode.AUTH_SESSION_EXPIRED,
                details={"kind": "absolute", "limit_seconds": limit},
            )
            django_logout(request._request)
            raise APIError(ErrorCode.AUTH_SESSION_EXPIRED)
        return result

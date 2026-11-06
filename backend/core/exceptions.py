"""
One exception handler for every DRF view.

Goals (from the brief: "use stable error codes and never expose stack traces"):
  * every failure returns the same JSON envelope with a stable code
  * unexpected exceptions are logged server-side with the request ID,
    and the client only sees INTERNAL_ERROR plus that ID
  * validation messages never echo what the client sent
  * security-relevant refusals are written to the audit log:
      access.denied         a signed-in user hit an endpoint their role may not use,
                            or a request failed the CSRF check
      request.rate_limited  a client was throttled (recorded once per client per minute,
                            so a flood cannot flood the audit log)
"""

import logging

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import RequestDataTooBig, SuspiciousOperation
from django.db import DatabaseError
from django.http import Http404
from rest_framework import exceptions as drf
from rest_framework.response import Response

from .errors import ERROR_CATALOG, APIError, ErrorCode, error_body

logger = logging.getLogger("fogtrust.errors")

# DRF messages for these codes include the submitted value, e.g. '"x" is not a valid choice.'
_ECHOING_VALIDATION_CODES = {
    "invalid_choice": "Not a valid choice.",
    "does_not_exist": "The referenced object does not exist.",
}

RATE_LIMIT_AUDIT_WINDOW_SECONDS = 60


def _safe_validation_detail(detail):
    if isinstance(detail, dict):
        return {key: _safe_validation_detail(value) for key, value in detail.items()}
    if isinstance(detail, list):
        return [_safe_validation_detail(item) for item in detail]
    code = getattr(detail, "code", None)
    return _ECHOING_VALIDATION_CODES.get(code, str(detail))


def _has_session_cookie(request) -> bool:
    return bool(request is not None and request.COOKIES.get(settings.SESSION_COOKIE_NAME))


def _classify(exc, request=None) -> tuple[str, dict | None]:
    """Map an exception to (error code, optional safe details)."""
    if isinstance(exc, APIError):
        return exc.error_code, exc.details
    if isinstance(exc, RequestDataTooBig):
        return ErrorCode.PAYLOAD_TOO_LARGE, None
    if isinstance(exc, drf.ValidationError):
        return ErrorCode.VALIDATION_ERROR, {"fields": _safe_validation_detail(exc.detail)}
    if isinstance(exc, drf.ParseError):
        return ErrorCode.MALFORMED_REQUEST, None
    if isinstance(exc, (drf.NotAuthenticated, drf.AuthenticationFailed)):
        # A session cookie that no longer maps to a signed-in user means the session timed out.
        if _has_session_cookie(request):
            return ErrorCode.AUTH_SESSION_EXPIRED, None
        return ErrorCode.AUTH_REQUIRED, None
    if isinstance(exc, drf.PermissionDenied):
        if str(exc.detail).startswith("CSRF Failed"):
            return ErrorCode.CSRF_FAILED, None
        return ErrorCode.PERMISSION_DENIED, None
    if isinstance(exc, DjangoPermissionDenied):
        return ErrorCode.PERMISSION_DENIED, None
    if isinstance(exc, (drf.NotFound, Http404)):
        return ErrorCode.NOT_FOUND, None
    if isinstance(exc, drf.MethodNotAllowed):
        return ErrorCode.METHOD_NOT_ALLOWED, None
    if isinstance(exc, drf.NotAcceptable):
        return ErrorCode.NOT_ACCEPTABLE, None
    if isinstance(exc, drf.UnsupportedMediaType):
        return ErrorCode.UNSUPPORTED_MEDIA_TYPE, None
    if isinstance(exc, drf.Throttled):
        return ErrorCode.RATE_LIMITED, {"retry_after_seconds": int(exc.wait or 0) or None}
    if isinstance(exc, SuspiciousOperation):
        return ErrorCode.MALFORMED_REQUEST, None
    if isinstance(exc, drf.APIException):
        return ErrorCode.REQUEST_FAILED, None
    return ErrorCode.INTERNAL_ERROR, None


def _audit_refusal(code: str, request, view) -> None:
    """Record denied and throttled requests. Never turns a 403/429 into a 500."""
    if request is None or code not in (ErrorCode.PERMISSION_DENIED, ErrorCode.CSRF_FAILED, ErrorCode.RATE_LIMITED):
        return
    from audit.services import log_event  # imported here: audit depends on core, not the reverse

    view_name = type(view).__name__ if view is not None else ""
    details = {"method": request.method, "path": request.path}
    try:
        if code == ErrorCode.RATE_LIMITED:
            scope = getattr(view, "throttle_scope", "") or "default"
            key = f"audit-rate-limited:{scope}:{request.META.get('REMOTE_ADDR', '')}"
            if not cache.add(key, 1, timeout=RATE_LIMIT_AUDIT_WINDOW_SECONDS):
                return
            log_event(
                "request.rate_limited",
                "denied",
                request=request,
                target_type="endpoint",
                target_id=view_name,
                reason_code=code,
                details={**details, "scope": scope},
            )
        else:
            log_event(
                "access.denied",
                "denied",
                request=request,
                target_type="endpoint",
                target_id=view_name,
                reason_code=code,
                details=details,
            )
    except DatabaseError:
        logger.exception("Could not write audit event for %s request_id=%s", code, getattr(request, "request_id", None))


def api_exception_handler(exc, context):
    request = context.get("request")
    view = context.get("view")
    request_id = getattr(request, "request_id", None)

    code, details = _classify(exc, request)
    status_code, _ = ERROR_CATALOG[code]
    message = None

    if isinstance(exc, APIError):
        status_code, message = exc.status_code, exc.message
    elif code == ErrorCode.REQUEST_FAILED:
        status_code = getattr(exc, "status_code", status_code)

    if code == ErrorCode.INTERNAL_ERROR:
        # Full details go to the server log only, never to the client.
        logger.exception("Unhandled exception request_id=%s", request_id)
    elif status_code >= 500:
        logger.error("Server error code=%s request_id=%s", code, request_id)

    _audit_refusal(code, request, view)

    if details and "retry_after_seconds" in details and details["retry_after_seconds"] is None:
        details = None

    response = Response(error_body(code, message, request_id, details), status=status_code)

    if isinstance(exc, drf.Throttled) and exc.wait:
        response["Retry-After"] = str(int(exc.wait))
    return response

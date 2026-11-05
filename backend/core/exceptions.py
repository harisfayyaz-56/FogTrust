"""
One exception handler for every DRF view.

Goals (from the brief: "use stable error codes and never expose stack traces"):
  * every failure returns the same JSON envelope with a stable code
  * unexpected exceptions are logged server-side with the request ID,
    and the client only sees INTERNAL_ERROR plus that ID
"""

import logging

from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import RequestDataTooBig, SuspiciousOperation
from django.http import Http404
from rest_framework import exceptions as drf
from rest_framework.response import Response

from .errors import ERROR_CATALOG, APIError, ErrorCode, error_body

logger = logging.getLogger("fogtrust.errors")


def _classify(exc) -> tuple[str, dict | None]:
    """Map an exception to (error code, optional safe details)."""
    if isinstance(exc, APIError):
        return exc.error_code, exc.details
    if isinstance(exc, RequestDataTooBig):
        return ErrorCode.PAYLOAD_TOO_LARGE, None
    if isinstance(exc, drf.ValidationError):
        # DRF field messages are generic ("This field is required.") and do not echo input.
        return ErrorCode.VALIDATION_ERROR, {"fields": exc.detail}
    if isinstance(exc, drf.ParseError):
        return ErrorCode.MALFORMED_REQUEST, None
    if isinstance(exc, (drf.NotAuthenticated, drf.AuthenticationFailed)):
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


def api_exception_handler(exc, context):
    request = context.get("request")
    request_id = getattr(request, "request_id", None)

    code, details = _classify(exc)
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

    if details and "retry_after_seconds" in details and details["retry_after_seconds"] is None:
        details = None

    response = Response(error_body(code, message, request_id, details), status=status_code)

    if isinstance(exc, drf.Throttled) and exc.wait:
        response["Retry-After"] = str(int(exc.wait))
    return response

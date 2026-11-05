"""
Core views: health check plus JSON error pages for non-DRF requests.
"""

from django.conf import settings
from django.db import DatabaseError, connection
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .errors import APIError, ErrorCode, error_body


@api_view(["GET"])
@permission_classes([AllowAny])
@throttle_classes([])
def health(request):
    """
    GET /api/v1/health/

    Public liveness and readiness check. Reveals only a status and version,
    never configuration, paths or counts. Used by the restart-recovery test.
    """
    try:
        connection.ensure_connection()
    except DatabaseError as exc:
        raise APIError(ErrorCode.SERVICE_UNAVAILABLE) from exc

    return Response(
        {
            "status": "ok",
            "service": "fogtrust-broker",
            "version": settings.FOGTRUST_VERSION,
            "database": "ok",
        }
    )


# --- JSON replacements for Django's HTML error pages -----------------------


def _json_error(request, code: str, status: int) -> JsonResponse:
    return JsonResponse(error_body(code, request_id=getattr(request, "request_id", None)), status=status)


def error_400(request, exception=None):
    return _json_error(request, ErrorCode.MALFORMED_REQUEST, 400)


def error_403(request, exception=None):
    return _json_error(request, ErrorCode.PERMISSION_DENIED, 403)


def error_404(request, exception=None):
    return _json_error(request, ErrorCode.NOT_FOUND, 404)


def error_500(request):
    return _json_error(request, ErrorCode.INTERNAL_ERROR, 500)


def csrf_failure(request, reason=""):
    # `reason` explains the failure to developers; it is not sent to the client.
    return _json_error(request, ErrorCode.CSRF_FAILED, 403)

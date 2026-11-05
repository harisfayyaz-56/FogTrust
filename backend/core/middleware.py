"""
Request ID middleware.

Every request gets a server-generated UUID. It is returned in the
X-Request-ID response header, included in every error body, and will be
stored on audit events, so one ID links what the user saw to what the
server logged. Incoming X-Request-ID headers are ignored on purpose:
a client must not be able to choose or collide IDs.
"""

import uuid


class RequestIdMiddleware:
    header_name = "X-Request-ID"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.request_id = str(uuid.uuid4())
        response = self.get_response(request)
        response[self.header_name] = request.request_id
        return response

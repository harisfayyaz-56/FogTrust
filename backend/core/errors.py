"""
Stable error codes for the whole FogTrust API.

This file is the single source of truth. The frontend, the tests and the
report all refer to these codes, so a code is never renamed once published:
add a new one instead. Keep docs/api-contract.md (section 6) in sync.

Messages are deliberately generic. They never contain user input, stack
traces, file paths, SQL, keys or tokens.
"""

from rest_framework.exceptions import APIException


class ErrorCode:
    # --- Generic request errors (core, Member 1) ---
    VALIDATION_ERROR = "VALIDATION_ERROR"
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    NOT_ACCEPTABLE = "NOT_ACCEPTABLE"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    DUPLICATE_SUBMISSION = "DUPLICATE_SUBMISSION"
    RATE_LIMITED = "RATE_LIMITED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    REQUEST_FAILED = "REQUEST_FAILED"

    # --- Authentication and authorization (Member 1) ---
    AUTH_REQUIRED = "AUTH_REQUIRED"
    AUTH_INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
    AUTH_SESSION_EXPIRED = "AUTH_SESSION_EXPIRED"
    AUTH_ACCOUNT_DISABLED = "AUTH_ACCOUNT_DISABLED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    CSRF_FAILED = "CSRF_FAILED"
    CONFIRMATION_REQUIRED = "CONFIRMATION_REQUIRED"

    # --- Enrollment and revocation (Member 1) ---
    ENROLL_TOKEN_INVALID = "ENROLL_TOKEN_INVALID"
    ENROLL_TOKEN_EXPIRED = "ENROLL_TOKEN_EXPIRED"
    ENROLL_TOKEN_USED = "ENROLL_TOKEN_USED"
    ENROLL_KEY_INVALID = "ENROLL_KEY_INVALID"
    ENROLL_KEY_IN_USE = "ENROLL_KEY_IN_USE"
    ENROLL_PROOF_INVALID = "ENROLL_PROOF_INVALID"
    NODE_NAME_TAKEN = "NODE_NAME_TAKEN"
    NODE_UNKNOWN = "NODE_UNKNOWN"
    NODE_REVOKED = "NODE_REVOKED"
    NODE_ALREADY_REVOKED = "NODE_ALREADY_REVOKED"

    # --- Signed requests and heartbeats (Member 2) ---
    NODE_SIGNATURE_MISSING = "NODE_SIGNATURE_MISSING"
    NODE_SIGNATURE_INVALID = "NODE_SIGNATURE_INVALID"
    HEARTBEAT_STALE = "HEARTBEAT_STALE"
    HEARTBEAT_REPLAYED = "HEARTBEAT_REPLAYED"
    HEARTBEAT_COUNTER_REGRESSED = "HEARTBEAT_COUNTER_REGRESSED"

    # --- Results (Member 2) ---
    RESULT_INTEGRITY_FAILED = "RESULT_INTEGRITY_FAILED"
    RESULT_NOT_ASSIGNED = "RESULT_NOT_ASSIGNED"

    # --- Tasks, trust and policy (Member 3) ---
    TASK_NOT_FOUND = "TASK_NOT_FOUND"
    TASK_INVALID_STATE = "TASK_INVALID_STATE"
    NO_ELIGIBLE_NODE = "NO_ELIGIBLE_NODE"
    POLICY_INVALID = "POLICY_INVALID"

    # --- Audit and reports (Member 1 / Member 4) ---
    AUDIT_CHAIN_BROKEN = "AUDIT_CHAIN_BROKEN"
    EXPORT_FAILED = "EXPORT_FAILED"


# code -> (HTTP status, safe default message)
ERROR_CATALOG: dict[str, tuple[int, str]] = {
    ErrorCode.VALIDATION_ERROR: (400, "The request contains invalid fields."),
    ErrorCode.MALFORMED_REQUEST: (400, "The request body could not be parsed."),
    ErrorCode.PAYLOAD_TOO_LARGE: (413, "The request body is too large."),
    ErrorCode.UNSUPPORTED_MEDIA_TYPE: (415, "Only application/json is accepted."),
    ErrorCode.NOT_ACCEPTABLE: (406, "Only application/json responses are available."),
    ErrorCode.METHOD_NOT_ALLOWED: (405, "This method is not allowed on this endpoint."),
    ErrorCode.NOT_FOUND: (404, "The requested resource was not found."),
    ErrorCode.CONFLICT: (409, "The request conflicts with the current state."),
    ErrorCode.DUPLICATE_SUBMISSION: (409, "This request was already submitted."),
    ErrorCode.RATE_LIMITED: (429, "Too many requests. Try again later."),
    ErrorCode.INTERNAL_ERROR: (500, "An internal error occurred."),
    ErrorCode.SERVICE_UNAVAILABLE: (503, "The service is temporarily unavailable."),
    ErrorCode.REQUEST_FAILED: (400, "The request could not be completed."),
    ErrorCode.AUTH_REQUIRED: (401, "Authentication is required."),
    ErrorCode.AUTH_INVALID_CREDENTIALS: (401, "Invalid username or password."),
    ErrorCode.AUTH_SESSION_EXPIRED: (401, "Your session has expired. Please sign in again."),
    ErrorCode.AUTH_ACCOUNT_DISABLED: (401, "Invalid username or password."),  # same text: no account probing
    ErrorCode.PERMISSION_DENIED: (403, "Access denied."),
    ErrorCode.CSRF_FAILED: (403, "Security token missing or invalid. Refresh and try again."),
    ErrorCode.CONFIRMATION_REQUIRED: (400, "This action requires explicit confirmation."),
    ErrorCode.ENROLL_TOKEN_INVALID: (401, "Enrollment rejected."),
    ErrorCode.ENROLL_TOKEN_EXPIRED: (401, "Enrollment rejected."),
    ErrorCode.ENROLL_TOKEN_USED: (401, "Enrollment rejected."),
    ErrorCode.ENROLL_KEY_INVALID: (400, "The public key is not a valid Ed25519 key."),
    ErrorCode.ENROLL_KEY_IN_USE: (409, "Enrollment rejected."),
    ErrorCode.ENROLL_PROOF_INVALID: (401, "Enrollment rejected."),
    ErrorCode.NODE_NAME_TAKEN: (409, "A node with this name already exists."),
    ErrorCode.NODE_UNKNOWN: (401, "Node authentication failed."),
    ErrorCode.NODE_REVOKED: (403, "Node access has been revoked."),
    ErrorCode.NODE_ALREADY_REVOKED: (409, "This node is already revoked."),
    ErrorCode.NODE_SIGNATURE_MISSING: (401, "Node authentication failed."),
    ErrorCode.NODE_SIGNATURE_INVALID: (401, "Node authentication failed."),
    ErrorCode.HEARTBEAT_STALE: (401, "Heartbeat rejected."),
    ErrorCode.HEARTBEAT_REPLAYED: (401, "Heartbeat rejected."),
    ErrorCode.HEARTBEAT_COUNTER_REGRESSED: (401, "Heartbeat rejected."),
    ErrorCode.RESULT_INTEGRITY_FAILED: (422, "Result integrity check failed."),
    ErrorCode.RESULT_NOT_ASSIGNED: (403, "Access denied."),
    ErrorCode.TASK_NOT_FOUND: (404, "The requested resource was not found."),
    ErrorCode.TASK_INVALID_STATE: (409, "The task cannot change to that state."),
    ErrorCode.NO_ELIGIBLE_NODE: (409, "No trusted node is currently available."),
    ErrorCode.POLICY_INVALID: (400, "The policy values are invalid."),
    ErrorCode.AUDIT_CHAIN_BROKEN: (500, "Audit log integrity check failed."),
    ErrorCode.EXPORT_FAILED: (500, "The report could not be generated."),
}


def error_body(code: str, message: str | None = None, request_id: str | None = None, details=None) -> dict:
    """Build the standard error envelope used by every endpoint."""
    _, default_message = ERROR_CATALOG.get(code, (400, "The request could not be completed."))
    body = {"code": code, "message": message or default_message, "request_id": request_id}
    if details:
        body["details"] = details
    return {"error": body}


class APIError(APIException):
    """
    Raise this from any view or service to return a stable error code.

        raise APIError(ErrorCode.NODE_REVOKED)

    Callers outside the API (e.g. the audit log) can read `.error_code`
    to record *why* a request failed, even when the client sees a generic message.
    """

    def __init__(self, code: str, message: str | None = None, details=None, status_code: int | None = None):
        if code not in ERROR_CATALOG:
            raise ValueError(f"Unknown error code {code!r}; add it to ERROR_CATALOG first")
        default_status, default_message = ERROR_CATALOG[code]
        self.status_code = status_code or default_status
        self.error_code = code
        self.message = message or default_message
        self.details = details
        super().__init__(detail=self.message, code=code)

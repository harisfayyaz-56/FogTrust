"""
Role-based permissions, enforced on the server for every endpoint.

CAPABILITIES is the single source of truth for "who may do what"
(docs/api-contract.md, section 3). Views declare the capability they need:

    from accounts.permissions import require

    class RevokeNodeView(APIView):
        permission_classes = [require("nodes.revoke")]

/auth/me/ returns the same list so the dashboard can hide buttons, but hiding
a button is never the protection: this module is.

A denied request returns 403 PERMISSION_DENIED with the generic message and is
written to the audit log as `access.denied` by core/exceptions.py.
"""

from functools import cache

from django.core.exceptions import ImproperlyConfigured
from rest_framework.permissions import BasePermission

from .models import Role

ALL_ROLES = frozenset({Role.ADMIN, Role.OPERATOR, Role.VIEWER})
OPERATORS = frozenset({Role.ADMIN, Role.OPERATOR})
ADMINS = frozenset({Role.ADMIN})

CAPABILITIES: dict[str, frozenset] = {
    # read-only views: every signed-in role
    "nodes.view": ALL_ROLES,
    "tasks.view": ALL_ROLES,
    "trust.view": ALL_ROLES,
    "decisions.view": ALL_ROLES,
    "policy.view": ALL_ROLES,
    # normal workflow: operators and admins
    "tasks.submit": OPERATORS,
    "tasks.cancel": OPERATORS,
    "results.view": OPERATORS,
    "reports.export": OPERATORS,
    # administration: admins only
    "tokens.manage": ADMINS,
    "nodes.revoke": ADMINS,
    "policy.change": ADMINS,
    "users.manage": ADMINS,
    "audit.view": ADMINS,
    "audit.verify": ADMINS,
}


def capabilities_for(role: str) -> list[str]:
    return sorted(name for name, roles in CAPABILITIES.items() if role in roles)


class RolePermission(BasePermission):
    """Allows active, signed-in users whose role is in `allowed_roles`."""

    allowed_roles: frozenset = frozenset()
    capability: str = ""

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and user.is_active
            and getattr(user, "role", None) in self.allowed_roles
        )


@cache
def require(capability: str) -> type[RolePermission]:
    """Return a permission class for one capability. Unknown names fail at import time."""
    if capability not in CAPABILITIES:
        raise ImproperlyConfigured(f"Unknown capability {capability!r}; add it to CAPABILITIES first")
    class_name = "Requires_" + capability.replace(".", "_")
    return type(class_name, (RolePermission,), {"allowed_roles": CAPABILITIES[capability], "capability": capability})

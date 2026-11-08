"""
Login rate limits (threat ID-1, credential guessing).

Two independent limits, both returning 429 RATE_LIMITED:
  * per client IP   ScopedRateThrottle with scope "login"         (default 5/min)
  * per username    LoginUsernameThrottle, scope "login_username" (default 20/hour)

The per-username limit stops an attacker who rotates IP addresses from guessing
one account's password. The username is hashed before it becomes a cache key.
"""

import hashlib
from collections.abc import Mapping

from rest_framework.throttling import SimpleRateThrottle


class LoginUsernameThrottle(SimpleRateThrottle):
    scope = "login_username"

    def get_cache_key(self, request, view):
        data = request.data
        username = data.get("username") if isinstance(data, Mapping) else None
        if not isinstance(username, str) or not username:
            return None  # nothing to key on; the per-IP limit still applies
        ident = hashlib.sha256(username.strip().lower().encode("utf-8")).hexdigest()
        return self.cache_format % {"scope": self.scope, "ident": ident}

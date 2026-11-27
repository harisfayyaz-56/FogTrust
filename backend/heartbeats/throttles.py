"""
Rate limits for the heartbeat endpoint (contract: 120 per minute per node).

Two buckets, because the endpoint has no session to identify a client by:
  * per (node id, IP): the contract's 120/min. Including the IP means a stranger who spams a victim's
    node id fills their own bucket, not the victim's.
  * per IP: a wide cap (default 1200/min) so spraying thousands of different random node ids
    cannot create a fresh bucket each time and escape the limit.
"""

import os
import uuid

from rest_framework.throttling import SimpleRateThrottle


def _canonical_node_id(request):
    raw = request.headers.get("X-Node-Id", "")
    try:
        return raw if str(uuid.UUID(raw)) == raw else None
    except ValueError:
        return None


class NodeHeartbeatThrottle(SimpleRateThrottle):
    scope = "heartbeat"
    rate = os.environ.get("HEARTBEAT_NODE_RATE", "120/min")

    def get_cache_key(self, request, view):
        node = _canonical_node_id(request) or "unidentified"
        return self.cache_format % {"scope": self.scope, "ident": f"{node}:{self.get_ident(request)}"}


class IPHeartbeatThrottle(SimpleRateThrottle):
    scope = "heartbeat_ip"
    rate = os.environ.get("HEARTBEAT_IP_RATE", "1200/min")

    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": self.get_ident(request)}
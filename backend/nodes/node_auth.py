"""
The bridge between the Node table and Member 2's signature engine.

    from nodes.node_auth import lookup_node
    result = verify_heartbeat(request.headers, request.method, request.get_full_path(),
                              raw_body, lookup_node, store, window_s=...)

lookup_node is the `NodeLookup` the engine expects: node id in, (public key, status) out,
or None for an unknown node. Reading the status from the database on every call is what
makes revocation immediate: the very next request from a revoked node gets NODE_REVOKED
(contract step 3), with no cache to go stale.
"""

from __future__ import annotations

import uuid

from fogtrust_crypto.node_auth import NodeInfo

from .models import Node


def lookup_node(node_id: str) -> NodeInfo | None:
    try:
        node_uuid = uuid.UUID(str(node_id))
    except ValueError:
        return None
    row = Node.objects.filter(pk=node_uuid).values_list("public_key", "status").first()
    return NodeInfo(public_key=row[0], status=row[1]) if row else None

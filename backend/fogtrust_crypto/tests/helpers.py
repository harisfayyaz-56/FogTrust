"""Shared test fixtures (not a test file)."""

import json
import uuid

from fogtrust_crypto.keys import generate_private_key, public_key_to_b64
from fogtrust_crypto.node_auth import NodeInfo, sign_request

HEARTBEAT_PATH = "/api/v1/node-api/heartbeat/"
NOW = 1_763_547_631.0  # a fixed "server time" so window tests are exact


class Node:
    """A fake enrolled node plus a lookup function over a small in-memory node table."""

    def __init__(self, status="active"):
        self.key = generate_private_key()
        self.id = str(uuid.uuid4())
        self.info = NodeInfo(public_key_to_b64(self.key.public_key()), status)

    def lookup(self, node_id):
        return self.info if node_id == self.id else None

    def heartbeat(self, counter=1, *, ts=None, nonce=None, load=0, key=None):
        """Return (headers, body) for a signed heartbeat."""
        body = json.dumps(
            {"counter": counter, "reported_load": load, "sent_at": "2026-11-19T10:20:31.000Z"},
            separators=(",", ":"),
        ).encode()
        headers = sign_request(
            key or self.key,
            self.id,
            "POST",
            HEARTBEAT_PATH,
            body,
            timestamp=int(NOW) if ts is None else ts,
            nonce=nonce,
        )
        return headers, body


def lookup_for(*nodes):
    table = {n.id: n.info for n in nodes}
    return table.get
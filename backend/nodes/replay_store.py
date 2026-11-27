"""
Database-backed replay store: the persistent implementation of fogtrust_crypto.replay.ReplayStore.

Why the database and not memory: replay protection that forgets everything when the server
restarts lets an attacker replay a captured request right after a restart (test T-final,
"recovery after restart"). Here a nonce, once accepted, stays refused until its window closes
no matter how many times the process restarts.

    store = DatabaseReplayStore()
    verify_heartbeat(headers, method, path, body, lookup_node, store, window_s=...)

Member 2's heartbeat endpoint uses `advance_counter` through the same object.
"""

from __future__ import annotations

import random
import time

from django.db import IntegrityError, transaction

from .models import Node, NodeNonce


class DatabaseReplayStore:
    PURGE_ONE_IN = 100  # expired nonces are cleared on roughly 1 in 100 inserts, so no cron job is needed

    def add_nonce(self, node_id: str, nonce: str, expires_at: int) -> bool:
        """True if the nonce was new. The UNIQUE constraint decides, so two copies cannot both pass."""
        if random.randrange(self.PURGE_ONE_IN) == 0:
            self.purge()
        try:
            with transaction.atomic():  # savepoint: a duplicate must not poison an outer transaction
                NodeNonce.objects.create(node_id=node_id, nonce=nonce, expires_at=int(expires_at))
        except IntegrityError:
            return False
        return True

    def advance_counter(self, node_id: str, counter: int) -> bool:
        """Set the node's last counter to `counter` only if it is greater (one conditional UPDATE)."""
        return Node.objects.filter(pk=node_id, last_counter__lt=counter).update(last_counter=counter) == 1

    def last_counter(self, node_id: str) -> int:
        return Node.objects.filter(pk=node_id).values_list("last_counter", flat=True).first() or 0

    def purge(self, now: float | None = None) -> int:
        """Delete nonces whose window has closed. Safe: a request that old is refused as stale first."""
        deleted, _ = NodeNonce.objects.filter(expires_at__lt=int(time.time() if now is None else now)).delete()
        return deleted

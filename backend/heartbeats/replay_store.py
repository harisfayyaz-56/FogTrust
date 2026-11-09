"""
The database version of the engine's ReplayStore (fogtrust_crypto.replay.ReplayStore).

Both operations decide and write in ONE statement, so there is no gap between "check" and "store"
for two simultaneous requests to slip through. State is in the database, so it survives a restart
(test_restart_recovery): a copy sent after the server comes back is still refused.
"""

from django.db import IntegrityError, transaction

from nodes.models import Node

from .models import UsedNonce


class DatabaseReplayStore:
    def add_nonce(self, node_id: str, nonce: str, expires_at: int) -> bool:
        try:
            with transaction.atomic():
                UsedNonce.objects.create(node_id=node_id, nonce=nonce, expires_at=expires_at)
        except IntegrityError:  # the unique (node, nonce) constraint: already used
            return False
        return True

    def advance_counter(self, node_id: str, counter: int) -> bool:
        # One conditional UPDATE: it only matches while the stored counter is still lower.
        return Node.objects.filter(pk=node_id, last_counter__lt=counter).update(last_counter=counter) == 1

    def last_counter(self, node_id: str) -> int:
        return Node.objects.filter(pk=node_id).values_list("last_counter", flat=True).first() or 0

    @staticmethod
    def purge(now: float) -> int:
        """Forget nonces whose window has closed. Safe: the timestamp check refuses them first."""
        deleted, _ = UsedNonce.objects.filter(expires_at__lt=int(now)).delete()
        return deleted
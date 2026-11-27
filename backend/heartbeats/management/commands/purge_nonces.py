"""python manage.py purge_nonces   (optional: the store also clears expired nonces on about 1 in 100 inserts)"""

import time

from django.core.management.base import BaseCommand

from nodes.replay_store import DatabaseReplayStore


class Command(BaseCommand):
    help = "Delete replay-defence nonces whose timestamp window has closed."

    def handle(self, *args, **options):
        deleted = DatabaseReplayStore().purge(time.time())
        self.stdout.write(f"Purged {deleted} expired nonce(s).")
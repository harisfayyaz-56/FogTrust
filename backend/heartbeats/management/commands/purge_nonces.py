"""python manage.py purge_nonces   (run every minute or so; harmless to run more often)"""

import time

from django.core.management.base import BaseCommand

from heartbeats.replay_store import DatabaseReplayStore


class Command(BaseCommand):
    help = "Delete replay-defence nonces whose timestamp window has closed."

    def handle(self, *args, **options):
        deleted = DatabaseReplayStore.purge(time.time())
        self.stdout.write(f"Purged {deleted} expired nonce(s).")
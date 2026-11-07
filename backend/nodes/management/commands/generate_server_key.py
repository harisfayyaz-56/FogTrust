"""
python manage.py generate_server_key [--out keys/server_x25519.key]

Creates the broker's long-term X25519 key for result encryption (FR-5), prints its PUBLIC key
and the line to add to .env. The private key file is created with mode 0600 and the command
refuses to overwrite an existing key: replacing it would make every stored result undecryptable.
"""

from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from fogtrust_crypto.keys import CryptoKeyError, generate_x25519_private_key, save_x25519_private_key, x25519_public_to_b64

DEFAULT_OUT = "keys/server_x25519.key"


class Command(BaseCommand):
    help = "Create the server's X25519 result-encryption key (refuses to overwrite)."
    requires_system_checks = []  # the checks complain about the very key this command creates

    def add_arguments(self, parser):
        parser.add_argument("--out", default=DEFAULT_OUT, help=f"key file (default {DEFAULT_OUT}, relative to backend/)")

    def handle(self, *args, **options):
        out = Path(options["out"])
        target = out if out.is_absolute() else settings.BASE_DIR / out
        key = generate_x25519_private_key()
        try:
            save_x25519_private_key(key, target)
        except CryptoKeyError as exc:
            raise CommandError(str(exc)) from None
        self.stdout.write(self.style.SUCCESS(f"Private key written to {target} (mode 0600, git-ignored)."))
        self.stdout.write(f"server_public_key: {x25519_public_to_b64(key.public_key())}")
        self.stdout.write("")
        self.stdout.write("Add this line to your .env, then restart the server:")
        self.stdout.write(f"FOGTRUST_RESULT_KEY_FILE={options['out']}")

"""
python manage.py create_enrollment_token --label "gateway in lab 2" [--minutes 15]

Issues a one-time enrollment token from the server's command line (same rules and the same
audit event as the admin endpoint; the actor is recorded as the management command).
The token is printed once and cannot be shown again. Use it with the node simulator:

    FOGTRUST_ENROLL_TOKEN=<token> python -m fogtrust_crypto.node_sim enroll --key-file keys/n1.key --name gateway-01
"""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from nodes.serializers import no_control_characters
from nodes.services import create_enrollment_token
from rest_framework import serializers


class Command(BaseCommand):
    help = "Create a one-time node enrollment token and print it once."

    def add_arguments(self, parser):
        parser.add_argument("--label", required=True, help="what the token is for (max 64 characters)")
        parser.add_argument("--minutes", type=int, default=settings.ENROLLMENT_TOKEN_DEFAULT_MINUTES)

    def handle(self, *args, **options):
        label = options["label"].strip()
        minutes = options["minutes"]
        try:
            if not 1 <= len(label) <= 64:
                raise serializers.ValidationError("label must be 1 to 64 characters")
            no_control_characters(label)
        except serializers.ValidationError as exc:
            raise CommandError(f"Invalid label: {exc.detail[0]}") from None
        if not 1 <= minutes <= settings.ENROLLMENT_TOKEN_MAX_MINUTES:
            raise CommandError(f"--minutes must be between 1 and {settings.ENROLLMENT_TOKEN_MAX_MINUTES}")

        token, raw_token = create_enrollment_token(label=label, expires_in_minutes=minutes)
        self.stderr.write(f"Token {token.id} for '{label}' expires {token.expires_at:%Y-%m-%d %H:%M:%S} UTC. Shown once.")
        self.stdout.write(raw_token)  # alone on stdout so scripts can capture it: TOKEN=$(python manage.py ...)

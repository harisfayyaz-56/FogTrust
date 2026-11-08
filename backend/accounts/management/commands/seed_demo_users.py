"""
python manage.py seed_demo_users

Creates one account per role for the demo and the tests: admin1, operator1, viewer1.
Passwords are random, printed once and never stored in plain text. Existing accounts are left
untouched (their password is NOT reset). Use only on your own local database.
"""

import secrets

from django.contrib.auth.password_validation import validate_password
from django.core.management.base import BaseCommand

from accounts.models import Role, User

DEMO_ACCOUNTS = (("admin1", Role.ADMIN), ("operator1", Role.OPERATOR), ("viewer1", Role.VIEWER))


class Command(BaseCommand):
    help = "Create demo admin1, operator1 and viewer1 accounts with random passwords."

    def handle(self, *args, **options):
        for username, role in DEMO_ACCOUNTS:
            if User.objects.filter(username=username).exists():
                self.stdout.write(f"{username:10} already exists, left unchanged")
                continue
            password = secrets.token_urlsafe(12)
            validate_password(password, user=User(username=username))
            User.objects.create_user(username=username, password=password, role=role)
            self.stdout.write(f"{username:10} role={role:8} password={password}")
        self.stdout.write(self.style.WARNING("Passwords are shown once. Do not reuse them anywhere."))

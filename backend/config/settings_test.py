"""
Settings used by pytest and CI.

Provides a throwaway secret key so tests run without a .env file,
then loads the normal settings. Never use this module to run the server.
"""

import os

os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-not-secret-" + "x" * 40)
os.environ.setdefault("DJANGO_DEBUG", "False")

from .settings import *  # noqa: E402,F403

DATABASES["default"]["NAME"] = ":memory:"  # noqa: F405

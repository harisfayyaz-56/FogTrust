"""
Django system checks (run by `manage.py check` and at every `runserver` start).

A missing key, or a configured path whose file does not exist yet, is a WARNING: the broker
can run without it (nodes just cannot send encrypted results, FR-5, until it exists), and an
ERROR here would block `manage.py generate_server_key`, the command that fixes it. A file that
EXISTS but cannot be used (garbage, or readable by other users) is an ERROR: that is a mistake
and silently ignoring it would hide it.
"""

from django.conf import settings
from django.core.checks import Error, Warning, register

from fogtrust_crypto.keys import CryptoKeyError

from .server_keys import key_path, load_server_private_key


@register()
def check_result_key(app_configs, **kwargs):
    if not settings.RESULT_KEY_FILE:
        return [
            Warning(
                "FOGTRUST_RESULT_KEY_FILE is not set: nodes cannot send encrypted results yet.",
                hint="Run `python manage.py generate_server_key`, then put the printed line in .env.",
                id="nodes.W001",
            )
        ]
    path = key_path()
    try:
        load_server_private_key()
    except FileNotFoundError:
        return [
            Warning(
                f"The result key file does not exist yet: {path}",
                hint="Run `python manage.py generate_server_key`.",
                id="nodes.W002",
            )
        ]
    except (CryptoKeyError, OSError) as exc:
        return [Error(f"The result key file cannot be used: {exc}", id="nodes.E002")]
    return []

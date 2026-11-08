"""
The broker's long-term X25519 key for result encryption (FR-5).

The PRIVATE key lives in a file readable only by its owner (FOGTRUST_RESULT_KEY_FILE,
git-ignored, created by `python manage.py generate_server_key`). It never appears in the
database, in logs or in any API response. Nodes receive only the PUBLIC half, in the
enrollment response as `server_public_key`, and encrypt every result to it.

Member 2's result view calls load_server_private_key() to decrypt.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from django.conf import settings

from fogtrust_crypto.keys import load_x25519_private_key, x25519_public_to_b64


def key_path() -> Path | None:
    """The configured key file, or None. A relative path is relative to backend/."""
    configured = settings.RESULT_KEY_FILE
    if not configured:
        return None
    path = Path(configured)
    return path if path.is_absolute() else settings.BASE_DIR / path


@lru_cache(maxsize=4)
def _load(path_text: str, mtime_ns: int) -> X25519PrivateKey:  # mtime in the key: a replaced file is re-read
    return load_x25519_private_key(path_text)


def load_server_private_key() -> X25519PrivateKey | None:
    """The server's private key, or None when no key file is configured. Raises CryptoKeyError if unusable."""
    path = key_path()
    if path is None:
        return None
    return _load(str(path), os.stat(path).st_mtime_ns)


def server_public_key_b64() -> str | None:
    """Base64 of the server's X25519 public key for the enrollment response, or None if not configured."""
    from fogtrust_crypto.keys import CryptoKeyError

    try:
        key = load_server_private_key()
    except (CryptoKeyError, OSError):
        return None  # reported loudly by the system check and by the failure being visible in the response
    return x25519_public_to_b64(key.public_key()) if key else None

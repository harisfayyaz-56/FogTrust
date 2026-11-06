"""
Ed25519 key handling and the enrollment proof of possession.

Formats (agreed in docs/data-model.md):
  - public key  : base64 of the raw 32-byte key (44 characters)
  - fingerprint : SHA-256 hex of the raw public key bytes
  - private key : base64 of the raw 32-byte seed, in a file readable only by its owner

The private key stays on the node. The server only ever sees public keys.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

ENROLL_DOMAIN = "fogtrust-enroll-v1"


class CryptoKeyError(ValueError):
    """A key or key file is malformed or unsafe. Messages never contain key material."""


def _raw_public(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def strict_b64(value: object, nbytes: int, what: str) -> bytes:
    """Decode base64 that must be exactly `nbytes` bytes, in canonical form (no stray bits, no whitespace)."""
    expected_chars = 4 * ((nbytes + 2) // 3)
    if not isinstance(value, str) or len(value) != expected_chars:
        raise CryptoKeyError(f"{what} must be {expected_chars} base64 characters")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise CryptoKeyError(f"{what} is not valid base64") from None
    if len(raw) != nbytes or base64.b64encode(raw).decode("ascii") != value:
        raise CryptoKeyError(f"{what} must be a canonical encoding of {nbytes} bytes")
    return raw


def _strict_b64_32(value: object, what: str) -> bytes:
    return strict_b64(value, 32, what)


def _write_secret_file(raw: bytes, path: str | os.PathLike) -> None:
    """Create a new file with mode 0600 holding base64(raw). Refuses to overwrite."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = base64.b64encode(raw).decode("ascii") + "\n"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise CryptoKeyError("key file already exists; refusing to overwrite") from None
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(data)


def _read_secret_file(path: str | os.PathLike, what: str) -> bytes:
    """Read a key file written by _write_secret_file. On POSIX, refuses a file others can read."""
    path = Path(path)
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        raise CryptoKeyError("key file not found") from None
    if os.name != "nt" and mode & 0o077:
        raise CryptoKeyError("key file permissions are too open (expected 0600)")
    return _strict_b64_32(path.read_text(encoding="ascii").strip(), what)


# ---------------------------------------------------------------- public keys


def public_key_to_b64(public_key: Ed25519PublicKey) -> str:
    return base64.b64encode(_raw_public(public_key)).decode("ascii")


def public_key_from_b64(value: str) -> Ed25519PublicKey:
    """Strictly parse a public key; raises CryptoKeyError on anything else."""
    raw = _strict_b64_32(value, "public key")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        raise CryptoKeyError("public key could not be loaded") from None


def public_key_fingerprint(public_key: Ed25519PublicKey | str) -> str:
    """SHA-256 hex of the raw public key. Accepts a key object or its base64 form."""
    if isinstance(public_key, str):
        public_key = public_key_from_b64(public_key)
    return hashlib.sha256(_raw_public(public_key)).hexdigest()


# --------------------------------------------------------------- private keys


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_of(private_key: Ed25519PrivateKey) -> Ed25519PublicKey:
    return private_key.public_key()


def save_private_key(private_key: Ed25519PrivateKey, path: str | os.PathLike) -> None:
    """
    Write the private key to a new file with mode 0600.

    Refuses to overwrite: replacing a key file would silently destroy a node's identity.
    On Windows the mode bits have no effect; protect the folder instead (see docs).
    """
    raw = private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    _write_secret_file(raw, path)


def load_private_key(path: str | os.PathLike) -> Ed25519PrivateKey:
    """Load a key written by save_private_key. On POSIX, refuses a file others can read."""
    return Ed25519PrivateKey.from_private_bytes(_read_secret_file(path, "private key"))


# ------------------------------------------- server result key (X25519, Week 3)
# The server holds one long-term X25519 key. Nodes encrypt each result to its public key.


def generate_x25519_private_key() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def x25519_public_to_b64(public_key: X25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def x25519_public_from_b64(value: str) -> X25519PublicKey:
    """Strictly parse an X25519 public key (44 base64 characters, 32 bytes)."""
    return X25519PublicKey.from_public_bytes(_strict_b64_32(value, "public key"))


def save_x25519_private_key(private_key: X25519PrivateKey, path: str | os.PathLike) -> None:
    raw = private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    _write_secret_file(raw, path)


def load_x25519_private_key(path: str | os.PathLike) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(_read_secret_file(path, "private key"))


# --------------------------------------------------------- enrollment proof


def _enroll_message(token: str, name: str, public_key_b64: str) -> bytes:
    for part in (token, name, public_key_b64):
        if not isinstance(part, str) or "\n" in part:
            raise ValueError("enrollment fields must be strings without newlines")
    return "\n".join([ENROLL_DOMAIN, token, name, public_key_b64]).encode("utf-8")


def sign_enrollment_proof(private_key: Ed25519PrivateKey, token: str, name: str) -> str:
    """Proof of possession: sign (domain, token, name, public key) with the private key."""
    public_b64 = public_key_to_b64(private_key.public_key())
    signature = private_key.sign(_enroll_message(token, name, public_b64))
    return base64.b64encode(signature).decode("ascii")


def verify_enrollment_proof(public_key_b64: str, token: str, name: str, proof_b64: str) -> bool:
    """
    True only if `proof_b64` was made by the private key matching `public_key_b64`
    over exactly this token and name. Never raises on bad input; returns False.
    Member 1's enrollment view should call this instead of reimplementing it.
    """
    try:
        public_key = public_key_from_b64(public_key_b64)
        signature = base64.b64decode(proof_b64, validate=True)
        if len(signature) != 64:
            return False
        public_key.verify(signature, _enroll_message(token, name, public_key_b64))
        return True
    except (CryptoKeyError, binascii.Error, ValueError, TypeError, InvalidSignature):
        return False
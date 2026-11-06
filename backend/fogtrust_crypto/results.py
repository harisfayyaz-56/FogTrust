"""
Encrypted results (FR-5, test T4).

Flow (decisions B1 to B3 are explained in docs/node-signing-spec.md section 8):

  node:    ephemeral X25519 key  --ECDH with the server's public key-->  shared secret
           HKDF-SHA256(shared secret, info = domain | ephemeral pub | server pub)  -->  32-byte key
           AES-256-GCM(key, random 12-byte nonce, plaintext, AAD = domain | node_id | task_id)
  sent as: POST /api/v1/node-api/tasks/{task_id}/result/   (a normal SIGNED node request)
           {"ephemeral_public_key": b64(32), "nonce": b64(12), "ciphertext": b64(ciphertext + 16-byte tag)}

There is no second signature on the envelope: the request signature already covers the body hash,
which contains the ciphertext. GCM adds the integrity check on the data itself and, through the
AAD, ties a ciphertext to one node and one task.

Field sizes match docs/data-model.md section 3.6 (TaskResult).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Mapping, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import codes
from .keys import CryptoKeyError, strict_b64, x25519_public_from_b64
from .node_auth import NodeLookup, verify_node_request
from .replay import DEFAULT_WINDOW_S, ReplayStore, check_freshness, check_nonce
from .result import Run, VerificationResult

RESULT_DOMAIN = b"fogtrust-result-v1"
ENVELOPE_FIELDS = frozenset({"ephemeral_public_key", "nonce", "ciphertext"})
TAG_BYTES = 16
MAX_CIPHERTEXT_B64 = 65536  # data-model: ciphertext is base64, max 64 KB
MAX_PLAINTEXT_BYTES = (MAX_CIPHERTEXT_B64 // 4) * 3 - TAG_BYTES
MAX_RESULT_BODY_BYTES = 66_000  # envelope JSON around a maximum-size ciphertext


@dataclass(frozen=True)
class DecryptionOutcome:
    result: VerificationResult
    plaintext: Optional[bytes] = field(default=None, repr=False)  # repr=False: never printed or logged by accident
    plaintext_sha256: Optional[str] = None  # store this instead of the plaintext where possible

    @property
    def accepted(self) -> bool:
        return self.result.accepted


# ------------------------------------------------------------------- crypto


def _aad(node_id: str, task_id: str) -> bytes:
    node_id, task_id = str(uuid.UUID(node_id)), str(uuid.UUID(task_id))
    return RESULT_DOMAIN + b"|" + node_id.encode("ascii") + b"|" + task_id.encode("ascii")


def _derive_key(shared_secret: bytes, ephemeral_raw: bytes, server_raw: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=RESULT_DOMAIN + b"|" + ephemeral_raw + server_raw,
    ).derive(shared_secret)


def _raw(public_key: X25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def encrypt_result(server_public_key_b64: str, node_id: str, task_id: str, plaintext: bytes) -> dict:
    """Node side. Returns the envelope dict to send as the JSON body. Raises ValueError/CryptoKeyError on bad input."""
    if not isinstance(plaintext, (bytes, bytearray)) or len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ValueError(f"plaintext must be bytes of at most {MAX_PLAINTEXT_BYTES} bytes")
    server_public = x25519_public_from_b64(server_public_key_b64)
    ephemeral = X25519PrivateKey.generate()  # a new key per result, so no key is ever reused
    key = _derive_key(ephemeral.exchange(server_public), _raw(ephemeral.public_key()), _raw(server_public))
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, bytes(plaintext), _aad(node_id, task_id))
    return {
        "ephemeral_public_key": base64.b64encode(_raw(ephemeral.public_key())).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def _decrypt(run: Run, server_private: X25519PrivateKey, node_id: str, task_id: str, envelope: object):
    """Shared decryption steps. Returns plaintext bytes, or None after recording a denial on `run`."""
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        run.rule("envelope_shape", False, "envelope must contain exactly ephemeral_public_key, nonce, ciphertext")
        return None, run.deny(codes.VALIDATION_ERROR, "The result envelope is invalid.")
    ciphertext_b64 = envelope["ciphertext"]
    if isinstance(ciphertext_b64, str) and len(ciphertext_b64) > MAX_CIPHERTEXT_B64:
        run.rule("envelope_size", False, f"ciphertext limit {MAX_CIPHERTEXT_B64} base64 characters")
        return None, run.deny(codes.PAYLOAD_TOO_LARGE, "The result is too large.")
    try:
        ephemeral_raw = strict_b64(envelope["ephemeral_public_key"], 32, "ephemeral key")
        nonce = strict_b64(envelope["nonce"], 12, "nonce")
        if not isinstance(ciphertext_b64, str):
            raise CryptoKeyError("ciphertext must be a string")
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
        if len(ciphertext) < TAG_BYTES:
            raise CryptoKeyError("ciphertext shorter than the authentication tag")
        shared = server_private.exchange(X25519PublicKey.from_public_bytes(ephemeral_raw))
        aad = _aad(node_id, task_id)
    except (CryptoKeyError, binascii.Error, ValueError):  # includes low-order ephemeral keys
        run.rule("envelope_fields_valid", False, "a field is malformed or the ephemeral key is unusable")
        return None, run.deny(codes.VALIDATION_ERROR, "The result envelope is invalid.")
    run.rule("envelope_fields_valid", True, "ephemeral key, nonce and ciphertext are well formed")
    key = _derive_key(shared, ephemeral_raw, _raw(server_private.public_key()))
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        run.rule("aes_gcm_tag", False, "authentication tag does not match (ciphertext, key or node/task binding changed)")
        return None, run.deny(codes.RESULT_INTEGRITY_FAILED, "The result failed its integrity check.")
    run.rule("aes_gcm_tag", True, "authentication tag verified")
    return plaintext, None


def decrypt_envelope(server_private: X25519PrivateKey, node_id: str, task_id: str, envelope: object) -> DecryptionOutcome:
    """Server side, without the request checks. Never raises on bad envelope input."""
    run = Run("result_decryptor")
    plaintext, denial = _decrypt(run, server_private, node_id, task_id, envelope)
    if denial:
        return DecryptionOutcome(denial)
    digest = hashlib.sha256(plaintext).hexdigest()
    return DecryptionOutcome(
        run.allow("Result decrypted and verified.", plaintext_bytes=len(plaintext), plaintext_sha256_prefix=digest[:8]),
        plaintext,
        digest,
    )


# --------------------------------------------------------- full request path


def verify_result_request(
    headers: Mapping[str, str],
    method: str,
    path: str,
    body: bytes,
    lookup: NodeLookup,
    store: ReplayStore,
    server_private: X25519PrivateKey,
    task_id: str,
    assigned_node_id: Optional[str],
    *,
    window_s: int = DEFAULT_WINDOW_S,
    now: Optional[float] = None,
) -> DecryptionOutcome:
    """
    Verify and decrypt one result submission.

    Order: size, signed-request steps 1 to 6 (so a replayed submission is refused before any key
    exchange), assigned-node check, JSON parse, decryption.
    `assigned_node_id` is Task.assigned_node (Member 3); None means the task is not assigned.
    Whether a result for this task was ALREADY stored is the caller's TASK_INVALID_STATE check.
    """
    now = time.time() if now is None else now
    thresholds = {"timestamp_window_s": window_s, "max_body_bytes": MAX_RESULT_BODY_BYTES}

    if len(body) > MAX_RESULT_BODY_BYTES:
        run = Run("result_verifier", thresholds)
        run.rule("body_size", False, f"limit {MAX_RESULT_BODY_BYTES} bytes")
        return DecryptionOutcome(run.deny(codes.PAYLOAD_TOO_LARGE, "The request body is too large."))

    base = verify_node_request(headers, method, path, body, lookup)
    if not base.accepted:
        return DecryptionOutcome(base)
    run = Run("result_verifier", thresholds, base)

    denial = check_freshness(run, now, window_s) or check_nonce(run, store, window_s)
    if denial:
        return DecryptionOutcome(denial)

    try:
        task_id = str(uuid.UUID(task_id))
    except (ValueError, AttributeError, TypeError):
        run.rule("task_assigned", False, "task id is not a valid UUID")
        return DecryptionOutcome(run.deny(codes.RESULT_NOT_ASSIGNED, "Access denied."))
    run.evidence["task_id"] = task_id
    if assigned_node_id is None or str(assigned_node_id) != run.node_id:
        run.rule("task_assigned", False, "this task is not assigned to the submitting node")
        return DecryptionOutcome(run.deny(codes.RESULT_NOT_ASSIGNED, "Access denied."))
    run.rule("task_assigned", True, "task is assigned to the submitting node")

    try:
        envelope = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        run.rule("body_json", False, "body is not valid JSON")
        return DecryptionOutcome(run.deny(codes.MALFORMED_REQUEST, "The request body could not be parsed."))

    plaintext, denial = _decrypt(run, server_private, run.node_id, task_id, envelope)
    if denial:
        return DecryptionOutcome(denial)
    digest = hashlib.sha256(plaintext).hexdigest()
    result = run.allow("Result decrypted and verified.", plaintext_bytes=len(plaintext), plaintext_sha256_prefix=digest[:8])
    return DecryptionOutcome(result, plaintext, digest)
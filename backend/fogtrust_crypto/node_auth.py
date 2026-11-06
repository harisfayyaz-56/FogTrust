"""
Signed node requests (api-contract.md section 2.2).

Every request an enrolled node makes carries four headers:

  X-Node-Id         node UUID received at enrollment
  X-Node-Timestamp  Unix time in seconds
  X-Node-Nonce      16 random bytes as 32 lowercase hex characters
  X-Node-Signature  base64 Ed25519 signature of the string below

  string_to_sign = METHOD "\n" PATH "\n" TIMESTAMP "\n" NONCE "\n" hex(SHA-256(body))

The body is covered by its hash, so the node signs the exact bytes it sends and
the server hashes the exact bytes it received. Nothing is re-serialised, which
removes the "same JSON, different bytes" problem.

PATH is the request target as sent: the path plus "?query" when there is one
(Django: request.get_full_path()). Signing it stops an attacker changing the
query string of a signed request.

Replay checks (timestamp window, nonce, counter) are the next step in the
check order and are added in Week 3. They use the `timestamp` and `nonce`
that a successful verification returns.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import codes
from .keys import CryptoKeyError, public_key_fingerprint, public_key_from_b64
from .result import VerificationResult

HEADER_NODE_ID = "X-Node-Id"
HEADER_TIMESTAMP = "X-Node-Timestamp"
HEADER_NONCE = "X-Node-Nonce"
HEADER_SIGNATURE = "X-Node-Signature"
REQUIRED_HEADERS = (HEADER_NODE_ID, HEADER_TIMESTAMP, HEADER_NONCE, HEADER_SIGNATURE)

_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_NONCE_RE = re.compile(r"[0-9a-f]{32}")
_TIMESTAMP_RE = re.compile(r"[0-9]{1,12}")
_PATH_RE = re.compile(r"/[\x21-\x7e]*")  # printable ASCII, no spaces or newlines


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_nonce() -> str:
    return secrets.token_hex(16)


def build_string_to_sign(method: str, path: str, timestamp: int, nonce: str, body: bytes) -> bytes:
    """
    Build the exact bytes that get signed. Raises ValueError for any input that could make
    the newline-separated fields ambiguous (so a field can never "contain" another one).
    """
    if method not in _METHODS:
        raise ValueError("unsupported method")
    if not isinstance(path, str) or not _PATH_RE.fullmatch(path):
        raise ValueError("invalid path")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or not 0 <= timestamp < 10**12:
        raise ValueError("invalid timestamp")
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
        raise ValueError("invalid nonce")
    if not isinstance(body, (bytes, bytearray)):
        raise ValueError("body must be bytes")
    return "\n".join([method, path, str(timestamp), nonce, sha256_hex(bytes(body))]).encode("ascii")


def sign_request(
    private_key: Ed25519PrivateKey,
    node_id: str,
    method: str,
    path: str,
    body: bytes = b"",
    *,
    timestamp: Optional[int] = None,
    nonce: Optional[str] = None,
) -> dict:
    """Return the four headers for a request. `timestamp` and `nonce` are injectable for tests."""
    node_id = str(uuid.UUID(node_id))
    timestamp = int(time.time()) if timestamp is None else timestamp
    nonce = generate_nonce() if nonce is None else nonce
    signature = private_key.sign(build_string_to_sign(method, path, timestamp, nonce, body))
    return {
        HEADER_NODE_ID: node_id,
        HEADER_TIMESTAMP: str(timestamp),
        HEADER_NONCE: nonce,
        HEADER_SIGNATURE: base64.b64encode(signature).decode("ascii"),
    }


@dataclass(frozen=True)
class NodeInfo:
    """What the verifier needs to know about a node. The API layer builds this from the Node row."""

    public_key: str  # base64 raw Ed25519 key, as stored
    status: str  # "active" or "revoked"


NodeLookup = Callable[[str], Optional[NodeInfo]]


def verify_node_request(
    headers: Mapping[str, str],
    method: str,
    path: str,
    body: bytes,
    lookup: NodeLookup,
) -> VerificationResult:
    """
    Run the contract's check order (steps 1 to 4) and return an explainable result.

      1. headers present        -> NODE_SIGNATURE_MISSING
      2. node exists            -> NODE_UNKNOWN
      3. node active            -> NODE_REVOKED   (checked BEFORE the signature, as the contract says)
      4. signature valid        -> NODE_SIGNATURE_INVALID

    Header names are matched case-insensitively. A malformed timestamp, nonce or signature
    is reported as NODE_SIGNATURE_INVALID at step 4. This function never raises on bad
    client input. Only `lookup` may raise (a server fault), and that is not caught here.
    """
    started = time.perf_counter()
    rules: list = []

    def finish(accepted, code, explanation, evidence=None, node_id=None, timestamp=None, nonce=None):
        return VerificationResult(
            accepted=accepted,
            reason_code=code,
            explanation=explanation,
            rules_fired=rules,
            evidence=evidence or {},
            node_id=node_id,
            timestamp=timestamp,
            nonce=nonce,
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
        )

    def rule(name, passed, detail):
        rules.append({"rule": name, "passed": passed, "detail": detail})

    lowered = {str(k).lower(): v for k, v in headers.items()}
    values = {name: lowered.get(name.lower()) for name in REQUIRED_HEADERS}
    missing = [name for name, v in values.items() if not isinstance(v, str) or not v]

    # 1. headers present
    if missing:
        rule("headers_present", False, "missing: " + ", ".join(missing))
        return finish(False, codes.NODE_SIGNATURE_MISSING, "Signed-request headers are missing.", {"missing": missing})
    rule("headers_present", True, "all four signed-request headers supplied")

    # 2. node exists
    try:
        node_id = str(uuid.UUID(values[HEADER_NODE_ID]))
    except ValueError:
        rule("node_known", False, "node id is not a valid UUID")
        return finish(False, codes.NODE_UNKNOWN, "The node is not enrolled.")
    node = lookup(node_id)
    if node is None:
        rule("node_known", False, "no enrolled node has this id")
        return finish(False, codes.NODE_UNKNOWN, "The node is not enrolled.", {"node_id": node_id}, node_id)
    rule("node_known", True, "node is enrolled")

    # 3. node active
    if node.status != "active":
        rule("node_active", False, "node status is not active")
        return finish(False, codes.NODE_REVOKED, "The node has been revoked.", {"node_id": node_id}, node_id)
    rule("node_active", True, "node status is active")

    # 4. signature valid
    raw_ts, nonce, raw_sig = values[HEADER_TIMESTAMP], values[HEADER_NONCE], values[HEADER_SIGNATURE]
    evidence = {"node_id": node_id}

    def invalid(detail, explanation="The request signature could not be verified."):
        rule("signature_valid", False, detail)
        return finish(False, codes.NODE_SIGNATURE_INVALID, explanation, evidence, node_id)

    if not _TIMESTAMP_RE.fullmatch(raw_ts) or not _NONCE_RE.fullmatch(nonce):
        return invalid("timestamp or nonce header is malformed", "A signed-request header is malformed.")
    try:
        signature = base64.b64decode(raw_sig, validate=True)
    except (binascii.Error, ValueError):
        return invalid("signature header is not valid base64", "A signed-request header is malformed.")
    if len(signature) != 64:
        return invalid("signature header is not 64 bytes", "A signed-request header is malformed.")
    timestamp = int(raw_ts)
    try:
        string_to_sign = build_string_to_sign(method, path, timestamp, nonce, body)
    except ValueError:
        return invalid("request line could not be canonicalised")
    try:
        public_key = public_key_from_b64(node.public_key)
        evidence["key_fingerprint_prefix"] = public_key_fingerprint(public_key)[:8]
    except CryptoKeyError:
        return invalid("the stored public key could not be loaded")
    try:
        public_key.verify(signature, string_to_sign)
    except InvalidSignature:
        return invalid("Ed25519 signature does not match this request")
    rule("signature_valid", True, "Ed25519 signature matches the registered key")

    evidence.update({"timestamp": timestamp, "nonce_prefix": nonce[:4], "body_sha256_prefix": sha256_hex(body)[:8]})
    return finish(True, codes.OK, "Signature verified with the node's registered key.", evidence, node_id, timestamp, nonce)
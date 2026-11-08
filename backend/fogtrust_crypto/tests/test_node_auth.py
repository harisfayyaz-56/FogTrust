import base64
import hashlib
import uuid

import pytest

from fogtrust_crypto import codes
from fogtrust_crypto.keys import generate_private_key, public_key_to_b64
from fogtrust_crypto.node_auth import (
    HEADER_NODE_ID,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    REQUIRED_HEADERS,
    NodeInfo,
    build_string_to_sign,
    generate_nonce,
    sign_request,
    verify_node_request,
)

PATH = "/api/v1/node-api/heartbeat/"
BODY = b'{"counter":1,"reported_load":0,"sent_at":"2026-11-19T10:20:31.000Z"}'
NONCE = "00112233445566778899aabbccddeeff"


class Node:
    """A tiny fake node table: one enrolled node, plus a lookup function."""

    def __init__(self, status="active"):
        self.key = generate_private_key()
        self.id = str(uuid.uuid4())
        self.info = NodeInfo(public_key_to_b64(self.key.public_key()), status)

    def lookup(self, node_id):
        return self.info if node_id == self.id else None

    def headers(self, **kw):
        return sign_request(self.key, self.id, "POST", PATH, BODY, **kw)


@pytest.fixture
def node():
    return Node()


def verify(node, headers, method="POST", path=PATH, body=BODY):
    return verify_node_request(headers, method, path, body, node.lookup)


# ------------------------------------------------------- string to sign


def test_string_to_sign_matches_the_contract_literally():
    expected = "\n".join(["POST", PATH, "1763547631", NONCE, hashlib.sha256(BODY).hexdigest()]).encode()
    assert build_string_to_sign("POST", PATH, 1763547631, NONCE, BODY) == expected


def test_empty_body_is_hashed_not_skipped():
    s = build_string_to_sign("GET", "/api/v1/node-api/tasks/next/", 1, NONCE, b"")
    assert s.endswith(hashlib.sha256(b"").hexdigest().encode())


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(method="post"),  # lower-case
        dict(method="TRACE"),
        dict(path="no-leading-slash"),
        dict(path="/a\nb"),  # newline would let a field "contain" another
        dict(path="/a b"),
        dict(path="/caf\u00e9"),
        dict(timestamp=-1),
        dict(timestamp=1.5),
        dict(timestamp=True),
        dict(timestamp=10**12),
        dict(nonce="short"),
        dict(nonce=NONCE.upper()),
        dict(nonce=NONCE + "\n"),
        dict(body="text"),
    ],
)
def test_string_to_sign_rejects_ambiguous_inputs(kwargs):
    args = dict(method="POST", path=PATH, timestamp=1, nonce=NONCE, body=BODY)
    args.update(kwargs)
    with pytest.raises(ValueError):
        build_string_to_sign(**args)


def test_nonces_are_32_hex_and_unique():
    a, b = generate_nonce(), generate_nonce()
    assert len(a) == 32 and int(a, 16) >= 0 and a != b


# ------------------------------------------------------------ happy path


def test_honest_request_is_accepted(node):
    result = verify(node, node.headers())
    assert result.accepted and result.reason_code == codes.OK
    assert result.node_id == node.id
    assert [r["rule"] for r in result.rules_fired] == ["headers_present", "node_known", "node_active", "signature_valid"]
    assert all(r["passed"] for r in result.rules_fired)


def test_header_names_are_case_insensitive(node):
    headers = {k.lower(): v for k, v in node.headers().items()}
    assert verify(node, headers).accepted


def test_accepted_result_exposes_timestamp_and_nonce_for_replay_checks(node):
    result = verify(node, node.headers(timestamp=1763547631, nonce=NONCE))
    assert (result.timestamp, result.nonce) == (1763547631, NONCE)


# --------------------------------------------- tampering (each field is signed)


def test_changed_body_is_rejected(node):
    result = verify(node, node.headers(), body=BODY.replace(b'"counter":1', b'"counter":9'))
    assert not result.accepted and result.reason_code == codes.NODE_SIGNATURE_INVALID


def test_changed_path_is_rejected(node):
    assert verify(node, node.headers(), path="/api/v1/node-api/tasks/next/").reason_code == codes.NODE_SIGNATURE_INVALID


def test_added_query_string_is_rejected(node):
    assert verify(node, node.headers(), path=PATH + "?admin=1").reason_code == codes.NODE_SIGNATURE_INVALID


def test_changed_method_is_rejected(node):
    assert verify(node, node.headers(), method="PUT").reason_code == codes.NODE_SIGNATURE_INVALID


def test_changed_timestamp_is_rejected(node):
    headers = node.headers(timestamp=1000)
    headers[HEADER_TIMESTAMP] = "1001"
    assert verify(node, headers).reason_code == codes.NODE_SIGNATURE_INVALID


def test_changed_nonce_is_rejected(node):
    headers = node.headers(nonce=NONCE)
    headers[HEADER_NONCE] = "f" * 32
    assert verify(node, headers).reason_code == codes.NODE_SIGNATURE_INVALID


def test_signature_from_another_key_is_rejected_spoofed_node_T1(node):
    attacker = generate_private_key()
    headers = sign_request(attacker, node.id, "POST", PATH, BODY)
    result = verify(node, headers)
    assert not result.accepted and result.reason_code == codes.NODE_SIGNATURE_INVALID
    assert result.rules_fired[-1] == {
        "rule": "signature_valid",
        "passed": False,
        "detail": "Ed25519 signature does not match this request",
    }


def test_flipping_any_signature_bit_is_rejected(node):
    headers = node.headers()
    sig = bytearray(base64.b64decode(headers[HEADER_SIGNATURE]))
    for index in (0, 31, 63):
        mutated = bytearray(sig)
        mutated[index] ^= 0x01
        h = dict(headers, **{HEADER_SIGNATURE: base64.b64encode(bytes(mutated)).decode()})
        assert verify(node, h).reason_code == codes.NODE_SIGNATURE_INVALID


# ----------------------------------------------------------- check order


@pytest.mark.parametrize("missing", REQUIRED_HEADERS)
def test_each_missing_header_is_reported(node, missing):
    headers = node.headers()
    del headers[missing]
    result = verify(node, headers)
    assert result.reason_code == codes.NODE_SIGNATURE_MISSING
    assert result.evidence["missing"] == [missing]


def test_empty_header_value_counts_as_missing(node):
    headers = node.headers()
    headers[HEADER_SIGNATURE] = ""
    assert verify(node, headers).reason_code == codes.NODE_SIGNATURE_MISSING


def test_no_headers_at_all(node):
    assert verify(node, {}).reason_code == codes.NODE_SIGNATURE_MISSING


def test_unknown_node(node):
    headers = sign_request(node.key, str(uuid.uuid4()), "POST", PATH, BODY)
    assert verify(node, headers).reason_code == codes.NODE_UNKNOWN


def test_node_id_that_is_not_a_uuid_is_unknown_and_not_echoed(node):
    headers = node.headers()
    headers[HEADER_NODE_ID] = "'; DROP TABLE nodes;--"
    result = verify(node, headers)
    assert result.reason_code == codes.NODE_UNKNOWN
    assert "DROP" not in str(result)


def test_revoked_node_is_rejected_before_the_signature_is_checked():
    revoked = Node(status="revoked")
    headers = revoked.headers()
    headers[HEADER_SIGNATURE] = base64.b64encode(b"x" * 64).decode()  # garbage on purpose
    result = verify(revoked, headers)
    assert result.reason_code == codes.NODE_REVOKED
    assert "signature_valid" not in [r["rule"] for r in result.rules_fired]


@pytest.mark.parametrize(
    "header,value",
    [
        (HEADER_TIMESTAMP, "abc"),
        (HEADER_TIMESTAMP, "-5"),
        (HEADER_TIMESTAMP, "9" * 13),
        (HEADER_NONCE, "zz" * 16),
        (HEADER_NONCE, "ab"),
        (HEADER_SIGNATURE, "not base64!!"),
        (HEADER_SIGNATURE, base64.b64encode(b"x" * 10).decode()),
    ],
)
def test_malformed_headers_fail_safely(node, header, value):
    headers = node.headers()
    headers[header] = value
    result = verify(node, headers)
    assert not result.accepted and result.reason_code == codes.NODE_SIGNATURE_INVALID


def test_unusable_stored_key_fails_safely_without_exception():
    broken = Node()
    broken.info = NodeInfo("not-a-key", "active")
    assert verify(broken, broken.headers()).reason_code == codes.NODE_SIGNATURE_INVALID


def test_bad_request_line_fails_safely(node):
    assert verify(node, node.headers(), path="no-slash").reason_code == codes.NODE_SIGNATURE_INVALID


# ------------------------------------------------------------ decisions


def test_decision_for_a_denial_has_the_shared_schema(node):
    decision = verify(node, node.headers(), body=b"{}").to_decision("heartbeat")
    assert decision["decision"] == "deny"
    assert decision["reason_code"] == codes.NODE_SIGNATURE_INVALID
    assert decision["subject_type"] == "heartbeat" and decision["subject_id"] == node.id
    for key in ("explanation", "rules_fired", "evidence", "engine_name", "engine_version", "thresholds", "latency_ms", "decided_at"):
        assert key in decision


def test_decision_for_an_accept_uses_ok(node):
    decision = verify(node, node.headers()).to_decision("heartbeat")
    assert decision["decision"] == "allow" and decision["reason_code"] == codes.OK


def test_decisions_never_contain_secrets_or_full_signature(node):
    headers = node.headers()
    result = verify(node, headers)
    text = repr(result.to_decision("heartbeat"))
    assert headers[HEADER_SIGNATURE] not in text
    assert node.info.public_key not in text
    assert BODY.decode() not in text


def test_latency_is_measured(node):
    assert verify(node, node.headers()).latency_ms >= 0

# --------------------------------- found by the fuzz test (test_fuzz.py): one request, one spelling


def test_uppercase_node_id_is_not_accepted_as_the_same_node(node):
    headers = node.headers()
    headers[HEADER_NODE_ID] = node.id.upper()
    assert verify(node, headers).reason_code == codes.NODE_UNKNOWN


@pytest.mark.parametrize("spelling", [lambda i: "{" + i + "}", lambda i: i.replace("-", ""), lambda i: "urn:uuid:" + i, lambda i: " " + i])
def test_other_uuid_spellings_are_not_accepted(node, spelling):
    headers = node.headers()
    headers[HEADER_NODE_ID] = spelling(node.id)
    assert verify(node, headers).reason_code == codes.NODE_UNKNOWN


def test_timestamp_with_leading_zeros_is_not_accepted(node):
    headers = node.headers(timestamp=1763547631)
    headers[HEADER_TIMESTAMP] = "0" + headers[HEADER_TIMESTAMP]
    assert verify(node, headers).reason_code == codes.NODE_SIGNATURE_INVALID


def test_signature_with_non_canonical_base64_is_not_accepted(node):
    """The last base64 character carries 4 unused bits. Changing them decodes to the same signature,
    so without a canonical check one signature would have 16 valid spellings."""
    headers = node.headers()
    sig = headers[HEADER_SIGNATURE]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = sig[-3]  # the character before the "=="
    variant = alphabet[alphabet.index(last) ^ 1]
    assert base64.b64decode(sig[:-3] + variant + "==") == base64.b64decode(sig)  # same bytes, different text
    headers[HEADER_SIGNATURE] = sig[:-3] + variant + "=="
    assert verify(node, headers).reason_code == codes.NODE_SIGNATURE_INVALID


@pytest.mark.parametrize("method", [{}, [], None, 5, b"POST"])
def test_non_string_method_raises_value_error_not_type_error(method):
    with pytest.raises(ValueError):
        build_string_to_sign(method, PATH, 1, NONCE, BODY)


# ------------------------------------------- refuse oversized bodies before reading them


@pytest.mark.parametrize(
    "declared,limit,too_large",
    [(None, 2048, False), ("", 2048, False), ("0", 2048, False), ("2048", 2048, False), ("2049", 2048, True),
     ("99999999999999999999", 2048, True), ("abc", 2048, True), ("-1", 2048, True), ("12 ", 2048, True), ("\u0663", 2048, True), (2048, 2048, True)],
)
def test_declared_length_check(declared, limit, too_large):
    from fogtrust_crypto.node_auth import declared_length_too_large

    assert declared_length_too_large(declared, limit) is too_large
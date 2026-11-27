"""
Sanitized sample data: the test-fixture layer (Member 2).

    cd backend
    python -m fogtrust_crypto.samples --write ../docs/sample-data     # (re)create heartbeats.json and results.json
    python -m fogtrust_crypto.samples --check ../docs/sample-data     # replay every case against the engine, PASS or FAIL

Every case is a complete, signed request (headers, body) with the outcome it must produce. The files contain ONLY public
material: node public key, server public key, headers, bodies, ciphertext. The keys behind them are derived inside this
module from public strings ("...TEST-ONLY"), so anyone can regenerate them and nobody should ever use them for anything real.
Cases are replayed in order against a fresh replay store (so case 2, "replay", really is a copy of case 1).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .heartbeat import verify_heartbeat
from .keys import public_key_to_b64, x25519_public_to_b64
from .node_auth import NodeInfo, sign_request
from .replay import InMemoryReplayStore
from .results import decrypt_envelope, encrypt_result, verify_result_request

NOW = 1_763_547_631  # fixed "server time" for every case
WINDOW_S = 30
HEARTBEAT_PATH = "/api/v1/node-api/heartbeat/"
PLAINTEXT = b'{"answer": 42}'


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"fogtrust-sample-{label}-TEST-ONLY".encode()).digest()


def _uuid(label: str) -> str:
    return str(uuid.UUID(bytes=_seed(label)[:16]))


def _nonce(label: str) -> str:
    return _seed("nonce-" + label)[:16].hex()


def world() -> dict:
    node_key = Ed25519PrivateKey.from_private_bytes(_seed("node-key"))
    return {
        "node_key": node_key,
        "attacker_key": Ed25519PrivateKey.from_private_bytes(_seed("attacker-key")),
        "server_key": X25519PrivateKey.from_private_bytes(_seed("server-key")),
        "node_id": _uuid("node-id"),
        "unknown_id": _uuid("unknown-node-id"),
        "task_id": _uuid("task-id"),
        "other_task_id": _uuid("other-task-id"),
    }


def _hb_body(counter, load=1, extra=None) -> str:
    doc = {"counter": counter, "reported_load": load, "sent_at": "2025-11-19T10:20:31Z"}
    doc.update(extra or {})
    return json.dumps(doc, separators=(",", ":"))


def _request(path, headers, body):
    return {"method": "POST", "path": path, "headers": headers, "body": body}


def build_heartbeats(w) -> dict:
    def signed(label, body, *, key=None, node_id=None, ts=NOW, nonce=None):
        headers = sign_request(key or w["node_key"], node_id or w["node_id"], "POST", HEARTBEAT_PATH, body.encode(), timestamp=ts, nonce=nonce or _nonce(label))
        return _request(HEARTBEAT_PATH, headers, body)

    first = signed("hb-1", _hb_body(1))
    tampered = signed("hb-tamper", _hb_body(2))
    tampered["body"] = tampered["body"].replace('"counter":2', '"counter":999')
    cases = [
        ("valid", "A normal heartbeat from the enrolled node.", first, True, "OK"),
        ("replay", "An exact copy of case 1, as an eavesdropper would resend it (T2).", dict(first), False, "HEARTBEAT_REPLAYED"),
        ("counter-not-increasing", "Validly signed with a fresh nonce, but the counter is not higher than the last accepted one.", signed("hb-regress", _hb_body(1)), False, "HEARTBEAT_COUNTER_REGRESSED"),
        ("wrong-key", "Signed with a key the broker never registered (T1, spoofed node).", signed("hb-spoof", _hb_body(2), key=w["attacker_key"]), False, "NODE_SIGNATURE_INVALID"),
        ("body-altered-after-signing", "The body was changed after it was signed.", tampered, False, "NODE_SIGNATURE_INVALID"),
        ("stale", "Timestamp an hour in the past.", signed("hb-stale", _hb_body(2), ts=NOW - 3600), False, "HEARTBEAT_STALE"),
        ("future", "Timestamp an hour in the future.", signed("hb-future", _hb_body(2), ts=NOW + 3600), False, "HEARTBEAT_STALE"),
        ("unknown-node", "A node id that was never enrolled.", signed("hb-unknown", _hb_body(2), node_id=w["unknown_id"]), False, "NODE_UNKNOWN"),
        ("no-signature-headers", "No signed-request headers at all.", _request(HEARTBEAT_PATH, {}, _hb_body(2)), False, "NODE_SIGNATURE_MISSING"),
        ("body-not-json", "Validly signed, but the body is not JSON.", signed("hb-json", "not json"), False, "MALFORMED_REQUEST"),
        ("unexpected-field", "Validly signed, but the body has a field that is not allowed.", signed("hb-extra", _hb_body(2, extra={"admin": True})), False, "VALIDATION_ERROR"),
        ("oversized", "A body over the 2 KB limit.", signed("hb-big", "x" * 2049), False, "PAYLOAD_TOO_LARGE"),
        ("revoked-node", "A validly signed heartbeat from a node an admin has revoked (T5).", signed("hb-revoked", _hb_body(2)), False, "NODE_REVOKED"),
        ("valid-again", "An honest heartbeat after all the attacks: the node recovers.", signed("hb-2", _hb_body(2)), True, "OK"),
    ]
    return {
        "description": "Signed heartbeat cases, replayed in order against a fresh replay store. TEST DATA ONLY.",
        "server_time": NOW,
        "timestamp_window_s": WINDOW_S,
        "node": {"id": w["node_id"], "public_key": public_key_to_b64(w["node_key"].public_key()), "status": "active"},
        "cases": [
            {"name": n, "description": d, "request": r, "expected": {"accepted": a, "reason_code": c}, **({"node_status": "revoked"} if n == "revoked-node" else {})}
            for n, d, r, a, c in cases
        ],
    }


def build_results(w) -> dict:
    server_pub = x25519_public_to_b64(w["server_key"].public_key())

    def submit(label, task_id, *, key=None, envelope=None, body=None, ts=NOW):
        path = f"/api/v1/node-api/tasks/{task_id}/result/"
        env = envelope or encrypt_result(server_pub, w["node_id"], task_id, PLAINTEXT)
        text = body if body is not None else json.dumps(env, separators=(",", ":"))
        headers = sign_request(key or w["node_key"], w["node_id"], "POST", path, text.encode(), timestamp=ts, nonce=_nonce(label))
        return _request(path, headers, text), env

    def flipped(env):
        import base64

        raw = bytearray(base64.b64decode(env["ciphertext"]))
        raw[0] ^= 1
        return {**env, "ciphertext": base64.b64encode(bytes(raw)).decode()}

    valid, valid_env = submit("res-1", w["task_id"])
    after_signing, env = submit("res-transit", w["task_id"])
    altered_text = after_signing["body"].replace(env["ciphertext"][:6], ("A" if env["ciphertext"][0] != "A" else "B") + env["ciphertext"][1:6], 1)
    after_signing["body"] = altered_text
    _, base_env = submit("res-base", w["task_id"])
    other = encrypt_result(server_pub, w["node_id"], w["other_task_id"], PLAINTEXT)
    cases = [
        ("valid", "A normal encrypted result for a task assigned to this node.", valid, True, "OK", "node"),
        ("replay", "An exact copy of case 1.", dict(valid), False, "HEARTBEAT_REPLAYED", "node"),
        ("ciphertext-altered-before-signing", "One ciphertext byte changed, then the node signs it: only AES-GCM can catch this (T4).", submit("res-t4", w["task_id"], envelope=flipped(base_env))[0], False, "RESULT_INTEGRITY_FAILED", "node"),
        ("ciphertext-altered-in-transit", "The ciphertext was changed after signing.", after_signing, False, "NODE_SIGNATURE_INVALID", "node"),
        ("ciphertext-for-another-task", "A ciphertext made for a different task.", submit("res-other", w["task_id"], envelope=other)[0], False, "RESULT_INTEGRITY_FAILED", "node"),
        ("task-assigned-elsewhere", "The task belongs to another node.", submit("res-owner", w["task_id"])[0], False, "RESULT_NOT_ASSIGNED", "other"),
        ("signed-with-wrong-key", "Signed with a key the broker never registered.", submit("res-spoof", w["task_id"], key=w["attacker_key"])[0], False, "NODE_SIGNATURE_INVALID", "node"),
        ("stale", "Timestamp an hour in the past.", submit("res-stale", w["task_id"], ts=NOW - 3600)[0], False, "HEARTBEAT_STALE", "node"),
        ("body-not-json", "Validly signed, but the body is not JSON.", submit("res-json", w["task_id"], body="not json")[0], False, "MALFORMED_REQUEST", "node"),
        ("envelope-missing-fields", "Validly signed JSON, but not an encrypted-result envelope.", submit("res-env", w["task_id"], body='{"ciphertext":"AAAA"}')[0], False, "VALIDATION_ERROR", "node"),
    ]
    return {
        "description": "Encrypted result cases, replayed in order against a fresh replay store. TEST DATA ONLY.",
        "server_time": NOW,
        "timestamp_window_s": WINDOW_S,
        "node": {"id": w["node_id"], "public_key": public_key_to_b64(w["node_key"].public_key()), "status": "active"},
        "server_public_key": server_pub,
        "task_id": w["task_id"],
        "plaintext_sha256": hashlib.sha256(PLAINTEXT).hexdigest(),
        "cases": [
            {"name": n, "description": d, "request": r, "expected": {"accepted": a, "reason_code": c}, "task_assigned_to": who}
            for n, d, r, a, c, who in cases
        ],
    }


# ------------------------------------------------------------------ checking


def evaluate_heartbeats(data: dict, w=None) -> list[tuple]:
    store = InMemoryReplayStore()
    node = data["node"]
    out = []
    for case in data["cases"]:
        info = NodeInfo(node["public_key"], case.get("node_status", node["status"]))
        lookup = lambda nid, info=info: info if nid == node["id"] else None  # noqa: E731
        req = case["request"]
        result = verify_heartbeat(req["headers"], req["method"], req["path"], req["body"].encode(), lookup, store, window_s=data["timestamp_window_s"], now=data["server_time"])
        exp = case["expected"]
        out.append((case["name"], exp["reason_code"], result.reason_code, result.accepted == exp["accepted"] and result.reason_code == exp["reason_code"]))
    return out


def evaluate_results(data: dict, w=None) -> list[tuple]:
    w = w or world()
    store = InMemoryReplayStore()
    node = data["node"]
    out = []
    for case in data["cases"]:
        info = NodeInfo(node["public_key"], node["status"])
        lookup = lambda nid, info=info: info if nid == node["id"] else None  # noqa: E731
        req = case["request"]
        assigned = node["id"] if case["task_assigned_to"] == "node" else _uuid("someone-else")
        outcome = verify_result_request(req["headers"], req["method"], req["path"], req["body"].encode(), lookup, store, w["server_key"], data["task_id"], assigned, window_s=data["timestamp_window_s"], now=data["server_time"])
        exp = case["expected"]
        ok = outcome.accepted == exp["accepted"] and outcome.result.reason_code == exp["reason_code"]
        if outcome.accepted:
            ok = ok and outcome.plaintext_sha256 == data["plaintext_sha256"]
        out.append((case["name"], exp["reason_code"], outcome.result.reason_code, ok))
    return out


def write(folder: Path) -> None:
    w = world()
    folder.mkdir(parents=True, exist_ok=True)
    for name, data in (("heartbeats.json", build_heartbeats(w)), ("results.json", build_results(w))):
        (folder / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {folder / name}")


def check(folder: Path) -> int:
    w = world()
    failed = 0
    for name, evaluate in (("heartbeats.json", evaluate_heartbeats), ("results.json", evaluate_results)):
        data = json.loads((folder / name).read_text(encoding="utf-8"))
        for case, expected, actual, ok in evaluate(data, w):
            print(f"{'PASS' if ok else 'FAIL'}  {name}  {case}: expected {expected}, got {actual}")
            failed += not ok
    return 1 if failed else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Sanitized sample data for the crypto slice")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", metavar="DIR")
    group.add_argument("--check", metavar="DIR")
    args = parser.parse_args(argv)
    if args.write:
        write(Path(args.write))
        return 0
    return check(Path(args.check))


if __name__ == "__main__":
    sys.exit(main())
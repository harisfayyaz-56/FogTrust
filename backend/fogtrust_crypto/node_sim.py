"""
Node simulator (Member 2). Run from the backend/ folder:

    python -m fogtrust_crypto.node_sim keygen    --key-file keys/gateway-03.key
    python -m fogtrust_crypto.node_sim enroll    --key-file keys/gateway-03.key --name gateway-03 --token <token>
    python -m fogtrust_crypto.node_sim heartbeat --key-file keys/gateway-03.key --count 5 --interval 2
    python -m fogtrust_crypto.node_sim heartbeat --key-file keys/gateway-03.key --dry-run
    python -m fogtrust_crypto.node_sim heartbeat --key-file keys/gateway-03.key --behaviour replayer --count 2
    python -m fogtrust_crypto.node_sim result    --key-file keys/gateway-03.key --task-id <uuid> --server-public-key <b64>
    python -m fogtrust_crypto.node_sim server-keygen --key-file keys/server_x25519.key

Stand-alone: it uses only the standard library plus fogtrust_crypto. The key file and
the state file (node id and heartbeat counter) are kept next to each other; the
`keys/` folder is git-ignored. Attacker behaviours (for the T1, T2 and T4 demos) are in BEHAVIOURS
and RESULT_BEHAVIOURS. They only ever send to the server you point them at: use them on your own
local broker.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

import base64

from .keys import (
    CryptoKeyError,
    generate_private_key,
    generate_x25519_private_key,
    load_private_key,
    public_key_fingerprint,
    public_key_to_b64,
    save_private_key,
    save_x25519_private_key,
    sign_enrollment_proof,
    x25519_public_to_b64,
)
from .node_auth import sign_request
from .results import encrypt_result

HEARTBEAT_PATH = "/api/v1/node-api/heartbeat/"
RESULT_PATH = "/api/v1/node-api/tasks/{task_id}/result/"
ENROLL_PATH = "/api/v1/nodes/enroll/"
DEFAULT_SERVER = "http://127.0.0.1:8000"


# --------------------------------------------------------------------- state


def default_state_path(key_file: str) -> Path:
    return Path(key_file).with_suffix(".state.json")


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"State file {path} not found. Run 'enroll' first.") from None


def save_state(path: Path, state: dict) -> None:
    """Atomic write, so a crash can never leave a half-written counter."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.replace(tmp, path)


# ----------------------------------------------------------------- behaviours


def _iso_now(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def honest_behaviour(private_key, node_id: str, counter: int, load: int, now: float, state=None):
    """A well-behaved node: fresh counter, fresh nonce, correct key, untouched body."""
    body = json.dumps(
        {"counter": counter, "reported_load": load, "sent_at": _iso_now(now)}, separators=(",", ":")
    ).encode("utf-8")
    headers = sign_request(private_key, node_id, "POST", HEARTBEAT_PATH, body, timestamp=int(now))
    return body, headers


def spoofer_behaviour(private_key, node_id, counter, load, now, state=None):
    """T1: claims a real node id but signs with a key the broker never registered."""
    return honest_behaviour(generate_private_key(), node_id, counter, load, now)


def tamperer_behaviour(private_key, node_id, counter, load, now, state=None):
    """Signs an honest heartbeat, then changes the body in transit (counter + 1000)."""
    body, headers = honest_behaviour(private_key, node_id, counter, load, now)
    return body.replace(b'"counter":%d' % counter, b'"counter":%d' % (counter + 1000), 1), headers


def drifting_behaviour(private_key, node_id, counter, load, now, state=None):
    """A node whose clock is an hour slow: everything it signs is stale."""
    return honest_behaviour(private_key, node_id, counter, load, now - 3600)


def regressor_behaviour(private_key, node_id, counter, load, now, state=None):
    """Always reports counter 1 with a fresh nonce: accepted once, then the counter 'goes backwards'."""
    return honest_behaviour(private_key, node_id, 1, load, now)


def replayer_behaviour(private_key, node_id, counter, load, now, state=None):
    """
    T2: the first call sends (and records) an honest heartbeat, like an eavesdropper capturing it.
    Every later call resends those exact bytes and headers.
    """
    captured = (state or {}).get("captured_heartbeat")
    if captured:
        return captured["body"].encode("utf-8"), captured["headers"]
    body, headers = honest_behaviour(private_key, node_id, counter, load, now)
    if state is not None:
        state["captured_heartbeat"] = {"body": body.decode("utf-8"), "headers": headers}
    return body, headers


BEHAVIOURS = {
    "honest": honest_behaviour,
    "spoofer": spoofer_behaviour,
    "tamperer": tamperer_behaviour,
    "drifting": drifting_behaviour,
    "regressor": regressor_behaviour,
    "replayer": replayer_behaviour,
}


def _flip_ciphertext_byte(envelope: dict) -> dict:
    raw = bytearray(base64.b64decode(envelope["ciphertext"]))
    raw[0] ^= 0x01
    return dict(envelope, ciphertext=base64.b64encode(bytes(raw)).decode("ascii"))


def build_result_request(private_key, node_id, task_id, plaintext, server_public_key, behaviour, now, state=None):
    """Return (path, body, headers) for a result submission. `behaviour` is a key of RESULT_BEHAVIOURS."""
    path = RESULT_PATH.format(task_id=task_id)
    if behaviour == "replay" and (state or {}).get("captured_result"):
        captured = state["captured_result"]
        return path, captured["body"].encode("utf-8"), captured["headers"]
    envelope = encrypt_result(server_public_key, node_id, task_id, plaintext)
    if behaviour == "tamper_ciphertext":  # altered BEFORE signing: a valid sender, a damaged result (T4)
        envelope = _flip_ciphertext_byte(envelope)
    body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    headers = sign_request(private_key, node_id, "POST", path, body, timestamp=int(now))
    if behaviour == "tamper_in_transit":  # altered AFTER signing
        body = json.dumps(_flip_ciphertext_byte(envelope), separators=(",", ":")).encode("utf-8")
    if behaviour == "replay" and state is not None:
        state["captured_result"] = {"body": body.decode("utf-8"), "headers": headers}
    return path, body, headers


RESULT_BEHAVIOURS = ("honest", "tamper_ciphertext", "tamper_in_transit", "replay")


# ----------------------------------------------------------------------- HTTP


def post(server: str, path: str, body: bytes, headers: dict, timeout: float = 5.0):
    """POST raw bytes. Returns (status, parsed JSON or {}). Raises URLError if unreachable."""
    request = urllib.request.Request(
        server.rstrip("/") + path,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, {}


def send_heartbeat(server, key_file, state_file=None, behaviour="honest", load=0, dry_run=False):
    """Build, sign and (unless dry_run) send one heartbeat. Returns (status, payload) or (None, request-dict)."""
    state_path = Path(state_file) if state_file else default_state_path(key_file)
    state = load_state(state_path)
    private_key = load_private_key(key_file)
    counter = int(state.get("counter", 0)) + 1
    body, headers = BEHAVIOURS[behaviour](private_key, state["node_id"], counter, load, time.time(), state)
    if dry_run:
        return None, {"path": HEARTBEAT_PATH, "headers": headers, "body": body.decode("utf-8")}
    # Persist the counter BEFORE sending: if the send fails, the number is never reused.
    state["counter"] = counter
    save_state(state_path, state)
    return post(server, HEARTBEAT_PATH, body, headers)


def send_result(server, key_file, task_id, plaintext, server_public_key, state_file=None, behaviour="honest", dry_run=False):
    """Encrypt, sign and (unless dry_run) send one result. Returns (status, payload) or (None, request-dict)."""
    state_path = Path(state_file) if state_file else default_state_path(key_file)
    state = load_state(state_path)
    private_key = load_private_key(key_file)
    path, body, headers = build_result_request(
        private_key, state["node_id"], task_id, plaintext, server_public_key, behaviour, time.time(), state
    )
    if dry_run:
        return None, {"path": path, "headers": headers, "body": body.decode("utf-8")}
    save_state(state_path, state)  # keeps a captured request for the replay behaviour
    return post(server, path, body, headers)


# ------------------------------------------------------------------- commands


def cmd_keygen(args) -> int:
    key = generate_private_key()
    save_private_key(key, args.key_file)
    print(f"Private key written to {args.key_file} (keep it secret; never commit it).")
    print(f"public_key : {public_key_to_b64(key.public_key())}")
    print(f"fingerprint: {public_key_fingerprint(key.public_key())}")
    return 0


def cmd_enroll(args) -> int:
    token = args.token or os.environ.get("FOGTRUST_ENROLL_TOKEN")
    if not token:
        print("Provide --token or set FOGTRUST_ENROLL_TOKEN (the env var keeps it out of shell history).")
        return 2
    key = load_private_key(args.key_file)
    body = json.dumps(
        {
            "enrollment_token": token,
            "name": args.name,
            "public_key": public_key_to_b64(key.public_key()),
            "capacity": args.capacity,
            "proof": sign_enrollment_proof(key, token, args.name),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    status, payload = post(args.server, ENROLL_PATH, body, {})
    if status != 201:
        print(f"Enrollment failed: HTTP {status} {payload.get('error', {}).get('code', '')}")
        return 1
    state_path = Path(args.state_file) if args.state_file else default_state_path(args.key_file)
    save_state(state_path, {"node_id": str(uuid.UUID(payload["node_id"])), "name": args.name, "counter": 0})
    print(f"Enrolled as {payload['node_id']}. State saved to {state_path}.")
    return 0


def cmd_heartbeat(args) -> int:
    for i in range(args.count):
        try:
            status, payload = send_heartbeat(
                args.server, args.key_file, args.state_file, args.behaviour, args.load, args.dry_run
            )
        except urllib.error.URLError as error:
            print(f"Server unreachable: {error.reason}")
            return 2
        if args.dry_run:
            print(json.dumps(payload, indent=2))
        else:
            code = payload.get("error", {}).get("code", "OK" if payload.get("accepted") else "")
            print(f"[{i + 1}/{args.count}] HTTP {status} {code}")
        if i + 1 < args.count:
            time.sleep(args.interval)
    return 0


def cmd_server_keygen(args) -> int:
    key = generate_x25519_private_key()
    save_x25519_private_key(key, args.key_file)
    print(f"Server result key written to {args.key_file} (keep it secret; never commit it).")
    print(f"server_public_key: {x25519_public_to_b64(key.public_key())}")
    return 0


def cmd_result(args) -> int:
    server_key = args.server_public_key or os.environ.get("FOGTRUST_SERVER_PUBLIC_KEY")
    if not server_key:
        print("Provide --server-public-key or set FOGTRUST_SERVER_PUBLIC_KEY.")
        return 2
    try:
        status, payload = send_result(
            args.server, args.key_file, args.task_id, args.payload.encode("utf-8"), server_key,
            args.state_file, args.behaviour, args.dry_run,
        )
    except urllib.error.URLError as error:
        print(f"Server unreachable: {error.reason}")
        return 2
    if args.dry_run:
        print(json.dumps(payload, indent=2))
    else:
        code = payload.get("error", {}).get("code", "OK" if payload.get("accepted") else "")
        print(f"HTTP {status} {code}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="node_sim", description="FogTrust edge node simulator")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="create a new Ed25519 identity")
    keygen.add_argument("--key-file", required=True)
    keygen.set_defaults(func=cmd_keygen)

    enroll = sub.add_parser("enroll", help="register this node with an enrollment token")
    enroll.add_argument("--key-file", required=True)
    enroll.add_argument("--state-file")
    enroll.add_argument("--name", required=True)
    enroll.add_argument("--token", help="or set FOGTRUST_ENROLL_TOKEN")
    enroll.add_argument("--capacity", type=int, default=4)
    enroll.add_argument("--server", default=DEFAULT_SERVER)
    enroll.set_defaults(func=cmd_enroll)

    heartbeat = sub.add_parser("heartbeat", help="send signed heartbeats")
    heartbeat.add_argument("--key-file", required=True)
    heartbeat.add_argument("--state-file")
    heartbeat.add_argument("--behaviour", choices=sorted(BEHAVIOURS), default="honest")
    heartbeat.add_argument("--load", type=int, default=0)
    heartbeat.add_argument("--count", type=int, default=1)
    heartbeat.add_argument("--interval", type=float, default=10.0)
    heartbeat.add_argument("--server", default=DEFAULT_SERVER)
    heartbeat.add_argument("--dry-run", action="store_true", help="print the signed request, send nothing")
    heartbeat.set_defaults(func=cmd_heartbeat)

    result = sub.add_parser("result", help="encrypt and send a task result")
    result.add_argument("--key-file", required=True)
    result.add_argument("--state-file")
    result.add_argument("--task-id", required=True)
    result.add_argument("--payload", default='{"answer":42}')
    result.add_argument("--server-public-key", help="or set FOGTRUST_SERVER_PUBLIC_KEY")
    result.add_argument("--behaviour", choices=RESULT_BEHAVIOURS, default="honest")
    result.add_argument("--server", default=DEFAULT_SERVER)
    result.add_argument("--dry-run", action="store_true", help="print the signed request, send nothing")
    result.set_defaults(func=cmd_result)

    server_keygen = sub.add_parser("server-keygen", help="dev helper: create the server's X25519 result key")
    server_keygen.add_argument("--key-file", required=True)
    server_keygen.set_defaults(func=cmd_server_keygen)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CryptoKeyError as error:
        print(f"Key error: {error}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
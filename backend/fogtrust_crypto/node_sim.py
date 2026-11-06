"""
Node simulator (Member 2). Run from the backend/ folder:

    python -m fogtrust_crypto.node_sim keygen    --key-file keys/gateway-03.key
    python -m fogtrust_crypto.node_sim enroll    --key-file keys/gateway-03.key --name gateway-03 --token <token>
    python -m fogtrust_crypto.node_sim heartbeat --key-file keys/gateway-03.key --count 5 --interval 2
    python -m fogtrust_crypto.node_sim heartbeat --key-file keys/gateway-03.key --dry-run

Stand-alone: it uses only the standard library plus fogtrust_crypto. The key file and
the state file (node id and heartbeat counter) are kept next to each other; the
`keys/` folder is git-ignored. Behaviours are in BEHAVIOURS so the spoofer, replayer,
tamperer and crasher can be added later without changing the command line.
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

from .keys import (
    CryptoKeyError,
    generate_private_key,
    load_private_key,
    public_key_fingerprint,
    public_key_to_b64,
    save_private_key,
    sign_enrollment_proof,
)
from .node_auth import sign_request

HEARTBEAT_PATH = "/api/v1/node-api/heartbeat/"
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


def honest_behaviour(private_key, node_id: str, counter: int, load: int, now: float):
    """A well-behaved node: fresh counter, fresh nonce, correct key, untouched body."""
    body = json.dumps(
        {"counter": counter, "reported_load": load, "sent_at": _iso_now(now)}, separators=(",", ":")
    ).encode("utf-8")
    headers = sign_request(private_key, node_id, "POST", HEARTBEAT_PATH, body, timestamp=int(now))
    return body, headers


BEHAVIOURS = {"honest": honest_behaviour}


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
    body, headers = BEHAVIOURS[behaviour](private_key, state["node_id"], counter, load, time.time())
    if dry_run:
        return None, {"path": HEARTBEAT_PATH, "headers": headers, "body": body.decode("utf-8")}
    # Persist the counter BEFORE sending: if the send fails, the number is never reused.
    state["counter"] = counter
    save_state(state_path, state)
    return post(server, HEARTBEAT_PATH, body, headers)


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
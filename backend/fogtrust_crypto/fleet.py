"""
A small fleet of simulated nodes (Member 2), for the T3 (failed worker) and T6 (load balancing) demos.

    cd backend
    python -m fogtrust_crypto.fleet --server http://127.0.0.1:8000 --tokens-file tokens.txt --duration 60

tokens.txt holds one enrollment token per line (create them as an admin; each works once). Every node gets its
own key, enrolls, and then sends signed heartbeats on its own thread. Profiles decide how each one behaves:

    honest    sends honest heartbeats with a changing load
    crasher   honest, then goes silent after --crash-after heartbeats (T3)
    spoofer   claims to be a real node but signs with another key (T1)
    replayer  resends its first heartbeat again and again (T2)
    drifting  clock an hour slow (every heartbeat stale)

Profiles are assigned in the order given by --profiles (default: honest, honest, honest, honest, crasher, replayer).
Use only against your own local broker.
"""

from __future__ import annotations

import argparse
import itertools
import json
import tempfile
import threading
import time
import urllib.error
from collections import Counter
from pathlib import Path

from . import node_sim
from .keys import generate_private_key, public_key_to_b64, save_private_key, sign_enrollment_proof

DEFAULT_PROFILES = ["honest", "honest", "honest", "honest", "crasher", "replayer"]
PROFILE_BEHAVIOUR = {"honest": "honest", "crasher": "crasher", "spoofer": "spoofer", "replayer": "replayer", "drifting": "drifting"}


def enroll_node(server: str, token: str, name: str, key_file: Path, capacity: int = 4) -> None:
    """Create a key and enroll it. Raises RuntimeError with the server's code if enrollment fails."""
    key = generate_private_key()
    save_private_key(key, key_file)
    body = json.dumps(
        {"enrollment_token": token, "name": name, "public_key": public_key_to_b64(key.public_key()),
         "capacity": capacity, "proof": sign_enrollment_proof(key, token, name)},
        separators=(",", ":"),
    ).encode("utf-8")
    status, payload = node_sim.post(server, node_sim.ENROLL_PATH, body, {})
    if status != 201:
        raise RuntimeError(f"{name}: enrollment failed, HTTP {status} {payload.get('error', {}).get('code', '')}")
    node_sim.save_state(
        node_sim.default_state_path(str(key_file)),
        {"node_id": payload["node_id"], "name": name, "counter": 0, "server_public_key": payload.get("server_public_key", "")},
    )


def run_node(server: str, key_file: Path, profile: str, name: str, duration: float, interval: float, crash_after: int, results: dict, stop: threading.Event) -> None:
    """One node's life: send heartbeats until the time is up. Records (HTTP status, code) per heartbeat in `results[name]`."""
    behaviour = PROFILE_BEHAVIOUR[profile]
    deadline = time.monotonic() + duration
    sent = 0
    outcomes = results.setdefault(name, [])
    while time.monotonic() < deadline and not stop.is_set():
        if profile == "crasher" and sent >= crash_after:
            outcomes.append(("silent", "CRASHED"))
            break
        try:
            load = (sent * 7 + len(name)) % 5  # a load that moves, so the load balancer has something to see
            status, payload = node_sim.send_heartbeat(server, str(key_file), behaviour=behaviour, load=load)
            outcomes.append((status, payload.get("error", {}).get("code", "OK" if payload.get("accepted") else "")))
        except urllib.error.URLError as error:
            outcomes.append(("error", str(error.reason)[:40]))
        sent += 1
        stop.wait(interval)


def summarise(results: dict, profiles: dict) -> str:
    lines = ["| Node | Profile | Heartbeats | Outcomes |", "|---|---|---|---|"]
    for name, outcomes in results.items():
        counts = Counter(f"{status} {code}".strip() for status, code in outcomes)
        lines.append(f"| {name} | {profiles[name]} | {len(outcomes)} | " + ", ".join(f"{k} x{v}" for k, v in counts.items()) + " |")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run a fleet of simulated FogTrust nodes")
    parser.add_argument("--server", default=node_sim.DEFAULT_SERVER)
    parser.add_argument("--tokens-file", required=True, help="one enrollment token per line")
    parser.add_argument("--profiles", nargs="+", default=DEFAULT_PROFILES, choices=sorted(PROFILE_BEHAVIOUR))
    parser.add_argument("--duration", type=float, default=30.0, help="seconds")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between heartbeats per node")
    parser.add_argument("--crash-after", type=int, default=3)
    parser.add_argument("--key-dir", help="where to keep keys (default: a temporary folder deleted at the end)")
    args = parser.parse_args(argv)

    tokens = [line.strip() for line in Path(args.tokens_file).read_text().splitlines() if line.strip()]
    if len(tokens) < len(args.profiles):
        print(f"Need {len(args.profiles)} tokens, found {len(tokens)}.")
        return 2

    holder = None if args.key_dir else tempfile.TemporaryDirectory(prefix="fogtrust-fleet-")
    key_dir = Path(args.key_dir or holder.name)
    results: dict = {}
    profiles: dict = {}
    stop = threading.Event()
    threads = []
    try:
        for i, (profile, token) in enumerate(zip(args.profiles, tokens), start=1):
            name = f"fleet-{i:02d}-{profile}"
            key_file = key_dir / f"{name}.key"
            enroll_node(args.server, token, name, key_file)
            profiles[name] = profile
            print(f"enrolled {name}")
        for name, profile in profiles.items():
            thread = threading.Thread(
                target=run_node,
                args=(args.server, key_dir / f"{name}.key", profile, name, args.duration, args.interval, args.crash_after, results, stop),
                daemon=True,
            )
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        stop.set()
    except (RuntimeError, urllib.error.URLError) as error:
        print(f"Stopped: {error}")
        return 2
    finally:
        if holder:
            holder.cleanup()
    print()
    print(summarise(results, profiles))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
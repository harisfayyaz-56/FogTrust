"""
The attack demo (Member 2): the T1, T2, T4 and T5-support steps against a RUNNING broker, with the exact result of each.

    cd backend
    set FOGTRUST_ENROLL_TOKEN=<one-time token>          (PowerShell: $env:FOGTRUST_ENROLL_TOKEN = "...")
    python -m fogtrust_crypto.demo --server http://127.0.0.1:8000
    python -m fogtrust_crypto.demo --server http://127.0.0.1:8000 --server-public-key <b64> --task-ids <t1> <t2> <t3> <t4> <t5>
    python -m fogtrust_crypto.demo --markdown ../docs/test-evidence/live-demo.md ...

It enrolls one demo node, runs each step, compares the real HTTP status and error code with what the
contract says it must be, and prints a PASS or FAIL table. Exit code 1 if any step differs. Use only on your own broker.
The result steps need FIVE tasks assigned to the demo node; they are skipped without --task-ids.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from . import node_sim
from .fleet import enroll_node

OK = (200, "OK")


def step_table(rows) -> str:
    lines = ["| # | Step | Expected | Actual | Result |", "|---|---|---|---|---|"]
    for i, (name, expected, actual, ok) in enumerate(rows, start=1):
        lines.append(f"| {i} | {name} | {expected[0]} {expected[1]} | {actual[0]} {actual[1]} | {'PASS' if ok else '**FAIL**'} |")
    return "\n".join(lines)


def heartbeat(server, key_file, behaviour):
    status, payload = node_sim.send_heartbeat(server, str(key_file), behaviour=behaviour)
    return status, payload.get("error", {}).get("code", "OK" if payload.get("accepted") else "")


def result(server, key_file, task_id, server_key, behaviour):
    status, payload = node_sim.send_result(server, str(key_file), task_id, b'{"answer":42}', server_key, behaviour=behaviour)
    return status, payload.get("error", {}).get("code", "OK" if payload.get("accepted") else "")


def run(server, key_file, server_key=None, task_ids=None):
    rows = []

    def check(name, expected, actual):
        rows.append((name, expected, actual, tuple(actual) == tuple(expected)))

    check("Honest heartbeat", OK, heartbeat(server, key_file, "honest"))
    check("Honest heartbeat (counter moves on)", OK, heartbeat(server, key_file, "honest"))
    check("T1: spoofed node (wrong key)", (401, "NODE_SIGNATURE_INVALID"), heartbeat(server, key_file, "spoofer"))
    check("Heartbeat body altered after signing", (401, "NODE_SIGNATURE_INVALID"), heartbeat(server, key_file, "tamperer"))
    check("T2: captured heartbeat, first delivery", OK, heartbeat(server, key_file, "replayer"))
    check("T2: the same bytes sent again", (401, "HEARTBEAT_REPLAYED"), heartbeat(server, key_file, "replayer"))
    check("Node clock an hour slow", (401, "HEARTBEAT_STALE"), heartbeat(server, key_file, "drifting"))
    check("Counter goes backwards (fresh nonce)", (401, "HEARTBEAT_COUNTER_REGRESSED"), heartbeat(server, key_file, "regressor"))
    check("Honest heartbeat after all the attacks", OK, heartbeat(server, key_file, "honest"))

    if server_key and task_ids and len(task_ids) >= 5:
        t_ok, t_tamper, t_transit, t_replay, t_repeat = task_ids[:5]
        check("Honest encrypted result", (201, "OK"), result(server, key_file, t_ok, server_key, "honest"))
        check("T4: ciphertext altered before signing", (422, "RESULT_INTEGRITY_FAILED"), result(server, key_file, t_tamper, server_key, "tamper_ciphertext"))
        check("T4: ciphertext altered in transit", (401, "NODE_SIGNATURE_INVALID"), result(server, key_file, t_transit, server_key, "tamper_in_transit"))
        check("Result, first delivery", (201, "OK"), result(server, key_file, t_replay, server_key, "replay"))
        check("Result, same bytes sent again", (401, "HEARTBEAT_REPLAYED"), result(server, key_file, t_replay, server_key, "replay"))
        check("Second result for a completed task", (409, "TASK_INVALID_STATE"), result(server, key_file, t_ok, server_key, "honest"))
    return rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run the FogTrust attack demo against a running broker")
    parser.add_argument("--server", default=node_sim.DEFAULT_SERVER)
    parser.add_argument("--token", help="or set FOGTRUST_ENROLL_TOKEN")
    parser.add_argument("--name", default="demo-node")
    parser.add_argument("--server-public-key", help="for the result steps (default: the one the server gave at enrollment)")
    parser.add_argument("--state-dir", help="keep the demo node here and reuse it on the next run (so tasks can be assigned to it in between)")
    parser.add_argument("--task-ids", nargs="*", help="five tasks assigned to the demo node, for the result steps")
    parser.add_argument("--markdown", help="also write the table to this file")
    args = parser.parse_args(argv)

    token = args.token or os.environ.get("FOGTRUST_ENROLL_TOKEN")
    if not token:
        print("Provide --token or set FOGTRUST_ENROLL_TOKEN.")
        return 2
    holder = None if args.state_dir else tempfile.TemporaryDirectory(prefix="fogtrust-demo-")
    folder = Path(args.state_dir or holder.name)
    key_file = folder / f"{args.name}.key"
    try:
        if not key_file.exists():
            enroll_node(args.server, token, args.name, key_file)
            print(f"Enrolled {args.name}; state kept in {folder}" if args.state_dir else f"Enrolled {args.name}")
        state_path = node_sim.default_state_path(str(key_file))
        state = node_sim.load_state(state_path)
        for stale in ("captured_heartbeat", "captured_result"):  # a replay demo must capture fresh bytes each run
            state.pop(stale, None)
        node_sim.save_state(state_path, state)
        server_key = args.server_public_key or state.get("server_public_key") or None
        rows = run(args.server, key_file, server_key, args.task_ids)
    except (RuntimeError, urllib.error.URLError) as error:
        print(f"Could not run the demo: {error}")
        return 2
    finally:
        if holder:
            holder.cleanup()
    table = step_table(rows)
    print(table)
    failed = [r for r in rows if not r[3]]
    print(f"\n{len(rows) - len(failed)} of {len(rows)} steps behaved as the contract says.")
    if args.markdown:
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        Path(args.markdown).write_text(f"# Live attack demo\n\nRun {stamp} against `{args.server}` with `python -m fogtrust_crypto.demo`.\n\n{table}\n", encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
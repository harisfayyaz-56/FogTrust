"""
Heartbeat latency against a RUNNING broker (the Django numbers for the report).

    cd backend
    set FOGTRUST_ENROLL_TOKEN=<one-time token>
    python -m fogtrust_crypto.bench_live --server http://127.0.0.1:8000 --count 300

Enrolls one node, sends --count honest heartbeats one after another, and prints median, 95th and 99th
percentile in milliseconds as seen by the client (signing is done before the clock starts). Numbers depend on the
machine and on the server (Django's development server is slow and single-threaded; say which you used).
"""

from __future__ import annotations

import argparse
import os
import platform
import statistics
import tempfile
import time
from pathlib import Path

from . import node_sim
from .fleet import enroll_node
from .node_auth import sign_request


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Heartbeat latency against a running broker")
    parser.add_argument("--server", default=node_sim.DEFAULT_SERVER)
    parser.add_argument("--token")
    parser.add_argument("--count", type=int, default=300)
    args = parser.parse_args(argv)
    token = args.token or os.environ.get("FOGTRUST_ENROLL_TOKEN")
    if not token:
        print("Provide --token or set FOGTRUST_ENROLL_TOKEN.")
        return 2
    with tempfile.TemporaryDirectory(prefix="fogtrust-bench-") as folder:
        key_file = Path(folder) / "bench.key"
        enroll_node(args.server, token, "bench-node", key_file)
        state = node_sim.load_state(node_sim.default_state_path(str(key_file)))
        key = node_sim.load_private_key(str(key_file))
        samples, failures = [], 0
        for counter in range(1, args.count + 1):
            body = node_sim.honest_behaviour(key, state["node_id"], counter, counter % 5, time.time())  # signed with the current time
            started = time.perf_counter()
            status, _ = node_sim.post(args.server, node_sim.HEARTBEAT_PATH, *body)
            samples.append((time.perf_counter() - started) * 1000)
            failures += status != 200
    s = sorted(samples)
    pct = lambda p: s[min(len(s) - 1, int(len(s) * p))]
    print(f"{args.count} heartbeats to {args.server} on {platform.system()} {platform.machine()}, Python {platform.python_version()}")
    print(f"failures: {failures}")
    print(f"median {statistics.median(s):.2f} ms | 95th {pct(0.95):.2f} ms | 99th {pct(0.99):.2f} ms | max {s[-1]:.2f} ms")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
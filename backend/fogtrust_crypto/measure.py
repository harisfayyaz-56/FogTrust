"""
Repeatable measurements for the crypto slice (Part D, and the timing experiment C3).

    cd backend
    python -m fogtrust_crypto.measure --out ../docs/test-evidence/crypto-measurements.md
    python -m fogtrust_crypto.measure --quick          # small run, used by the automated test

Nothing here is typed in by hand: every number in the output comes from running the engine.
The random seed is fixed, so the COUNTS (false positives, false negatives, coverage) are identical on
every run. The TIMES depend on the machine, so the header records where the run happened. Re-run it on
your own laptop before putting numbers in the report.

Sections: D1 detection coverage and false positives/negatives, D2 latency (engine only and over HTTP
against the local stub broker), D3 clock drift and replay exposure, C3 timing of the early-exit paths.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import statistics
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import cryptography

from . import codes, node_sim
from .heartbeat import MAX_HEARTBEAT_BODY_BYTES, verify_heartbeat
from .keys import generate_private_key, generate_x25519_private_key, public_key_to_b64, x25519_public_to_b64
from .node_auth import NodeInfo, sign_request, verify_node_request
from .replay import InMemoryReplayStore
from .results import MAX_PLAINTEXT_BYTES, decrypt_envelope, encrypt_result, verify_result_request

SEED = 20261107
NOW = 1_763_547_631.0
HB_PATH = "/api/v1/node-api/heartbeat/"


class Node:
    def __init__(self, status="active"):
        self.key = generate_private_key()
        self.id = str(uuid.uuid4())
        self.info = NodeInfo(public_key_to_b64(self.key.public_key()), status)
        self.counter = 0


class World:
    """A small fleet, one shared replay store and one server key."""

    def __init__(self, nodes=5):
        self.nodes = [Node() for _ in range(nodes)]
        self.revoked = Node(status="revoked")
        self.table = {n.id: n.info for n in self.nodes + [self.revoked]}
        self.store = InMemoryReplayStore()
        self.server = generate_x25519_private_key()
        self.server_pub = x25519_public_to_b64(self.server.public_key())
        self.assignments = {}

    def lookup(self, node_id):
        return self.table.get(node_id)

    def hb(self, node, *, counter=None, ts=None, key=None, body=None, node_id=None, headers_only=False):
        if counter is None:
            node.counter += 1
            counter = node.counter
        body = body if body is not None else json.dumps(
            {"counter": counter, "reported_load": 1, "sent_at": "2026-11-19T10:20:31.000Z"}, separators=(",", ":")
        ).encode()
        headers = sign_request(key or node.key, node_id or node.id, "POST", HB_PATH, body, timestamp=int(NOW) if ts is None else ts)
        return headers, body

    def beat(self, headers, body, store=None):
        return verify_heartbeat(headers, "POST", HB_PATH, body, self.lookup, store or self.store, now=NOW)

    def task_for(self, node):
        task_id = str(uuid.uuid4())
        self.assignments[task_id] = node.id
        return task_id

    def result_request(self, node, task_id, *, plaintext=b'{"answer":42}', ts=None, key=None, envelope=None):
        path = f"/api/v1/node-api/tasks/{task_id}/result/"
        env = envelope or encrypt_result(self.server_pub, node.id, task_id, plaintext)
        body = json.dumps(env, separators=(",", ":")).encode()
        headers = sign_request(key or node.key, node.id, "POST", path, body, timestamp=int(NOW) if ts is None else ts)
        return path, headers, body, env

    def submit(self, path, headers, body, task_id, assigned="auto", store=None):
        assigned = self.assignments.get(task_id) if assigned == "auto" else assigned
        return verify_result_request(headers, "POST", path, body, self.lookup, store or self.store, self.server, task_id, assigned, now=NOW)


# ----------------------------------------------------------------- statistics


def pct(sorted_ms, p):
    return sorted_ms[min(len(sorted_ms) - 1, int(len(sorted_ms) * p))]


def stats(samples):
    s = sorted(samples)
    return {"n": len(s), "median": statistics.median(s), "p95": pct(s, 0.95), "p99": pct(s, 0.99), "max": s[-1]}


def ms(value):
    return f"{value:.3f}"


def table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


# --------------------------------------------------------------- D1: coverage


def run_d1(n_honest, n_attack, rng):
    world = World()
    rows_fp = []

    # --- false positives: honest traffic must always be accepted
    rejected = 0
    for i in range(n_honest):
        node = world.nodes[i % len(world.nodes)]
        headers, body = world.hb(node, ts=int(NOW) + rng.randint(-20, 20))
        rejected += not world.beat(headers, body).accepted
    rows_fp.append(("Honest heartbeats (5 nodes, clock error up to ±20 s, window 30 s)", n_honest, rejected))

    rejected = 0
    n_results = max(10, n_honest // 3)
    for i in range(n_results):
        node = world.nodes[i % len(world.nodes)]
        task = world.task_for(node)
        path, headers, body, _ = world.result_request(node, task, plaintext=bytes(rng.randrange(256) for _ in range(rng.choice([0, 33, 1024]))))
        rejected += not world.submit(path, headers, body, task).accepted
    rows_fp.append(("Honest encrypted results (0 B, 33 B or 1 KB)", n_results, rejected))

    # --- attacks: each must be rejected, with the expected reason
    other = Node().key  # the attacker's own key

    def replay_hb(i):
        node = world.nodes[i % 5]
        headers, body = world.hb(node)
        assert world.beat(headers, body).accepted
        return codes.HEARTBEAT_REPLAYED, world.beat(headers, body)

    def regress_hb(i):
        node = world.nodes[i % 5]
        headers, body = world.hb(node)
        assert world.beat(headers, body).accepted
        stale_counter = rng.randint(1, node.counter)
        return codes.HEARTBEAT_COUNTER_REGRESSED, world.beat(*world.hb(node, counter=stale_counter))

    def tamper_hb(i):
        node = world.nodes[i % 5]
        headers, body = world.hb(node)
        return codes.NODE_SIGNATURE_INVALID, world.beat(headers, body.replace(b'"reported_load":1', b'"reported_load":9'))

    def result_attack(kind):
        def run(i):
            node = world.nodes[i % 5]
            task = world.task_for(node)
            if kind == "tamper_before_signing":
                _, _, _, env = world.result_request(node, task)
                bad = node_sim._flip_ciphertext_byte(env)
                path, headers, body, _ = world.result_request(node, task, envelope=bad)
                return codes.RESULT_INTEGRITY_FAILED, world.submit(path, headers, body, task).result
            if kind == "tamper_in_transit":
                path, headers, body, env = world.result_request(node, task)
                altered = json.dumps(node_sim._flip_ciphertext_byte(env), separators=(",", ":")).encode()
                return codes.NODE_SIGNATURE_INVALID, world.submit(path, headers, altered, task).result
            if kind == "replay":
                path, headers, body, _ = world.result_request(node, task)
                assert world.submit(path, headers, body, task).accepted
                return codes.HEARTBEAT_REPLAYED, world.submit(path, headers, body, task).result
            if kind == "cross_task":
                other_task = world.task_for(node)
                env = encrypt_result(world.server_pub, node.id, other_task, b"{}")  # made for another task
                path, headers, body, _ = world.result_request(node, task, envelope=env)
                return codes.RESULT_INTEGRITY_FAILED, world.submit(path, headers, body, task).result
            if kind == "not_assigned":
                path, headers, body, _ = world.result_request(node, task)
                return codes.RESULT_NOT_ASSIGNED, world.submit(path, headers, body, task, assigned=str(uuid.uuid4())).result
            if kind == "spoofed":
                path, headers, body, _ = world.result_request(node, task, key=other)
                return codes.NODE_SIGNATURE_INVALID, world.submit(path, headers, body, task).result
            if kind == "stale":
                path, headers, body, _ = world.result_request(node, task, ts=int(NOW) - 3600)
                return codes.HEARTBEAT_STALE, world.submit(path, headers, body, task).result
        return run

    attacks = [
        ("T1 spoofed node: real id, attacker's key", lambda i: (codes.NODE_SIGNATURE_INVALID, world.beat(*world.hb(world.nodes[i % 5], key=other)))),
        ("Heartbeat body altered after signing", tamper_hb),
        ("T2 replayed heartbeat (exact copy)", replay_hb),
        ("Clock an hour slow (stale)", lambda i: (codes.HEARTBEAT_STALE, world.beat(*world.hb(world.nodes[i % 5], ts=int(NOW) - 3600)))),
        ("Clock an hour fast (future)", lambda i: (codes.HEARTBEAT_STALE, world.beat(*world.hb(world.nodes[i % 5], ts=int(NOW) + 3600)))),
        ("Counter equal or lower, fresh nonce", regress_hb),
        ("Unknown node id", lambda i: (codes.NODE_UNKNOWN, world.beat(*world.hb(Node())))),
        ("Revoked node (valid signature)", lambda i: (codes.NODE_REVOKED, world.beat(*world.hb(world.revoked)))),
        ("Signed body with an unexpected field", lambda i: (codes.VALIDATION_ERROR, world.beat(*world.hb(world.nodes[i % 5], body=b'{"counter":1,"reported_load":0,"sent_at":"2026-11-19T10:20:31Z","x":1}')))),
        ("Signed body that is not JSON", lambda i: (codes.MALFORMED_REQUEST, world.beat(*world.hb(world.nodes[i % 5], body=b"garbage")))),
        ("Oversized heartbeat body", lambda i: (codes.PAYLOAD_TOO_LARGE, world.beat({}, b"x" * (MAX_HEARTBEAT_BODY_BYTES + 1)))),
        ("No signed-request headers", lambda i: (codes.NODE_SIGNATURE_MISSING, world.beat({}, b"{}"))),
        ("T4 result altered before signing (GCM)", result_attack("tamper_before_signing")),
        ("T4 result altered in transit (signature)", result_attack("tamper_in_transit")),
        ("Replayed result submission", result_attack("replay")),
        ("Ciphertext made for another task", result_attack("cross_task")),
        ("Result for a task assigned to another node", result_attack("not_assigned")),
        ("Result signed with the attacker's key", result_attack("spoofed")),
        ("Stale result submission", result_attack("stale")),
    ]
    rows_attack = []
    for name, run in attacks:
        rejected = right_reason = accepted = 0
        for i in range(n_attack):
            expected, result = run(i)
            if result.accepted:
                accepted += 1
            else:
                rejected += 1
                right_reason += result.reason_code == expected
        rows_attack.append((name, n_attack, rejected, right_reason, accepted, f"{100 * rejected / n_attack:.1f}%"))
    return rows_fp, rows_attack


# ------------------------------------------------------------- D2: latency


def time_calls(calls):
    samples = []
    for call in calls:
        started = time.perf_counter()
        call()
        samples.append((time.perf_counter() - started) * 1000)
    return samples


def run_d2_engine(n):
    world = World(nodes=1)
    node = world.nodes[0]
    rows = []

    def add(label, calls):
        s = stats(time_calls(calls))
        rows.append((label, s["n"], ms(s["median"]), ms(s["p95"]), ms(s["p99"]), ms(s["max"])))

    reqs = [world.hb(node) for _ in range(n)]
    add("Heartbeat accepted (all 8 checks)", [lambda r=r: world.beat(*r) for r in reqs])
    replay = world.hb(node)
    world.beat(*replay)
    add("Heartbeat rejected: replay", [lambda: world.beat(*replay) for _ in range(n)])
    other = Node().key
    bad = [world.hb(node, key=other) for _ in range(n)]
    add("Heartbeat rejected: bad signature", [lambda r=r: world.beat(*r) for r in bad])
    stale = [world.hb(node, ts=int(NOW) - 3600) for _ in range(n)]
    add("Heartbeat rejected: stale", [lambda r=r: world.beat(*r) for r in stale])
    unknown = [world.hb(Node()) for _ in range(n)]
    add("Heartbeat rejected: unknown node", [lambda r=r: world.beat(*r) for r in unknown])
    for label, size in (("1 KB", 1024), ("maximum, 49,136 B", MAX_PLAINTEXT_BYTES)):
        task = world.task_for(node)
        envs = [encrypt_result(world.server_pub, node.id, task, b"x" * size) for _ in range(max(50, n // 4))]
        add(f"Result decryption only ({label})", [lambda e=e: decrypt_envelope(world.server, node.id, task, e) for e in envs])
        subs = []
        for _ in range(max(50, n // 4)):
            subs.append(world.result_request(node, task, plaintext=b"x" * size))
        add(f"Result submission accepted, full pipeline ({label})", [lambda s=s: world.submit(s[0], s[1], s[2], task) for s in subs])
    return rows


def run_d2_http(n):
    from .tests.stub_broker import StubBroker

    world = World(nodes=1)
    node = world.nodes[0]
    broker = StubBroker(world.server)
    broker.nodes = dict(world.table)
    task = world.task_for(node)
    broker.assignments = dict(world.assignments)
    rows = []
    try:
        # warm up the connection machinery
        for _ in range(5):
            body = json.dumps({"counter": 0, "reported_load": 0, "sent_at": "2026-11-19T10:20:31Z"}).encode()
            node_sim.post(broker.url, HB_PATH, body, {})

        def beat_calls():
            calls, counter = [], 0
            for _ in range(n):
                counter += 1
                body = json.dumps({"counter": counter, "reported_load": 1, "sent_at": "2026-11-19T10:20:31.000Z"}, separators=(",", ":")).encode()
                headers = sign_request(node.key, node.id, "POST", HB_PATH, body)  # real clock: the stub server uses it
                calls.append(lambda b=body, h=headers: node_sim.post(broker.url, HB_PATH, b, h))
            return calls

        def result_calls():
            calls = []
            for _ in range(n):
                path = f"/api/v1/node-api/tasks/{task}/result/"
                env = encrypt_result(world.server_pub, node.id, task, b"x" * 1024)
                body = json.dumps(env, separators=(",", ":")).encode()
                headers = sign_request(node.key, node.id, "POST", path, body)
                calls.append(lambda p=path, b=body, h=headers: node_sim.post(broker.url, p, b, h))
            return calls

        for label, calls in (("Heartbeat, sign-verify-respond over loopback HTTP", beat_calls()), ("Result (1 KB), over loopback HTTP", result_calls())):
            s = stats(time_calls(calls))
            rows.append((label, s["n"], ms(s["median"]), ms(s["p95"]), ms(s["p99"]), ms(s["max"])))
    finally:
        broker.close()
    return rows


# ------------------------------------------------------- C3: timing of exits


def run_c3(n_engine, n_http):
    from .tests.stub_broker import StubBroker

    world = World(nodes=1)
    node = world.nodes[0]
    attacker = Node().key
    classes = {
        "unknown node id": lambda: world.hb(Node()),
        "known node, wrong key": lambda: world.hb(node, key=attacker),
        "revoked node": lambda: world.hb(world.revoked),
    }
    # engine level: interleave so slow drift in the machine hits all three equally
    prepared = {name: [make() for _ in range(n_engine)] for name, make in classes.items()}
    samples = {name: [] for name in classes}
    for i in range(n_engine):
        for name in list(classes)[i % 3 :] + list(classes)[: i % 3]:
            headers, body = prepared[name][i]
            started = time.perf_counter()
            verify_node_request(headers, "POST", HB_PATH, body, world.lookup)
            samples[name].append((time.perf_counter() - started) * 1_000_000)  # microseconds
    engine_rows = []
    base = statistics.median(samples["known node, wrong key"])
    for name, values in samples.items():
        med = statistics.median(values)
        engine_rows.append((name, len(values), f"{med:.1f}", f"{sorted(values)[int(len(values) * .95)]:.1f}", f"{med - base:+.1f}"))

    # http level, same idea
    broker = StubBroker(world.server)
    broker.nodes = dict(world.table)
    samples = {name: [] for name in classes}
    try:
        for i in range(n_http):
            for name in list(classes)[i % 3 :] + list(classes)[: i % 3]:
                if name == "unknown node id":
                    node_ = Node()
                    body = b"{}"
                    headers = sign_request(node_.key, node_.id, "POST", HB_PATH, body)
                elif name == "revoked node":
                    body = b"{}"
                    headers = sign_request(world.revoked.key, world.revoked.id, "POST", HB_PATH, body)
                else:
                    body = b"{}"
                    headers = sign_request(attacker, node.id, "POST", HB_PATH, body)
                started = time.perf_counter()
                node_sim.post(broker.url, HB_PATH, body, headers)
                samples[name].append((time.perf_counter() - started) * 1_000_000)
    finally:
        broker.close()
    http_rows = []
    base = statistics.median(samples["known node, wrong key"])
    for name, values in samples.items():
        med = statistics.median(values)
        http_rows.append((name, len(values), f"{med:.0f}", f"{sorted(values)[int(len(values) * .95)]:.0f}", f"{med - base:+.0f}"))
    return engine_rows, http_rows


# ----------------------------------------------------------- D3: clock drift


def run_d3():
    windows = [5, 10, 30, 60]
    offsets = [-90, -60, -35, -31, -30, -10, -5, -1, 0, 1, 5, 10, 30, 31, 35, 60, 90]
    world = World(nodes=1)
    node = world.nodes[0]
    matrix = []
    for off in offsets:
        row = [f"{off:+d} s"]
        for w in windows:
            store = InMemoryReplayStore()
            headers, body = world.hb(node, ts=int(NOW) + off, counter=1)
            result = verify_heartbeat(headers, "POST", HB_PATH, body, world.lookup, store, window_s=w, now=NOW)
            row.append("accepted" if result.accepted else "REJECTED")
        matrix.append(row)

    exposure = []
    for w in windows:
        outcomes = []
        for delay in (1, w - 1, w, w + 1, w + 10):
            store = InMemoryReplayStore()
            headers, body = world.hb(node, ts=int(NOW), counter=1)
            assert verify_heartbeat(headers, "POST", HB_PATH, body, world.lookup, store, window_s=w, now=NOW).accepted
            copy = verify_heartbeat(headers, "POST", HB_PATH, body, world.lookup, store, window_s=w, now=NOW + delay)
            outcomes.append("ACCEPTED" if copy.accepted else copy.reason_code.replace("HEARTBEAT_", ""))
        exposure.append([f"{w} s"] + outcomes)

    growth = []
    for w in windows:
        store = InMemoryReplayStore()
        node_ids = [str(uuid.uuid4()) for _ in range(10)]
        peak = 0
        for tick in range(0, 600):  # 300 simulated seconds, one heartbeat per node every 0.5 s (120 per minute)
            now = tick * 0.5
            for nid in node_ids:
                store.add_nonce(nid, uuid.uuid4().hex, int(now) + w)
            store.purge(now)
            peak = max(peak, store.nonce_count())
        growth.append((f"{w} s", 10, "120/min each", peak, f"{peak / 10:.0f}"))
    return windows, matrix, exposure, growth


# --------------------------------------------------------------------- report


def build_report(quick: bool) -> tuple[str, dict]:
    rng = random.Random(SEED)
    n_honest, n_attack, n_lat, n_http, n_c3 = (150, 20, 100, 40, 300) if quick else (3000, 200, 2000, 300, 3000)
    started = time.time()
    fp, attacks = run_d1(n_honest, n_attack, rng)
    d2_engine = run_d2_engine(n_lat)
    d2_http = run_d2_http(n_http)
    c3_engine, c3_http = run_c3(n_c3, max(60, n_http))
    windows, matrix, exposure, growth = run_d3()

    total_attacks = sum(r[1] for r in attacks)
    summary = {
        "false_positives": sum(r[2] for r in fp),
        "honest_total": sum(r[1] for r in fp),
        "false_negatives": sum(r[4] for r in attacks),
        "attack_total": total_attacks,
        "wrong_reason": sum(r[2] - r[3] for r in attacks),
        "replay_accepted": sum(1 for row in exposure for cell in row[1:] if cell == "ACCEPTED"),
    }
    out = [
        "# Measurements: crypto slice (Member 2)",
        "",
        f"Generated by `python -m fogtrust_crypto.measure{' --quick' if quick else ''}`. Nothing in this file is typed by hand.",
        "",
        table(
            ["", ""],
            [
                ("Date (UTC)", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")),
                ("Machine", f"{platform.system()} {platform.release()}, {platform.machine()}"),
                ("Python / cryptography", f"{platform.python_version()} / {cryptography.__version__}"),
                ("Seed", SEED),
                ("Run time", f"{time.time() - started:.1f} s"),
            ],
        ),
        "",
        "Counts (D1, D3) are the same on every run. Times (D2, C3) depend on the machine; re-run on your own laptop before quoting them.",
        "",
        "## D1. False positives, false negatives, detection coverage",
        "",
        "**False positives** (honest request wrongly rejected):",
        "",
        table(["Honest traffic", "Requests", "Rejected (false positives)"], fp),
        "",
        "**Attacks.** Every attempt must be rejected, and for the reason named in the attack. 'Rejected with the expected reason code' counts the ones that were:",
        "",
        table(["Attack", "Attempts", "Rejected", "Rejected with the expected reason code", "Accepted (false negatives)", "Detection coverage"], attacks),
        "",
        f"**Totals:** {summary['false_positives']} false positives in {summary['honest_total']} honest requests; "
        f"{summary['false_negatives']} false negatives in {summary['attack_total']} attacks; "
        f"{summary['wrong_reason']} attacks rejected for a different reason than expected.",
        "",
        "Scope: these are the attack types listed above, not every possible attack. Coverage of 100 % here is not a claim of security in general.",
        "",
        "## D2. Decision latency",
        "",
        "**Engine only** (pure Python, in-memory store, requests prepared in advance, milliseconds):",
        "",
        table(["Operation", "Runs", "Median", "95th pct", "99th pct", "Max"], d2_engine),
        "",
        "**End to end over loopback HTTP** against the local stub broker (not Django; includes JSON handling and the HTTP client; milliseconds). Re-run after the Django endpoints exist.",
        "",
        table(["Operation", "Runs", "Median", "95th pct", "99th pct", "Max"], d2_http),
        "",
        "## D3. Clock drift and replay exposure",
        "",
        "An **honest** node whose clock is off by the amount shown, against each admin-set window (`timestamp_window_s`):",
        "",
        table(["Clock error"] + [f"window {w} s" for w in windows], matrix),
        "",
        "An **attacker** replays a captured, validly signed request this long after it was first accepted. The window must never let a copy through:",
        "",
        table(["Window", "after 1 s", "after window − 1 s", "after window", "after window + 1 s", "after window + 10 s"], exposure),
        "",
        "Replay attempts that were accepted: " + str(summary["replay_accepted"]) + ".",
        "",
        "Nonces the store must hold (10 nodes, each sending 120 heartbeats per minute, which is the throttle limit, purged every 0.5 s):",
        "",
        table(["Window", "Nodes", "Rate", "Peak nonces held", "Per node"], growth),
        "",
        "Reading: a bigger window forgives more clock error, but (1) a request that was blocked on the way and delivered late is still accepted for longer, and (2) the store holds more nonces. A copy of a request that already arrived is refused at every window size (second table).",
        "",
        "## C3. Do the early exits take a different time?",
        "",
        "The verifier stops at the first failed check, so an unknown node, a revoked node and a wrong key may take different amounts of time. Classes are interleaved so machine drift affects all equally. Difference is against the 'wrong key' class.",
        "",
        "Engine only (microseconds):",
        "",
        table(["Request", "Runs", "Median µs", "95th pct µs", "Difference vs wrong key (µs)"], c3_engine),
        "",
        "Over loopback HTTP (microseconds):",
        "",
        table(["Request", "Runs", "Median µs", "95th pct µs", "Difference vs wrong key (µs)"], c3_http),
        "",
    ]
    return "\n".join(out), summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Repeatable measurements for the crypto slice")
    parser.add_argument("--out", help="write the markdown report to this file")
    parser.add_argument("--quick", action="store_true", help="small run for the automated test")
    args = parser.parse_args(argv)
    report, summary = build_report(args.quick)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(report)
    print(json.dumps(summary), file=sys.stderr)
    return 1 if summary["false_positives"] or summary["false_negatives"] or summary["wrong_reason"] or summary["replay_accepted"] else 0


if __name__ == "__main__":
    sys.exit(main())
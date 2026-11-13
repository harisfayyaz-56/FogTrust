# Node Signing and Result Encryption Spec (Member 2)

| | |
|---|---|
| Version | 0.5 (Week 4) |
| Author | Member 2 |
| Implements | [api-contract.md](api-contract.md) sections 2.2, 5.5 and 5.7 (contract version 0.2), and the enrollment proof in 5.4 |
| Code | `backend/fogtrust_crypto/` (`keys.py`, `node_auth.py`, `replay.py`, `heartbeat.py`, `results.py`, `result.py`, `node_sim.py`) |

The contract holds the rules. This file explains how they are implemented, why, and how the API layer calls the code.

## 1. What is signed

```
string_to_sign = METHOD "\n" PATH "\n" TIMESTAMP "\n" NONCE "\n" hex(SHA-256(body))
```

| Part | Rule | Why |
|---|---|---|
| METHOD | Upper case: `GET POST PUT PATCH DELETE` | A signed POST cannot be replayed as another method |
| PATH | The request target as sent, **including `?query`** (`request.get_full_path()`) | An unsigned query string could be altered |
| TIMESTAMP | Integer Unix seconds, 0 to 10^12 | No floats, so both sides print the same digits |
| NONCE | Exactly 32 lowercase hex characters | One format, no case ambiguity |
| body | The **raw bytes** sent, hashed with SHA-256. An empty body is hashed too | The node signs what it sends; the server hashes what it received. No re-serialising |

A value containing a newline, a space or a non-ASCII character is refused before signing or verifying, so one field can never be read as part of another. The signature is Ed25519, base64 in `X-Node-Signature` (64 bytes decoded).

**One request, one spelling.** Python's parsers are forgiving: `uuid.UUID` accepts upper case, braces and no hyphens, `int` accepts leading zeros, and base64 decoding accepts different last characters that decode to the same bytes. Each of those would let one signed request appear as many different header strings. The verifier therefore accepts only the canonical form: a lower-case hyphenated node id, a decimal timestamp without leading zeros, and a canonical base64 signature. The fuzz test (`test_fuzz.py`) found the node-id case and a crash on a non-string method; the other two were fixed in the same change and each has its own test.

## 2. Check order

| Step | Check | Code | HTTP |
|---|---|---|---|
| pre | Body within the endpoint limit (heartbeat 2 KB, result 66,000 bytes) | `PAYLOAD_TOO_LARGE` | 413 |
| 1 | The four headers are present and non-empty | `NODE_SIGNATURE_MISSING` | 401 |
| 2 | Node id is a UUID of an enrolled node | `NODE_UNKNOWN` | 401 |
| 3 | Node status is `active` (before the signature) | `NODE_REVOKED` | 403 |
| 4 | Timestamp, nonce and signature well formed, and the signature verifies | `NODE_SIGNATURE_INVALID` | 401 |
| 5 | Timestamp within the window (`timestamp_window_s`, default 30) | `HEARTBEAT_STALE` | 401 |
| 6 | Nonce unused by this node (atomic add) | `HEARTBEAT_REPLAYED` | 409 |
| 7 | Heartbeat body has exactly `counter`, `reported_load`, `sent_at` with the right types | `MALFORMED_REQUEST` / `VALIDATION_ERROR` | 400 |
| 8 | Counter greater than the last accepted one (atomic advance) | `HEARTBEAT_COUNTER_REGRESSED` | 409 |

## 3. Why the replay checks are built this way (T2)

- **Signature before any state change.** Only an authenticated node can touch the nonce store or the counter. An anonymous attacker cannot fill the store (test `test_bad_signature_cannot_fill_the_nonce_store`).
- **Timestamp before nonce.** It needs no stored state, and it makes purging safe: anything older than the window is refused before the store is read, so a nonce is only remembered until `timestamp + window` (test `test_nonces_are_purged_only_after_their_window`).
- **Atomic store operations.** Check-then-store lets two copies of one request both pass. `add_nonce` and `advance_counter` decide and write in one step. Twenty simultaneous copies give exactly one accept (tests `test_identical_requests_sent_at_the_same_moment...`, `test_two_requests_with_the_same_counter...`).
- **Each check stops something the others do not.** The timestamp stops an old capture. The nonce stops a copy inside the window. The counter stops a validly signed request that reuses an old number, and still works after the nonce has been purged.
- **A rejected request never advances the counter.** The only leftover is a burned nonce on a request that fails step 7 or 8, which is harmless.
- **Gaps are allowed.** The counter only has to increase, so a node that crashes between saving the counter and sending does not lock itself out.

`ReplayStore` is an interface of three operations (`add_nonce`, `advance_counter`, `last_counter`). `InMemoryReplayStore` is the reference version. The database version for Member 1:

| Operation | Django |
|---|---|
| `add_nonce` | `Heartbeat.objects.create(...)` and treat `IntegrityError` on `unique (node, nonce)` as "already used" (a result submission needs a table or column for its nonce too) |
| `advance_counter` | `Node.objects.filter(id=..., last_counter__lt=n).update(last_counter=n) == 1` |
| purge | delete rows older than `timestamp + window` in a scheduled job |

An in-memory store loses its state on restart. The database store does not (T-final: recovery after restart).

## 4. Verification result

Every verifier returns a `VerificationResult`. `result.to_decision("heartbeat")` is a dict in the shared Decision schema ([data-model.md](data-model.md) section 4): `decision`, `reason_code`, `explanation`, `rules_fired` (every rule evaluated), `evidence`, `engine_name`, `engine_version`, `thresholds` (e.g. `timestamp_window_s`), `latency_ms`, `decided_at`. The caller adds `decision_id` and `request_id`.

`evidence` holds only non-secret values: node id, an 8-character key-fingerprint prefix, the timestamp, a 4-character nonce prefix, an 8-character body-hash prefix, and for a stale request the measured skew. Never keys, signatures, bodies or plaintext.

## 5. Calling it from the API layer (for Member 1 and Member 3)

Implemented in `backend/heartbeats/` (the view is `NodeHeartbeatView`). It does four things and no more: refuse an oversized body on `Content-Length` before reading it, read the raw bytes, call `verify_heartbeat`, and store what happened.

```python
raw_body = request.body                      # the exact signed bytes, read before anything parses them
window_s, interval_s, policy_version = current_policy()
result = verify_heartbeat(request.headers, request.method, request.get_full_path(), raw_body,
                          lookup_node, DatabaseReplayStore(), window_s=window_s)
# accepted -> Heartbeat row + Node.last_seen_at.   rejected -> Decision + audit event + rejected Heartbeat row
```

- `lookup_node` (Member 1, `nodes/node_auth.py`) builds the `NodeInfo` from the `Node` row.
- `nodes.replay_store.DatabaseReplayStore` (Member 1, shared by every signed node endpoint): the nonce is claimed by inserting into `NodeNonce` (unique `(node, nonce)`), the counter by one conditional `UPDATE`. State lives in the database, so it survives a restart. Expired nonces are cleared on about 1 in 100 inserts, and `purge_nonces` does it on demand. (Member 2 first wrote a second copy of this store in the heartbeats app; it was removed so that there is one nonce table.)
- Rejections are stored with `record_decision_dict(result.to_decision("heartbeat"))` and `log_event("heartbeat.rejected", ...)`; the Decision carries the rules fired, the window in `thresholds` and the policy version.
- Throttles (`heartbeats/throttles.py`): 120/min per (node id, client address) and 1200/min per client address.

Results are in `backend/results/` (`NodeResultView`, `ResultDetailView`). The view calls `verify_result_request(..., task_id, task.assigned_node_id, window_s=...)`, which returns a `DecryptionOutcome` (`.accepted`, `.result`, `.plaintext`, `.plaintext_sha256`), then makes the one decision only the database can: a conditional `UPDATE` completes the task if it is still `assigned`, so a task is completed once. Only the ciphertext and the SHA-256 are stored. The plaintext field is hidden from `repr` so it cannot be logged by accident, and `GET /tasks/{id}/result/` decrypts at read time, so a ciphertext edited in the database is caught when someone opens it.

For enrollment, `verify_enrollment_proof(public_key, token, name, proof)` is already called by `nodes/services.py`.

Member 3: the denials are your trust-score inputs. Read `reason_code` from the Decision; do not parse `explanation`.

## 6. Result encryption (FR-5, T4)

1. The server holds one long-term X25519 key. Its public key reaches the node in the enrollment response (proposal in the contract, 5.7).
2. For each result the node makes a new ephemeral X25519 key and runs ECDH with the server's public key.
3. HKDF-SHA256 derives a 32-byte key. The `info` input is `fogtrust-result-v1 | ephemeral public key | server public key`.
4. AES-256-GCM encrypts with a random 12-byte nonce. The associated data is `fogtrust-result-v1 | node_id | task_id`.
5. The node sends `{ephemeral_public_key, nonce, ciphertext}` as a normal signed request to `/node-api/tasks/{task_id}/result/`.

Field sizes match `data-model.md` section 3.6: 44-character key, 16-character nonce, ciphertext at most 65,536 base64 characters (so a plaintext of at most 49,136 bytes).

**Decision B2: no second signature on the envelope.** The request signature already covers the body hash, and the body contains the ciphertext, so a second signature would prove nothing new at submission time. GCM protects the data and binds it to one node and one task (moving a ciphertext to another task fails: `test_ciphertext_moved_to_another_task_is_detected`).
**What this does not cover:** AES-GCM does not say who encrypted, because anyone can encrypt to the server's public key. Someone who can write directly to the database could therefore store a forged result. Defending against that needs the node's signature stored with each result, which the data model does not have. It is listed in the limitations.

**Two ways a result can be altered, two different codes:**

| Where | What is caught | Code |
|---|---|---|
| In transit, after signing | Signature mismatch | `NODE_SIGNATURE_INVALID` |
| Before signing (damaged or tampered by the node's own side) or at rest | GCM tag mismatch | `RESULT_INTEGRITY_FAILED` |

## 7. Running the node simulator

From `backend/`:

```bash
python -m fogtrust_crypto.node_sim keygen    --key-file keys/gateway-03.key
python -m fogtrust_crypto.node_sim enroll    --key-file keys/gateway-03.key --name gateway-03   # token from FOGTRUST_ENROLL_TOKEN
python -m fogtrust_crypto.node_sim heartbeat --key-file keys/gateway-03.key --count 5 --interval 2
python -m fogtrust_crypto.node_sim heartbeat --key-file keys/gateway-03.key --dry-run
python -m fogtrust_crypto.node_sim server-keygen --key-file keys/server_x25519.key              # dev helper
python -m fogtrust_crypto.node_sim result    --key-file keys/gateway-03.key --task-id <uuid> --server-public-key <b64>
```

Attacker behaviours (use only on your own local broker):

| `heartbeat --behaviour` | Demonstrates | Expected code |
|---|---|---|
| `honest` | Normal node | accepted |
| `spoofer` | T1: real node id, unregistered key | `NODE_SIGNATURE_INVALID` |
| `tamperer` | Body changed after signing | `NODE_SIGNATURE_INVALID` |
| `replayer` | T2: first call is captured, later calls resend it | first accepted, then `HEARTBEAT_REPLAYED` |
| `drifting` | Clock an hour slow | `HEARTBEAT_STALE` |
| `regressor` | Always counter 1 | first accepted, then `HEARTBEAT_COUNTER_REGRESSED` |
| `crasher` | Honest, then silent after `--crash-after` heartbeats (T3: the broker should notice the silence) | accepted, then no more requests |

| `result --behaviour` | Demonstrates | Expected code |
|---|---|---|
| `honest` | Normal result | accepted |
| `tamper_ciphertext` | T4: ciphertext changed before signing | `RESULT_INTEGRITY_FAILED` |
| `tamper_in_transit` | Ciphertext changed after signing | `NODE_SIGNATURE_INVALID` |
| `replay` | Captured result resent | first accepted, then `HEARTBEAT_REPLAYED` |

**Fleet and demo runners** (use only on your own local broker):

```bash
python -m fogtrust_crypto.fleet --server http://127.0.0.1:8000 --tokens-file tokens.txt --duration 60   # T3, T6: several nodes, one per profile
python -m fogtrust_crypto.demo  --server http://127.0.0.1:8000                                          # T1, T2: PASS/FAIL table, exit code 1 on any mismatch
python -m fogtrust_crypto.demo  --server ... --state-dir demo-state --task-ids <5 task ids>              # adds the encrypted-result steps (T4)
python -m fogtrust_crypto.bench_live --server http://127.0.0.1:8000 --count 300                         # latency
```

The fleet needs one enrollment token per node (each works once). The demo needs one token, and for the result steps five tasks assigned to the demo node, so run it once with `--state-dir` to enroll, assign the tasks, then run it again with `--task-ids`.

`keys/` is git-ignored. The state file next to the key holds the node id, the heartbeat counter and (for replay demos) one captured request. The counter is saved **before** each send, so a number is never reused. On Windows, file mode bits do nothing: keep `keys/` in a folder only your account can read, and not in OneDrive.

## 8. Early exits and timing

The verifier stops at the first failed check. Measured (`crypto-measurements.md`, section C3), an unknown or revoked node is rejected about 100 microseconds faster than a request with the wrong key, because the signature check is skipped (about 6 µs against about 107 µs in the engine, about 125 µs apart over loopback HTTP). The specific error code already tells the caller the same thing, so equalising the time alone would hide nothing.

**Decision: accepted.** Node ids are random 122-bit UUIDs, so a caller must already hold an id to learn that it exists or is revoked. The early exit is also useful: it makes a flood of requests with unknown ids cheaper for the server than a flood with bad signatures. Hiding the difference would need two changes together (the same client code for unknown, missing and invalid, plus a dummy signature check on the unknown path) and would remove the clear "revoked" signal a legitimate node benefits from. If the team prefers masking, the change is in the API layer's code mapping, not in the engine.

## 9. Known limits (for the limitations statement)

- A stolen node private key is full impersonation until an admin revokes the node.
- A node that loses its counter file sends counters the server rejects; it must be re-enrolled.
- Node clocks must be within `timestamp_window_s` of the server.
- A forged result written directly to the database cannot be told apart from a real one (section 6).
- The in-memory replay store forgets everything on restart; the database store (used by the endpoints) does not.
- Anyone with write access to the database can insert a brand-new result that looks valid (anyone can encrypt to the server's public key). Editing an existing result is caught (AES-GCM, checked when it is read); forging a new one is not. See the threat model, CR-11.
- The server has one long-term result key and no rotation: whoever steals it can read every stored result.
- Rate limiting that bounds nonce growth is Member 1's throttle (120 per minute per node); the engine itself only purges.
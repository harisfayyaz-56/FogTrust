# Test evidence: crypto and the other slices (T3, trust, load)

Date: 2026-11-15. Tests: `backend/results/tests/test_t3_failed_worker.py`, `test_trust_integration.py`, `backend/heartbeats/tests/test_all_node_routes_signed.py`. All pass.

## 1. T3 across the slices: a worker crashes

Input: two enrolled workers, one queued task. Both send signed heartbeats. The scheduler assigns the task to one of them, which then goes silent for two minutes while the other keeps sending heartbeats. An attacker replays the silent worker's old heartbeat.

| Step | Expected | Actual |
|---|---|---|
| Both workers heartbeat | 200; `last_seen_at` set on both | as expected |
| Scheduler assigns the task | One worker, load 1, attempts 1 | as expected |
| Replay of the silent worker's old heartbeat | 401 `HEARTBEAT_REPLAYED`; `last_seen_at` **not** refreshed | as expected |
| `detect_stalled_tasks(60)` | Returns the task; status queued, no worker; the silent worker's load 0, trust 65 (80 minus 15) | as expected |
| Scheduler assigns again | The healthy worker (higher trust, same load); attempts 2 | as expected |
| Healthy worker sends the encrypted result | 201; task completed; its load 0; trust 85 | as expected |

Also: a worker that keeps heartbeating is never declared stalled (`test_a_node_that_keeps_heartbeating_is_not_declared_stalled`), and five forged heartbeats using a silent worker's id do not keep it alive (`test_rejected_heartbeats_do_not_keep_a_silent_worker_alive`).

## 2. Verified work earns trust, damage costs it

| Input | Expected | Test |
|---|---|---|
| A verified result for a task | 201; node load 1 to 0; trust 80 to 85 with a stored trust record | `test_completing_a_task_frees_the_load_slot_and_raises_trust` |
| Load already 0 | Stays 0, never negative | `test_load_never_goes_below_zero` |
| `capacity + 2` tasks finished in a row | Load back to 0 each time; the node is never "full" | `test_a_node_that_keeps_finishing_tasks_is_never_full` |
| One altered result | 422; trust 80 to 55, below the threshold of 60; the trust record names the rule `integrity_failures` | `test_one_altered_result_drops_the_score_below_the_threshold` |
| Three altered results | Trust 55, 30, then 5: **automatically revoked**; the next request gets 403 `NODE_REVOKED`; a node decision is recorded | `test_repeated_tampering_ends_in_automatic_revocation` |
| A good result after a bad one | 201; trust 80 minus 25 plus 5 = 60 | `test_a_good_result_after_a_bad_one_still_counts` |

## 3. A stranger cannot poison a victim's trust (threat model CR-20)

Everything here is done with only the victim's node id. After each attack the victim is still `active` with trust 80 and has **no** trust record.

| Attack | Count | Result |
|---|---|---|
| Heartbeats signed with another key | 30 | all 401, trust untouched |
| Results signed with another key | 10 | all 401, trust untouched |
| Replays of the victim's own heartbeat | 20 | all `HEARTBEAT_REPLAYED`, trust untouched |
| Replays of the victim's own accepted result | 20 | all refused; trust stays at the post-success value |
| Old captures delivered late (counter going backwards) | 5 | refused, trust untouched |
| Captures from an hour ago | 10 | `HEARTBEAT_STALE`, trust untouched |
| A different node asks for the victim's task | 1 | 403, the asker's trust untouched |

Why it matters: with the default weights (-20 per signature failure, automatic revocation below 10) scoring signature failures would revoke any node after four forged requests.

## 4. All node routes refuse unsigned callers (security review)

`test_no_node_route_answers_an_unsigned_caller` runs for each of the three `node-api` routes, with no headers, with only a node id, and with garbage signature headers: every answer is 401, 403, 413 or 429. `test_a_signed_in_human_is_not_a_node` does the same with an administrator's browser session. It found a real defect (the result endpoint returned 500 to strangers when the server key was missing); fixed, with `test_an_unsigned_caller_cannot_tell_that_the_server_key_is_missing`.
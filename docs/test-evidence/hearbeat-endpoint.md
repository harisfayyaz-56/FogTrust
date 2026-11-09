# Test evidence: heartbeat endpoint (FR-2) through Django

Member 2. Date: 2026-11-08. Code: `backend/heartbeats/`. Automated tests: `python -m pytest backend/heartbeats`.
This file records (1) the automated tests that map to T1, T2, T5 and T-final, and (2) one live run of the real server with the node simulator.

## 1. Automated tests (real endpoint, real database, real engine)

| Case | Input | Expected | Actual | Test |
|---|---|---|---|---|
| Honest | Signed heartbeat, counter 1 | 200; `Heartbeat` row; `last_counter` 1; `last_seen_at` set; no Decision, no audit event | as expected | `TestAcceptedHeartbeat` |
| Gaps allowed | Counters 1, 2, 7, 50 | All accepted | as expected | `test_a_sequence_with_gaps_is_accepted` |
| **T1** spoofed node | Genuine node id, attacker's key | 401 `NODE_SIGNATURE_INVALID`; generic message; Decision `deny` with the failed `signature_valid` rule; audit `heartbeat.rejected`; Decision `request_id` equals the response's `X-Request-ID` | as expected | `TestT1SpoofedNode.test_wrong_key_is_refused_and_explained` |
| T1 | Same | No state change: counter 0, no `last_seen_at`, no nonce stored | as expected | `test_a_spoofer_changes_no_state` |
| T1 | Unknown node id | 401 `NODE_UNKNOWN`; audited; not stored in history | as expected | `test_unknown_node_is_refused_and_audited_but_not_stored` |
| **T2** replay | Exact copy of an accepted heartbeat | 401 `HEARTBEAT_REPLAYED`; Decision shows `nonce_unique` failed while the earlier five rules passed | as expected | `TestT2ReplayedHeartbeat.test_exact_copy_is_refused_with_the_nonce_reason` |
| T2 | Three copies | Counter and nonce table unchanged; one accepted row, three rejected rows in the history | as expected | `test_replay_changes_no_state_and_is_visible_in_history` |
| T2 | Capture an hour old | 401 `HEARTBEAT_STALE`, "limit 30 s" in the evidence | as expected | `test_old_capture_is_stale` |
| T2 | Counter 5 accepted, then 3 | 401 `HEARTBEAT_COUNTER_REGRESSED`; `last_counter` stays 5 | as expected | `test_counter_going_backwards_is_refused` |
| T2 | Replay after a restart (cache cleared, new store object) | Still `HEARTBEAT_REPLAYED` | as expected | `test_replay_is_still_refused_after_a_restart` |
| **T5** | Node revoked, then sends | 403 `NODE_REVOKED` on the very next request; signature never checked; counter unchanged | as expected | `TestT5Revocation` |
| T-final | Body 3,000 bytes | 413 `PAYLOAD_TOO_LARGE` before the body is read; audited | as expected | `test_oversized_body_is_refused_before_it_is_read` |
| T-final | Signed non-JSON; wrong types; extra field | 400 `MALFORMED_REQUEST` / `VALIDATION_ERROR`; counter unchanged | as expected | `test_signed_but_malformed_json_is_refused`, `test_signed_but_invalid_body_is_refused` (4 cases) |
| T-final | Every header replaced by empty, non-ASCII, 5,000-character and SQL-looking values | Never a 5xx, never a stack trace | as expected | `test_garbage_headers_never_cause_a_server_error` |
| T-final | Error body | Never echoes the input; Decision text never contains it | as expected | `test_errors_never_echo_input` |
| Rate limit | 4th request of a 3/min limit | 429 `RATE_LIMITED`; another node unaffected | as expected | `TestRateLimits` (3 tests, incl. victim-quota and random-id spraying) |
| Atomicity | Reused nonce; counter compare-and-set | The database rejects a reused nonce even through raw inserts; the counter update is one statement | as expected | `TestAtomicity` (5 tests) |
| History | Viewer lists, filters `?accepted=false`, `?reason_code=`; anonymous; unknown node | 200 / 401 / 404; bad filter 400; full nonce never shown | as expected | `TestHistoryEndpoint` (4 tests) |

A real bug found by these tests: the `?accepted=` filter used a DRF `BooleanField`, which reads a **missing** query parameter as `false`, so the unfiltered list silently hid every accepted heartbeat. It is now a `ChoiceField` (test `test_viewer_sees_history_and_can_filter_rejections`).

Limit: a true multi-connection race cannot be run in this repository's tests, because the audit log's append-only trigger stops transactional tests from cleaning up (`audit/migrations/0002`). The guarantee comes from the database (unique constraint, single conditional `UPDATE`), which `TestAtomicity` checks; the same race is run with 20 threads against the in-memory store in `fogtrust_crypto/tests/test_replay.py`.

## 2. Live run: real Django server, real simulator, over HTTP

Fresh database, `manage.py runserver`, a node created with `node_sim keygen` and enrolled with `node_sim enroll`, then:

| Simulator command | Result |
|---|---|
| `heartbeat` x3 (honest) | 200, 200, 200 |
| `heartbeat --behaviour replayer` x3 | 200, then **401 `HEARTBEAT_REPLAYED`** twice |
| `--behaviour spoofer` | **401 `NODE_SIGNATURE_INVALID`** |
| `--behaviour tamperer` | **401 `NODE_SIGNATURE_INVALID`** |
| `--behaviour drifting` | **401 `HEARTBEAT_STALE`** |
| `--behaviour regressor` x2 | **401 `HEARTBEAT_COUNTER_REGRESSED`** twice |
| `heartbeat` (honest, after all the attacks) | 200 |

State afterwards, read from the database:

```
node gateway-03 active, last_counter 12, last_seen_at set
heartbeat history: 12 rows = 5 accepted, 7 rejected
   rejected: REPLAYED x2, SIGNATURE_INVALID x2, STALE x1, COUNTER_REGRESSED x2
decisions (heartbeat): 7 deny rows, one per rejection, none for accepted heartbeats
audit events heartbeat.rejected: 7
used nonces: 7
```

This is the Week 2 "Friday check" (an honest node enrolls and heartbeats), plus the attackers.
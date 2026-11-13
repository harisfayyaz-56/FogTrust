# Live attack demo (T1, T2, T4, recovery)

Real Django server (`runserver`, SQLite), real node simulator over HTTP. Steps 1 to 9 are heartbeats, 10 to 15 are encrypted results. The status and code in "Expected" come from `api-contract.md`; "Actual" is what the server returned.

Run 2026-11-10 00:05 UTC against `http://127.0.0.1:8766` with `python -m fogtrust_crypto.demo`.

| # | Step | Expected | Actual | Result |
|---|---|---|---|---|
| 1 | Honest heartbeat | 200 OK | 200 OK | PASS |
| 2 | Honest heartbeat (counter moves on) | 200 OK | 200 OK | PASS |
| 3 | T1: spoofed node (wrong key) | 401 NODE_SIGNATURE_INVALID | 401 NODE_SIGNATURE_INVALID | PASS |
| 4 | Heartbeat body altered after signing | 401 NODE_SIGNATURE_INVALID | 401 NODE_SIGNATURE_INVALID | PASS |
| 5 | T2: captured heartbeat, first delivery | 200 OK | 200 OK | PASS |
| 6 | T2: the same bytes sent again | 401 HEARTBEAT_REPLAYED | 401 HEARTBEAT_REPLAYED | PASS |
| 7 | Node clock an hour slow | 401 HEARTBEAT_STALE | 401 HEARTBEAT_STALE | PASS |
| 8 | Counter goes backwards (fresh nonce) | 401 HEARTBEAT_COUNTER_REGRESSED | 401 HEARTBEAT_COUNTER_REGRESSED | PASS |
| 9 | Honest heartbeat after all the attacks | 200 OK | 200 OK | PASS |
| 10 | Honest encrypted result | 201 OK | 201 OK | PASS |
| 11 | T4: ciphertext altered before signing | 422 RESULT_INTEGRITY_FAILED | 422 RESULT_INTEGRITY_FAILED | PASS |
| 12 | T4: ciphertext altered in transit | 401 NODE_SIGNATURE_INVALID | 401 NODE_SIGNATURE_INVALID | PASS |
| 13 | Result, first delivery | 201 OK | 201 OK | PASS |
| 14 | Result, same bytes sent again | 401 HEARTBEAT_REPLAYED | 401 HEARTBEAT_REPLAYED | PASS |
| 15 | Second result for a completed task | 409 TASK_INVALID_STATE | 409 TASK_INVALID_STATE | PASS |
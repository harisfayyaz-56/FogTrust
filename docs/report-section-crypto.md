# Final report section: node identity, signed heartbeats and encrypted results

*Draft for Faiqa to edit and make her own. Every claim below points to a test, a measurement or a log; check each one before submitting.*

## 1. What this part of FogTrust does
A broker must not trust an edge node just because it says who it is. This part makes a node **prove** its identity on every request, makes captured messages **useless to replay**, and makes results **unreadable and tamper-evident**. It covers FR-2 (signed heartbeat) and FR-5 (encrypted results), and the proof of possession used at enrollment (FR-1).

## 2. Design decisions and why

| Decision | Alternative | Why this one |
|---|---|---|
| **Ed25519 signatures** over a canonical string: method, path (with query), timestamp, nonce, SHA-256 of the raw body | Shared secrets (HMAC); signing re-serialised JSON | A shared secret held by the server could be stolen and used to forge every node. Signing the hash of the **raw bytes** means the node signs exactly what it sends, so there is no "same JSON, different bytes" failure |
| **Three replay checks**: time window, one-time nonce, increasing counter | Nonce only, or timestamp only | Each stops something the others do not: the window stops an old capture, the nonce stops a copy inside the window, the counter stops a validly signed old number after the nonce has been purged. The nonce is stored only after the signature passes, so strangers cannot fill the table |
| **Atomic checks in the database** (unique constraint for the nonce, one conditional `UPDATE` for the counter) | Check, then store, in Python | Check-then-store lets two simultaneous copies both pass |
| **Hybrid encryption**: ephemeral X25519, HKDF-SHA256, AES-256-GCM, associated data = node id and task id | A shared AES key; RSA | A new key per result; the server holds one key but nodes hold none that can read results. GCM detects any changed byte, and binding the ciphertext to node and task stops it being moved |
| **No second signature on the result envelope** | Sign the envelope as well | The request signature already covers the ciphertext. The price: someone with database write access can insert a forged new result (limitation CR-11) |
| **Only attributable failures cost trust** | Score every refusal | A stranger can send bad signatures, replays and stale messages using a victim's id. Scoring those would let anyone ban any node in four requests (CR-20) |
| **Engine is plain Python, no Django** | Put the checks in the views | It can be tested alone (fuzzed 22,500 inputs) and a test fails if the package imports a web framework |

## 3. How it fits the required architecture
Browser interface (Member 4) → **API layer** (`heartbeats`, `results`: size limits, throttles, storage, error format) → **security engine** (`fogtrust_crypto`: every decision, with the rules it checked) → **repository** (database, append-only audit log) → **fixtures** (`docs/sample-data`, 24 signed cases). The trust boundaries are drawn in `diagrams/crypto-slice-dataflow.md`.

## 4. Evidence

| Claim | Evidence |
|---|---|
| Spoofed, replayed, altered and revoked cases are refused with the exact reason | `test-evidence/crypto-test-matrix.md`, `live-demo.md` (15 of 15 steps against the real server) |
| 0 false positives in 4,000 honest requests; 0 false negatives in 3,800 attacks of 19 kinds | `test-evidence/crypto-measurements.md` |
| Median 0.14 ms to decide in the engine; about 7 ms end to end on the development server | same, and `heartbeat-endpoint.md` section 3 |
| No crash on about 22,500 random and mutated inputs | `test-evidence/crypto-hardening.md` |
| No key, token, signature or plaintext in logs, decisions or responses | `crypto-hardening.md` C5 (the check was proven by adding a leak on purpose) |
| A crashed worker is replaced and its task completes | `test-evidence/integration-t3-trust.md` |
| All 804 automated tests pass | `test-evidence/crypto-test-matrix.md` |

## 5. Problems found and fixed (honest list)
Real defects found by the project's own tests, not by luck: a regular expression that let a trailing newline into the signed string; several different spellings of one signed request being accepted; a crash on a non-text method; a filter that hid every accepted heartbeat; a result endpoint that answered strangers with a server error when the key was missing; and a completion path that never freed a node's task slot, so a busy node would eventually stop receiving work. Two process failures also: a duplicate replay store, and a merge that removed two apps from the settings twice. The lesson recorded in the review: run `git diff --stat main` before every commit.

## 6. Limitations and ethics
See `crypto-limitations-ethics.md` (ten limits, stated plainly, and the rules for the attacker simulators: local broker only, no real data, no claim of unbreakable security).

## 7. What would come next
A per-result node signature (closes the database-forgery gap), key rotation for the server key, rate limits in a shared store, and counting missed heartbeats in the trust score (a trust rule exists but nothing feeds it).
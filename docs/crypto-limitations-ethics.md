# Limitations and ethics: cryptography and node simulator slice (Member 2)

Draft for the final report. Every claim points to a test, a measurement or a log, as the brief requires.

## What this slice does and does not protect

| Claim | Evidence |
|---|---|
| A request signed with the wrong key, or changed after signing, is refused | `crypto-T2-T4.md`, `live-demo.md` steps 3 and 4 |
| A captured request cannot be replayed, within or after the time window, even after a restart | `heartbeat-endpoint.md` section 1, `live-demo.md` steps 6 and 14 |
| An altered result is detected, in transit and at rest | `results-endpoint.md`, `live-demo.md` steps 11 and 12 |
| Malformed, oversized or random input never causes a server error | `crypto-hardening.md` C1 and C2 |
| No key, token, signature or plaintext appears in logs, decisions or responses | `crypto-hardening.md` C5 |
| 0 false positives in 4,000 honest requests, 0 false negatives in 3,800 attacks of 19 kinds | `crypto-measurements.md` D1 |

These are the cases listed, not every possible attack.

## Known limits (stated plainly)

1. **A stolen node key is a stolen identity** until an admin revokes the node. Keys are in files with owner-only permissions on Linux and macOS; on Windows the mode bits do nothing, so the folder's own permissions are the only protection. Keys are not encrypted at rest and there is no hardware protection.
2. **Anyone with database write access can insert a forged result** that looks valid, because anyone can encrypt to the server's public key. Editing an existing result is caught; forging a new one is not (CR-11). Defending against it would need a per-result node signature that the data model does not store.
3. **One long-term server key, no rotation.** Whoever obtains it can read every stored result. There is no forward secrecy towards the server key.
4. **Clocks must agree within the time window** (default 30 seconds). A node whose clock drifts further is refused (`crypto-measurements.md` D3). A bigger window forgives more drift but accepts a request that was blocked and delivered late for longer.
5. **Error codes are specific.** Anyone holding a node id can learn whether it exists or is revoked, and the early exits are about 100 microseconds faster. Node ids are random 122-bit UUIDs, so this was accepted, with the reasons in `node-signing-spec.md` section 8.
6. **Rate limits are per address.** Many nodes behind one address share a 1,200 per minute cap, and the limits are counted in the cache, so they reset when the server restarts. A real deployment would put them in a shared store.
7. **Counters are kept by the node.** A node that loses its counter file is refused until it is re-enrolled.
8. **Decrypted results are visible to operators and admins.** Every view is audited (who and when), but the log cannot stop a legitimate operator from copying a result.
9. **Scale.** The numbers come from a development server with SQLite and a handful of simulated nodes. Nothing here says how it behaves with thousands of nodes.
10. **The fuzzing and the sweeps are evidence, not proof.** They found real bugs (node-id spellings, a crash on a non-string method, a filter that hid accepted heartbeats), which means other bugs may remain.

## Ethics

- **The attacker simulators are for the team's own local broker only.** The spoofer, replayer, tamperer and the rest send requests to whatever address they are given; they must never be pointed at a system the team does not own. The brief excludes real-world attack deployment and unapproved external targets, and the tools say so in their help text.
- **No real data.** Every key, token and result in the repository and the tests is generated for testing. Test keys are never reused, and `keys/` is git-ignored.
- **Data minimisation.** Plaintext results are never stored or logged, only their SHA-256 and ciphertext. Decisions and audit events hold short prefixes of identifiers, never full signatures, nonces or keys.
- **No claim of unbreakable security.** The system is a teaching project. Its guarantees are the ones tested above; it has had no independent review.
- **Honest reporting.** The limits above are reported together with the results, and the checks were validated by breaking them on purpose (for example the secrets sweep was shown to fail when a leak was added).